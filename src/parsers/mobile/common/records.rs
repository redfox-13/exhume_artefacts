//! Canonical record envelopes shared by parsers of the same kind.
//!
//! A parser that produces one of these emits a JSON shape guaranteed by the
//! type system rather than by convention, so any view written against the kind
//! works for every parser that produces it — an iOS chat app, an Android SMS
//! provider, or something added later — with no per-app query code.
//!
//! Anything a specific application records beyond the common fields goes in
//! `details`, so normalising never costs forensic detail.

use crate::core::ObjectParsed;
use serde_json::{Value, json};

/// Kind tag for a single conversational message, whatever the app.
pub const CHAT_MESSAGE_KIND: &str = "mobile.communication.message";

/// Envelope version, recorded as `source.schema_variant`.
pub const CHAT_SCHEMA_VARIANT: &str = "chat.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Incoming,
    Outgoing,
    Unknown,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Incoming => "incoming",
            Direction::Outgoing => "outgoing",
            Direction::Unknown => "unknown",
        }
    }

    /// Apple stores an `is_from_me` flag; Android a message `type` code.
    pub fn from_is_from_me(is_from_me: Option<bool>) -> Self {
        match is_from_me {
            Some(true) => Direction::Outgoing,
            Some(false) => Direction::Incoming,
            None => Direction::Unknown,
        }
    }
}

/// One end of a conversation: the device owner, or a correspondent.
#[derive(Debug, Clone, Default)]
pub struct Party {
    /// Stable handle — phone number, JID, e-mail, account id.
    pub id: Option<String>,
    pub display_name: Option<String>,
    pub is_self: bool,
}

impl Party {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "display_name": self.display_name,
            "is_self": self.is_self,
        })
    }
}

/// The thread a message belongs to.
///
/// `id` must be **stable and unique within this parser's own store** — only the
/// parser knows what identifies a thread in its schema. It does NOT need to be
/// unique across applications: numeric ids collide freely (Android SMS thread 3
/// and WhatsApp chat 3 are unrelated), so consumers compose global identity as
/// `parser:id`.
#[derive(Debug, Clone, Default)]
pub struct Conversation {
    pub id: String,
    pub display_name: Option<String>,
    pub participants: Vec<Party>,
}

/// Which application produced the message, for display and faceting.
#[derive(Debug, Clone, Copy)]
pub struct AppInfo {
    pub bundle_id: &'static str,
    pub label: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct Attachment {
    /// image | video | audio | document | sticker | contact | unknown
    pub kind: Option<String>,
    pub filename: Option<String>,
    /// Path on the device, when the app records one.
    pub local_path: Option<String>,
    pub mime: Option<String>,
    pub size_bytes: Option<i64>,
}

impl Attachment {
    fn to_json(&self) -> Value {
        json!({
            "kind": self.kind,
            "filename": self.filename,
            "local_path": self.local_path,
            "mime": self.mime,
            "size_bytes": self.size_bytes,
        })
    }
}

/// Per-message state. `None` means the app has no such concept — never
/// invent a value, an absent flag is different from a false one.
#[derive(Debug, Clone, Default)]
pub struct MessageState {
    pub read: Option<bool>,
    pub delivered: Option<bool>,
    pub deleted: Option<bool>,
}

/// A single message in the canonical shape.
pub struct ChatMessage {
    pub parser: &'static str,
    pub platform: &'static str,
    pub app: AppInfo,

    pub conversation: Conversation,
    pub direction: Direction,
    pub sender: Party,

    /// Canonical ordering timestamp — every consumer sorts and filters on this.
    /// Built with the timestamp helpers so the `{unix_ms, rfc3339, ...}` shape
    /// is identical regardless of the device's native epoch.
    pub timestamp: Value,
    /// Optional finer detail; either may be null.
    pub sent: Value,
    pub received: Value,

    pub body: Option<String>,
    pub attachments: Vec<Attachment>,
    pub state: MessageState,

    /// Provenance, from each parser's own `source_json`.
    pub source: Value,
    /// Everything app-specific, preserved verbatim.
    pub details: Value,
}

impl ChatMessage {
    /// What the grid and full-text search show for this row.
    fn display_text(&self) -> String {
        if let Some(body) = self
            .body
            .as_ref()
            .map(|b| b.trim())
            .filter(|b| !b.is_empty())
        {
            return body.to_string();
        }
        for attachment in &self.attachments {
            if let Some(name) = attachment.filename.as_deref().filter(|n| !n.is_empty()) {
                return name.to_string();
            }
            if let Some(kind) = attachment.kind.as_deref().filter(|k| !k.is_empty()) {
                return format!("[{kind}]");
            }
        }
        String::new()
    }
}

impl From<ChatMessage> for ObjectParsed {
    fn from(message: ChatMessage) -> Self {
        let text = message.display_text();

        // Stamp the envelope version onto the parser's provenance block.
        let mut source = message.source.clone();
        if let Some(object) = source.as_object_mut() {
            object.insert(
                "schema_variant".to_string(),
                Value::String(CHAT_SCHEMA_VARIANT.to_string()),
            );
        }

        let json = json!({
            "schema": CHAT_SCHEMA_VARIANT,
            "platform": message.platform,
            "record_type": "message",
            "app": {
                "bundle_id": message.app.bundle_id,
                "label": message.app.label,
            },
            "conversation": {
                "id": message.conversation.id,
                "display_name": message.conversation.display_name,
                "participants": message
                    .conversation
                    .participants
                    .iter()
                    .map(Party::to_json)
                    .collect::<Vec<_>>(),
            },
            "direction": message.direction.as_str(),
            "sender": message.sender.to_json(),
            "timestamps": {
                // Canonical key every view sorts and filters on.
                "message": message.timestamp,
                "sent": message.sent,
                "received": message.received,
            },
            "body": message.body,
            "attachments": message
                .attachments
                .iter()
                .map(Attachment::to_json)
                .collect::<Vec<_>>(),
            "has_attachments": !message.attachments.is_empty(),
            "state": {
                "read": message.state.read,
                "delivered": message.state.delivered,
                "deleted": message.state.deleted,
            },
            "source": source,
            "details": message.details,
        });

        ObjectParsed {
            parser: message.parser,
            kind: CHAT_MESSAGE_KIND,
            text,
            json,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ChatMessage {
        ChatMessage {
            parser: "test_parser",
            platform: "android",
            app: AppInfo {
                bundle_id: "com.example.app",
                label: "Example",
            },
            conversation: Conversation {
                id: "3".to_string(),
                display_name: Some("+15551234567".to_string()),
                participants: vec![Party {
                    id: Some("+15551234567".to_string()),
                    display_name: None,
                    is_self: false,
                }],
            },
            direction: Direction::Incoming,
            sender: Party {
                id: Some("+15551234567".to_string()),
                display_name: None,
                is_self: false,
            },
            timestamp: json!({ "unix_ms": 1_695_240_589_641i64 }),
            sent: Value::Null,
            received: Value::Null,
            body: Some("hello".to_string()),
            attachments: Vec::new(),
            state: MessageState {
                read: Some(false),
                ..Default::default()
            },
            source: json!({ "path": "/x", "table": "sms", "rowid": 1 }),
            details: json!({ "protocol": 0 }),
        }
    }

    #[test]
    fn builds_canonical_envelope() {
        let obj: ObjectParsed = sample().into();
        assert_eq!(obj.kind, CHAT_MESSAGE_KIND);
        assert_eq!(obj.text, "hello");
        assert_eq!(obj.json["schema"], CHAT_SCHEMA_VARIANT);
        assert_eq!(obj.json["conversation"]["id"], "3");
        assert_eq!(obj.json["direction"], "incoming");
        assert_eq!(obj.json["app"]["label"], "Example");
        assert_eq!(
            obj.json["timestamps"]["message"]["unix_ms"],
            1_695_240_589_641i64
        );
        assert_eq!(obj.json["state"]["read"], false);
        assert_eq!(obj.json["has_attachments"], false);
        // App-specific data survives, and the envelope version is stamped.
        assert_eq!(obj.json["details"]["protocol"], 0);
        assert_eq!(obj.json["source"]["schema_variant"], CHAT_SCHEMA_VARIANT);
    }

    #[test]
    fn falls_back_to_attachment_for_display_text() {
        let mut message = sample();
        message.body = Some("   ".to_string());
        message.attachments = vec![Attachment {
            kind: Some("image".to_string()),
            filename: Some("IMG_0001.jpg".to_string()),
            ..Default::default()
        }];
        let obj: ObjectParsed = message.into();
        assert_eq!(obj.text, "IMG_0001.jpg");
        assert_eq!(obj.json["has_attachments"], true);
    }

    #[test]
    fn absent_state_stays_null_rather_than_false() {
        let mut message = sample();
        message.state = MessageState::default();
        let obj: ObjectParsed = message.into();
        assert!(obj.json["state"]["read"].is_null());
        assert!(obj.json["state"]["delivered"].is_null());
    }
}
