//! macOS Messages `~/Library/Messages/chat.db` parser.
//!
//! The desktop Messages store uses the identical schema to the iOS `sms.db`, so
//! this parser reuses the shared Apple Messages engine
//! ([`crate::parsers::mobile::ios::imessage`]) with a macOS config: only the
//! parser name, platform tag, app label and materialized filename differ. It
//! emits the canonical `chat.v1` envelope (`mobile.communication.message` /
//! `mobile.communication.attachment`) so attachment-ref harvesting and any chat
//! UI work across platforms.

use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::parsers::mobile::common::records::AppInfo;
use crate::parsers::mobile::ios::imessage::{
    MessagesConfig, extract_message_timeline, run_messages,
};
use anyhow::Result;

const PARSER_NAME: &str = "macos_imessage";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

const MACOS_CONFIG: MessagesConfig = MessagesConfig {
    parser_name: PARSER_NAME,
    platform: "macos",
    app_label: "imessage",
    app: AppInfo {
        bundle_id: "com.apple.MobileSMS",
        label: "iMessage",
    },
    schema_variant: "macos_chatdb_v1",
    filename: "chat.db",
};

#[derive(Default)]
pub struct MacosIMessageParser;

impl Parser for MacosIMessageParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse macOS Messages chat.db chats, SMS/iMessage messages, and attachment references."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        extract_message_timeline(obj)
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        run_messages(&MACOS_CONFIG, input, sink)
    }
}

#[cfg(test)]
mod tests {
    use super::MacosIMessageParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::parsers::mobile::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_chatdb() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("chat.db");

        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE message (
                    ROWID INTEGER PRIMARY KEY,
                    guid TEXT NOT NULL,
                    text TEXT,
                    service TEXT,
                    handle_id INTEGER DEFAULT 0,
                    date INTEGER,
                    is_from_me INTEGER DEFAULT 0,
                    is_read INTEGER DEFAULT 0,
                    is_delivered INTEGER DEFAULT 0,
                    cache_has_attachments INTEGER DEFAULT 0
                );
                CREATE TABLE chat (
                    ROWID INTEGER PRIMARY KEY,
                    guid TEXT NOT NULL,
                    chat_identifier TEXT,
                    service_name TEXT,
                    display_name TEXT
                );
                CREATE TABLE handle (
                    ROWID INTEGER PRIMARY KEY,
                    id TEXT NOT NULL,
                    service TEXT NOT NULL
                );
                CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER);
                CREATE TABLE chat_handle_join (chat_id INTEGER, handle_id INTEGER);

                INSERT INTO handle VALUES (1, 'mephisto@example.com', 'iMessage');
                INSERT INTO chat VALUES (1, 'iMessage;-;mephisto@example.com', 'mephisto@example.com', 'iMessage', 'Mephisto');
                INSERT INTO chat_handle_join VALUES (1, 1);
                INSERT INTO message (ROWID, guid, text, service, handle_id, date, is_from_me, is_read, is_delivered)
                VALUES (10, 'MSG-1', 'ping', 'iMessage', 1, 1000000000, 0, 1, 1);
                INSERT INTO chat_message_join VALUES (1, 10);
                "#,
            )?;
        }

        let parser = MacosIMessageParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        // 1 chat + 1 message (no attachments)
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].kind, "mobile.communication.chat");
        assert_eq!(objects[0].json["platform"], "macos");
        let message = &objects[1];
        assert_eq!(message.kind, "mobile.communication.message");
        assert_eq!(message.json["schema"], "chat.v1");
        assert_eq!(message.json["platform"], "macos");
        assert_eq!(message.json["body"], "ping");
        assert_eq!(message.json["direction"], "incoming");
        assert_eq!(message.json["sender"]["id"], "mephisto@example.com");

        let events = parser.extract_timeline_events(message);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].description.as_deref(), Some("ping"));
        assert_eq!(events[0].actor.as_deref(), Some("mephisto@example.com"));

        Ok(())
    }
}
