use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::parsers::mobile::common::records::{
    AppInfo, ChatMessage, Conversation, Direction, MessageState, Party,
};
use crate::parsers::mobile::common::timestamps::apple_nanoseconds_to_json;
use crate::parsers::mobile::sqlite::{
    SqliteConnection, SqliteEvidence, SqliteSchema, SqliteStatement, select_column,
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

const PARSER_NAME: &str = "mobile_ios_imessage";
const APP: AppInfo = AppInfo {
    bundle_id: "com.apple.MobileSMS",
    label: "iMessage",
};
const SCHEMA_VARIANT: &str = "ios_smsdb_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

/// Everything that differs between the iOS (`sms.db`) and macOS (`chat.db`)
/// Messages parsers. The database schema, SQL and emitted `kind`s are identical,
/// so the macOS parser reuses this whole engine with a different config.
pub(crate) struct MessagesConfig {
    pub parser_name: &'static str,
    /// `"ios"` or `"macos"` — recorded on every emitted object.
    pub platform: &'static str,
    /// Short app label used in the app-specific JSON blocks.
    pub app_label: &'static str,
    pub app: AppInfo,
    pub schema_variant: &'static str,
    /// Filename the DB is materialized as in the temp dir.
    pub filename: &'static str,
}

const IOS_CONFIG: MessagesConfig = MessagesConfig {
    parser_name: PARSER_NAME,
    platform: "ios",
    app_label: "imessage",
    app: APP,
    schema_variant: SCHEMA_VARIANT,
    filename: "sms.db",
};

/// Run the Apple Messages engine end-to-end for either platform.
pub(crate) fn run_messages(
    cfg: &MessagesConfig,
    input: ParserInput,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let evidence = SqliteEvidence::from_input(input, cfg.filename)?;
    let conn = SqliteConnection::open(evidence.path())?;
    let schema = conn.schema()?;
    validate_schema(&schema)?;

    emit_chats(cfg, &conn, &schema, &evidence, sink)?;
    emit_messages(cfg, &conn, &schema, &evidence, sink)?;
    emit_attachments(cfg, &conn, &schema, &evidence, sink)?;

    Ok(())
}

/// Timeline extraction is identical for both platforms (same `kind`s and JSON).
pub(crate) fn extract_message_timeline(obj: &ObjectParsed) -> Vec<TimelineEvent> {
    match obj.kind {
        "mobile.communication.message" => {
            let Some(ts_unix_ms) = obj.json["timestamps"]["message"]["unix_ms"].as_i64() else {
                return Vec::new();
            };
            let description = obj.json["details"]["message"]["display_text"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            let actor = if obj.json["direction"].as_str() == Some("incoming") {
                obj.json["sender"]["id"].as_str().map(str::to_owned)
            } else {
                None
            };
            vec![TimelineEvent {
                ts_unix_ms,
                event_type: "mobile.communication.message",
                description,
                actor,
            }]
        }
        "mobile.communication.attachment" => {
            let Some(ts_unix_ms) = obj.json["timestamps"]["message"]["unix_ms"].as_i64() else {
                return Vec::new();
            };
            let description = obj.json["attachment"]["file_name"]
                .as_str()
                .filter(|s| !s.is_empty())
                .or_else(|| obj.json["attachment"]["kind"].as_str())
                .map(str::to_owned);
            vec![TimelineEvent {
                ts_unix_ms,
                event_type: "mobile.communication.attachment",
                description,
                actor: None,
            }]
        }
        _ => Vec::new(),
    }
}

#[derive(Default)]
pub struct IosIMessageParser;

impl Parser for IosIMessageParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse Apple Messages for iOS sms.db chats, SMS/iMessage messages, and attachment references."
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
        run_messages(&IOS_CONFIG, input, sink)
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    for table in ["message", "chat", "handle"] {
        if !schema.has_table(table) {
            bail!("not a supported iOS Messages sms.db: missing {table} table");
        }
    }

    let missing = schema.missing_columns(
        "message",
        &["ROWID", "guid", "date", "is_from_me", "handle_id"],
    );
    if !missing.is_empty() {
        bail!(
            "not a supported iOS Messages sms.db: missing required columns: {}",
            missing.join(", ")
        );
    }

    Ok(())
}

fn emit_chats(
    cfg: &MessagesConfig,
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let participant_columns = if can_join_chat_handles(schema) {
        r#"
            (SELECT group_concat(h.id || char(30) || h.service, char(31))
             FROM chat_handle_join chj
             LEFT JOIN handle h ON h.ROWID = chj.handle_id
             WHERE chj.chat_id = c.ROWID) AS participants,
            (SELECT count(*)
             FROM chat_handle_join chj
             WHERE chj.chat_id = c.ROWID) AS participant_count
        "#
    } else {
        "NULL AS participants, NULL AS participant_count"
    };

    let sql = format!(
        r#"
        SELECT
            c.ROWID AS chat_rowid,
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {participant_columns}
        FROM chat c
        ORDER BY c.ROWID;
        "#,
        select_column(schema, "chat", "c", "guid", "chat_guid"),
        select_column(schema, "chat", "c", "chat_identifier", "chat_identifier"),
        select_column(schema, "chat", "c", "service_name", "service_name"),
        select_column(schema, "chat", "c", "room_name", "room_name"),
        select_column(schema, "chat", "c", "display_name", "display_name"),
        select_column(schema, "chat", "c", "group_id", "group_id"),
        select_column(schema, "chat", "c", "style", "style"),
        select_column(schema, "chat", "c", "state", "state"),
        select_column(schema, "chat", "c", "account_login", "account_login"),
        select_column(schema, "chat", "c", "is_archived", "is_archived"),
        select_column(
            schema,
            "chat",
            "c",
            "last_read_message_timestamp",
            "last_read_message_timestamp"
        ),
    );

    conn.query_rows(&sql, |row| {
        let chat_rowid = row.i64(0).context("chat row missing ROWID")?;
        let display_name = non_empty(row.text(5));
        let text = display_name
            .clone()
            .or_else(|| row.text(2))
            .or_else(|| row.text(1))
            .unwrap_or_default();
        let json = json!({
            "platform": cfg.platform,
            "app": cfg.app_label,
            "record_type": "chat",
            "source": source_json(cfg, evidence, "chat", chat_rowid),
            "chat": {
                "rowid": chat_rowid,
                "guid": row.text(1),
                "identifier": row.text(2),
                "service": row.text(3),
                "room_name": row.text(4),
                "display_name": display_name,
                "group_id": row.text(6),
                "style_code": row.i64(7),
                "state_code": row.i64(8),
                "account_login": row.text(9),
                "archived": row.bool(10),
                "participant_count": row.i64(13),
            },
            "participants": participants_json(row.text(12)),
            "timestamps": {
                "last_read_message": apple_nanoseconds_to_json(row.i64(11)),
            },
        });

        sink(ObjectParsed {
            parser: cfg.parser_name,
            kind: "mobile.communication.chat",
            text,
            json,
        })
    })
}

fn emit_messages(
    cfg: &MessagesConfig,
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let has_handle_join = schema.has_table("handle")
        && schema.has_column("handle", "ROWID")
        && schema.has_column("message", "handle_id");
    let handle_join = if has_handle_join {
        "LEFT JOIN handle h ON h.ROWID = m.handle_id"
    } else {
        ""
    };

    let has_chat_join = can_join_chat_messages(schema);
    let chat_join = if has_chat_join {
        "LEFT JOIN chat_message_join cmj ON cmj.message_id = m.ROWID LEFT JOIN chat c ON c.ROWID = cmj.chat_id"
    } else {
        ""
    };

    let sql = format!(
        r#"
        SELECT
            m.ROWID AS message_rowid,
            m.guid AS message_guid,
            {},
            {},
            {},
            {},
            m.date AS message_date,
            {},
            {},
            m.is_from_me AS is_from_me,
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {}
        FROM message m
        {handle_join}
        {chat_join}
        ORDER BY m.date, m.ROWID;
        "#,
        select_column(schema, "message", "m", "text", "message_text"),
        select_column(schema, "message", "m", "subject", "subject"),
        select_column(schema, "message", "m", "service", "service"),
        select_column(schema, "message", "m", "account", "account"),
        select_column(schema, "message", "m", "date_read", "date_read"),
        select_column(schema, "message", "m", "date_delivered", "date_delivered"),
        select_column(schema, "message", "m", "is_read", "is_read"),
        select_column(schema, "message", "m", "is_sent", "is_sent"),
        select_column(schema, "message", "m", "is_delivered", "is_delivered"),
        select_column(schema, "message", "m", "error", "error"),
        select_column(
            schema,
            "message",
            "m",
            "is_system_message",
            "is_system_message"
        ),
        select_column(
            schema,
            "message",
            "m",
            "is_service_message",
            "is_service_message"
        ),
        select_column(
            schema,
            "message",
            "m",
            "cache_has_attachments",
            "cache_has_attachments"
        ),
        select_column(schema, "message", "m", "handle_id", "handle_id"),
        select_joined_column(has_handle_join, schema, "handle", "h", "id", "handle"),
        select_joined_column(
            has_handle_join,
            schema,
            "handle",
            "h",
            "service",
            "handle_service"
        ),
        select_joined_column(
            has_handle_join,
            schema,
            "handle",
            "h",
            "uncanonicalized_id",
            "uncanonicalized_id"
        ),
        select_joined_column(has_handle_join, schema, "handle", "h", "country", "country"),
        select_joined_column(has_chat_join, schema, "chat", "c", "ROWID", "chat_rowid"),
        select_joined_column(has_chat_join, schema, "chat", "c", "guid", "chat_guid"),
        select_joined_column(
            has_chat_join,
            schema,
            "chat",
            "c",
            "chat_identifier",
            "chat_identifier"
        ),
        select_joined_column(
            has_chat_join,
            schema,
            "chat",
            "c",
            "display_name",
            "display_name"
        ),
        select_joined_column(
            has_chat_join,
            schema,
            "chat",
            "c",
            "service_name",
            "chat_service"
        ),
        select_joined_column(has_chat_join, schema, "chat", "c", "room_name", "room_name"),
        select_column(schema, "message", "m", "item_type", "item_type"),
        select_column(
            schema,
            "message",
            "m",
            "associated_message_guid",
            "associated_message_guid"
        ),
        select_column(
            schema,
            "message",
            "m",
            "associated_message_type",
            "associated_message_type"
        ),
        select_column(schema, "message", "m", "reply_to_guid", "reply_to_guid"),
        select_column(schema, "message", "m", "date_edited", "date_edited"),
        select_column(schema, "message", "m", "date_retracted", "date_retracted"),
        select_column(
            schema,
            "message",
            "m",
            "is_audio_message",
            "is_audio_message"
        ),
        select_column(schema, "message", "m", "group_title", "group_title"),
        select_column(
            schema,
            "message",
            "m",
            "expressive_send_style_id",
            "expressive_send_style_id"
        ),
        select_column(
            schema,
            "message",
            "m",
            "balloon_bundle_id",
            "balloon_bundle_id"
        ),
    );

    conn.query_rows(&sql, |row| emit_message(cfg, row, evidence, sink))
}

fn emit_message(
    cfg: &MessagesConfig,
    row: &SqliteStatement<'_>,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let message_rowid = row.i64(0).context("message row missing ROWID")?;
    let text = row.text(2);
    let is_from_me = row.bool(9);
    let classification = classify_message(row, text.as_deref());
    let conversation_id = row
        .i64(22)
        .map(|id| id.to_string())
        .or_else(|| row.text(23))
        .or_else(|| row.text(24))
        .unwrap_or_else(|| "unknown".to_string());
    let handle_id = row.text(18);
    let outgoing = is_from_me == Some(true);

    let message = ChatMessage {
        parser: cfg.parser_name,
        platform: cfg.platform,
        app: cfg.app,
        conversation: Conversation {
            id: conversation_id,
            display_name: row.text(25).or_else(|| row.text(24)),
            participants: handle_id
                .clone()
                .map(|id| {
                    vec![Party {
                        id: Some(id),
                        display_name: None,
                        is_self: false,
                    }]
                })
                .unwrap_or_default(),
        },
        direction: Direction::from_is_from_me(is_from_me),
        sender: if outgoing {
            Party {
                id: None,
                display_name: None,
                is_self: true,
            }
        } else {
            Party {
                id: handle_id,
                display_name: None,
                is_self: false,
            }
        },
        timestamp: apple_nanoseconds_to_json(row.i64(6)),
        sent: if outgoing {
            apple_nanoseconds_to_json(row.i64(6))
        } else {
            Value::Null
        },
        received: if outgoing {
            Value::Null
        } else {
            apple_nanoseconds_to_json(row.i64(6))
        },
        body: text.clone(),
        // Attachments are emitted as their own records by emit_attachments.
        attachments: Vec::new(),
        state: MessageState {
            read: row.bool(10),
            delivered: row.bool(12),
            deleted: None,
        },
        source: source_json(cfg, evidence, "message", message_rowid),
        details: json!({
            "message": {
                "rowid": message_rowid,
                "guid": row.text(1),
                "display_text": classification.display_text,
                "subject": row.text(3),
                "service": row.text(4),
                "account": row.text(5),
                "type_family": classification.type_family,
                "item_type_code": row.i64(28),
                "error_code": row.i64(13),
                "sent": row.bool(11),
                "system_message": row.bool(14),
                "service_message": row.bool(15),
                "has_attachments": row.bool(16),
                "audio_message": row.bool(34),
                "associated_message_guid": row.text(29),
                "associated_message_type_code": row.i64(30),
                "reply_to_guid": row.text(31),
                "group_title": row.text(35),
                "expressive_send_style_id": row.text(36),
                "balloon_bundle_id": row.text(37),
            },
            "timestamps": {
                "read": apple_nanoseconds_to_json(row.i64(7)),
                "delivered": apple_nanoseconds_to_json(row.i64(8)),
                "edited": apple_nanoseconds_to_json(row.i64(32)),
                "retracted": apple_nanoseconds_to_json(row.i64(33)),
            },
            "chat": {
                "rowid": row.i64(22),
                "guid": row.text(23),
                "identifier": row.text(24),
                "display_name": row.text(25),
                "service": row.text(26),
                "room_name": row.text(27),
            },
            "handle": {
                "rowid": row.i64(17),
                "id": row.text(18),
                "service": row.text(19),
                "uncanonicalized_id": row.text(20),
                "country": row.text(21),
            },
        }),
    };

    sink(message.into())
}

fn emit_attachments(
    cfg: &MessagesConfig,
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    if !can_join_attachments(schema) {
        return Ok(());
    }

    let has_chat_join = can_join_chat_messages(schema);
    let chat_join = if has_chat_join {
        "LEFT JOIN chat_message_join cmj ON cmj.message_id = m.ROWID LEFT JOIN chat c ON c.ROWID = cmj.chat_id"
    } else {
        ""
    };

    let sql = format!(
        r#"
        SELECT
            a.ROWID AS attachment_rowid,
            a.guid AS attachment_guid,
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            maj.message_id AS message_rowid,
            m.guid AS message_guid,
            m.date AS message_date,
            {},
            m.is_from_me AS is_from_me,
            {},
            {},
            {},
            {},
            {}
        FROM message_attachment_join maj
        JOIN attachment a ON a.ROWID = maj.attachment_id
        JOIN message m ON m.ROWID = maj.message_id
        {chat_join}
        ORDER BY m.date, m.ROWID, a.ROWID;
        "#,
        select_column(schema, "attachment", "a", "created_date", "created_date"),
        select_column(schema, "attachment", "a", "start_date", "start_date"),
        select_column(schema, "attachment", "a", "filename", "filename"),
        select_column(schema, "attachment", "a", "uti", "uti"),
        select_column(schema, "attachment", "a", "mime_type", "mime_type"),
        select_column(
            schema,
            "attachment",
            "a",
            "transfer_state",
            "transfer_state"
        ),
        select_column(schema, "attachment", "a", "is_outgoing", "is_outgoing"),
        select_column(schema, "attachment", "a", "transfer_name", "transfer_name"),
        select_column(schema, "attachment", "a", "total_bytes", "total_bytes"),
        select_column(schema, "attachment", "a", "is_sticker", "is_sticker"),
        select_column(
            schema,
            "attachment",
            "a",
            "hide_attachment",
            "hide_attachment"
        ),
        select_column(schema, "attachment", "a", "original_guid", "original_guid"),
        select_column(schema, "message", "m", "text", "message_text"),
        select_joined_column(has_chat_join, schema, "chat", "c", "ROWID", "chat_rowid"),
        select_joined_column(has_chat_join, schema, "chat", "c", "guid", "chat_guid"),
        select_joined_column(
            has_chat_join,
            schema,
            "chat",
            "c",
            "chat_identifier",
            "chat_identifier"
        ),
        select_joined_column(
            has_chat_join,
            schema,
            "chat",
            "c",
            "display_name",
            "display_name"
        ),
        select_joined_column(
            has_chat_join,
            schema,
            "chat",
            "c",
            "service_name",
            "chat_service"
        ),
    );

    conn.query_rows(&sql, |row| {
        let attachment_rowid = row.i64(0).context("attachment row missing ROWID")?;
        let filename = row.text(4);
        let transfer_name = non_empty(row.text(9));
        let text = transfer_name
            .clone()
            .or_else(|| basename(filename.as_deref()))
            .or_else(|| filename.clone())
            .unwrap_or_default();
        let json = json!({
            "platform": cfg.platform,
            "app": cfg.app_label,
            "record_type": "attachment",
            "source": source_json(cfg, evidence, "attachment", attachment_rowid),
            "timestamps": {
                "message": apple_nanoseconds_to_json(row.i64(16)),
                "created": apple_nanoseconds_to_json(row.i64(2)),
                "start": apple_nanoseconds_to_json(row.i64(3)),
            },
            "direction": direction_label(row.bool(18)),
            "message": {
                "rowid": row.i64(14),
                "guid": row.text(15),
                "text": row.text(17),
            },
            "chat": {
                "rowid": row.i64(19),
                "guid": row.text(20),
                "identifier": row.text(21),
                "display_name": row.text(22),
                "service": row.text(23),
            },
            "attachment": {
                "rowid": attachment_rowid,
                "guid": row.text(1),
                "original_guid": row.text(13),
                "kind": attachment_kind(filename.as_deref(), row.text(5).as_deref(), row.text(6).as_deref(), row.bool(11)),
                "filename": filename,
                "file_name": basename(row.text(4).as_deref()),
                "transfer_name": transfer_name,
                "uti": row.text(5),
                "mime": row.text(6),
                "transfer_state_code": row.i64(7),
                "outgoing": row.bool(8),
                "total_bytes": row.i64(10),
                "sticker": row.bool(11),
                "hidden": row.bool(12),
            },
        });

        sink(ObjectParsed {
            parser: cfg.parser_name,
            kind: "mobile.communication.attachment",
            text,
            json,
        })
    })
}

struct MessageClassification {
    type_family: &'static str,
    display_text: Option<String>,
}

fn classify_message(row: &SqliteStatement<'_>, text: Option<&str>) -> MessageClassification {
    let display_text = text.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    });

    let type_family = if row.bool(16) == Some(true) {
        "media"
    } else if row.bool(14) == Some(true) || row.bool(15) == Some(true) {
        "service_or_system"
    } else if row.i64(30).unwrap_or(0) != 0 || row.text(29).is_some() {
        "associated_message"
    } else if row.bool(34) == Some(true) {
        "audio"
    } else if display_text.is_some() {
        "text"
    } else {
        "empty_or_system"
    };

    MessageClassification {
        type_family,
        display_text,
    }
}

fn participants_json(value: Option<String>) -> Value {
    let Some(value) = value else {
        return Value::Null;
    };

    let participants = value
        .split('\u{1f}')
        .filter_map(|entry| {
            let mut parts = entry.splitn(2, '\u{1e}');
            let id = non_empty(parts.next().map(ToString::to_string))?;
            let service = non_empty(parts.next().map(ToString::to_string));
            Some(json!({
                "id": id,
                "service": service,
            }))
        })
        .collect::<Vec<_>>();

    json!(participants)
}

fn attachment_kind(
    filename: Option<&str>,
    uti: Option<&str>,
    mime: Option<&str>,
    is_sticker: Option<bool>,
) -> &'static str {
    let hints = [filename, uti, mime];
    if is_sticker == Some(true) {
        return "sticker";
    }
    if has_prefix_or_extension(
        &hints,
        "image/",
        &[".jpg", ".jpeg", ".png", ".gif", ".heic"],
    ) {
        return "image";
    }
    if has_prefix_or_extension(&hints, "video/", &[".mp4", ".mov", ".m4v"]) {
        return "video";
    }
    if has_prefix_or_extension(&hints, "audio/", &[".m4a", ".mp3", ".amr", ".caf"]) {
        return "audio";
    }
    if has_extension(&hints, &[".vcf"]) {
        return "contact";
    }
    if filename.is_some() || mime.is_some() || uti.is_some() {
        return "document";
    }

    "unknown"
}

fn has_prefix_or_extension(values: &[Option<&str>], prefix: &str, extensions: &[&str]) -> bool {
    values.iter().any(|value| {
        value
            .map(|value| value.to_ascii_lowercase().starts_with(prefix))
            .unwrap_or(false)
    }) || has_extension(values, extensions)
}

fn has_extension(values: &[Option<&str>], extensions: &[&str]) -> bool {
    values.iter().any(|value| {
        let Some(value) = value else {
            return false;
        };
        let lower = value
            .split(['?', '#'])
            .next()
            .unwrap_or(value)
            .to_ascii_lowercase();
        extensions
            .iter()
            .any(|extension| lower.ends_with(extension))
    })
}

fn basename(path: Option<&str>) -> Option<String> {
    let value = path?.split(['/', '\\']).next_back()?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(value)
        }
    })
}

fn can_join_chat_handles(schema: &SqliteSchema) -> bool {
    schema.has_table("chat_handle_join")
        && schema.has_column("chat_handle_join", "chat_id")
        && schema.has_column("chat_handle_join", "handle_id")
        && schema.has_table("handle")
        && schema.has_column("handle", "ROWID")
}

fn can_join_chat_messages(schema: &SqliteSchema) -> bool {
    schema.has_table("chat_message_join")
        && schema.has_column("chat_message_join", "message_id")
        && schema.has_column("chat_message_join", "chat_id")
        && schema.has_table("chat")
        && schema.has_column("chat", "ROWID")
}

fn can_join_attachments(schema: &SqliteSchema) -> bool {
    schema.has_table("attachment")
        && schema.has_table("message_attachment_join")
        && schema.has_column("attachment", "ROWID")
        && schema.has_column("attachment", "guid")
        && schema.has_column("message_attachment_join", "message_id")
        && schema.has_column("message_attachment_join", "attachment_id")
}

fn source_json(cfg: &MessagesConfig, evidence: &SqliteEvidence, table: &str, rowid: i64) -> Value {
    json!({
        "path": evidence.source_label(),
        "table": table,
        "rowid": rowid,
        "schema_variant": cfg.schema_variant,
        "parser_confidence": "compatible_schema",
        "copied_sidecars": evidence.copied_sidecars(),
        "files": evidence
            .source_files()
            .iter()
            .map(|file| {
                json!({
                    "role": &file.role,
                    "path": &file.path,
                    "artifact_id": file.artifact_id,
                    "system_file_id": file.system_file_id,
                    "fs_identifier": file.fs_identifier,
                })
            })
            .collect::<Vec<_>>(),
    })
}

fn select_joined_column(
    joined: bool,
    schema: &SqliteSchema,
    table: &str,
    alias: &str,
    column: &str,
    output_alias: &str,
) -> String {
    if joined {
        select_column(schema, table, alias, column, output_alias)
    } else {
        format!("NULL AS {output_alias}")
    }
}

fn direction_label(is_from_me: Option<bool>) -> &'static str {
    match is_from_me {
        Some(true) => "outgoing",
        Some(false) => "incoming",
        None => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::IosIMessageParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::parsers::mobile::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_smsdb() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("sms.db");

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
                    date_read INTEGER,
                    date_delivered INTEGER,
                    is_from_me INTEGER DEFAULT 0,
                    is_read INTEGER DEFAULT 0,
                    is_sent INTEGER DEFAULT 0,
                    is_delivered INTEGER DEFAULT 0,
                    error INTEGER DEFAULT 0,
                    cache_has_attachments INTEGER DEFAULT 0
                );

                CREATE TABLE chat (
                    ROWID INTEGER PRIMARY KEY,
                    guid TEXT NOT NULL,
                    chat_identifier TEXT,
                    service_name TEXT,
                    display_name TEXT,
                    last_read_message_timestamp INTEGER DEFAULT 0
                );

                CREATE TABLE handle (
                    ROWID INTEGER PRIMARY KEY,
                    id TEXT NOT NULL,
                    service TEXT NOT NULL,
                    country TEXT
                );

                CREATE TABLE chat_message_join (
                    chat_id INTEGER,
                    message_id INTEGER,
                    message_date INTEGER DEFAULT 0
                );

                CREATE TABLE chat_handle_join (
                    chat_id INTEGER,
                    handle_id INTEGER
                );

                CREATE TABLE attachment (
                    ROWID INTEGER PRIMARY KEY,
                    guid TEXT NOT NULL,
                    created_date INTEGER DEFAULT 0,
                    start_date INTEGER DEFAULT 0,
                    filename TEXT,
                    uti TEXT,
                    mime_type TEXT,
                    transfer_state INTEGER DEFAULT 0,
                    is_outgoing INTEGER DEFAULT 0,
                    transfer_name TEXT,
                    total_bytes INTEGER DEFAULT 0,
                    is_sticker INTEGER DEFAULT 0,
                    hide_attachment INTEGER DEFAULT 0,
                    original_guid TEXT NOT NULL
                );

                CREATE TABLE message_attachment_join (
                    message_id INTEGER,
                    attachment_id INTEGER
                );

                INSERT INTO handle (ROWID, id, service, country)
                VALUES (1, '+15551234567', 'iMessage', 'us');

                INSERT INTO chat (ROWID, guid, chat_identifier, service_name, display_name, last_read_message_timestamp)
                VALUES (1, 'iMessage;-;+15551234567', '+15551234567', 'iMessage', 'Example', 1000000000);

                INSERT INTO chat_handle_join (chat_id, handle_id) VALUES (1, 1);

                INSERT INTO message (
                    ROWID, guid, text, service, handle_id, date, date_read, date_delivered,
                    is_from_me, is_read, is_sent, is_delivered, cache_has_attachments
                ) VALUES (
                    10, 'MSG-1', 'hello', 'iMessage', 1, 1000000000, 2000000000, 3000000000,
                    1, 1, 1, 1, 1
                );

                INSERT INTO chat_message_join (chat_id, message_id, message_date)
                VALUES (1, 10, 1000000000);

                INSERT INTO attachment (
                    ROWID, guid, created_date, start_date, filename, uti, mime_type,
                    transfer_state, is_outgoing, transfer_name, total_bytes, original_guid
                ) VALUES (
                    20, 'ATT-1', 1000000000, 1000000000, '/var/mobile/Library/SMS/Attachments/example.jpg',
                    'public.jpeg', 'image/jpeg', 0, 1, 'example.jpg', 1234, 'ATT-1'
                );

                INSERT INTO message_attachment_join (message_id, attachment_id)
                VALUES (10, 20);
                "#,
            )?;
        }

        let parser = IosIMessageParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 3);
        assert_eq!(objects[0].kind, "mobile.communication.chat");
        assert_eq!(objects[1].kind, "mobile.communication.message");
        assert_eq!(objects[2].kind, "mobile.communication.attachment");
        assert_eq!(objects[0].json["participants"][0]["id"], "+15551234567");
        assert_eq!(objects[1].json["direction"], "outgoing");
        // Canonical envelope: body at the top level, app-specific under details.
        assert_eq!(objects[1].json["schema"], "chat.v1");
        assert_eq!(objects[1].json["body"], "hello");
        assert_eq!(objects[1].json["app"]["label"], "iMessage");
        assert_eq!(objects[1].json["conversation"]["id"], "1");
        assert_eq!(objects[1].json["sender"]["is_self"], true);
        assert_eq!(
            objects[1].json["details"]["message"]["display_text"],
            "hello"
        );
        assert_eq!(
            objects[1].json["timestamps"]["message"]["rfc3339"],
            "2001-01-01T00:00:01+00:00"
        );
        assert_eq!(objects[2].json["attachment"]["kind"], "image");
        assert_eq!(objects[2].json["attachment"]["total_bytes"], 1234);

        Ok(())
    }
}
