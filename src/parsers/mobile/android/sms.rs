use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::parsers::mobile::common::records::{
    AppInfo, ChatMessage, Conversation, Direction, MessageState, Party,
};
use crate::parsers::mobile::common::timestamps::unix_millis_to_json;
use crate::parsers::mobile::sqlite::{
    SqliteConnection, SqliteEvidence, SqliteSchema, select_column,
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const PARSER_NAME: &str = "mobile_android_sms";
const APP: AppInfo = AppInfo {
    bundle_id: "com.android.providers.telephony",
    label: "SMS",
};
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

#[derive(Default)]
pub struct AndroidSmsParser;

impl Parser for AndroidSmsParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse the Android telephony provider mmssms.db SMS messages, threads and addresses."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        // Identical to every other chat parser because the envelope guarantees
        // the shape — no per-app path knowledge required.
        if obj.kind != "mobile.communication.message" {
            return Vec::new();
        }
        let Some(ts_unix_ms) = obj.json["timestamps"]["message"]["unix_ms"].as_i64() else {
            return Vec::new();
        };
        let description = obj.json["body"]
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

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = SqliteEvidence::from_input(input, "mmssms.db")?;
        let conn = SqliteConnection::open(evidence.path())?;
        let schema = conn.schema()?;
        validate_schema(&schema)?;

        let addresses = load_canonical_addresses(&conn, &schema)?;
        let threads = load_threads(&conn, &schema, &addresses)?;
        emit_messages(&conn, &schema, &evidence, &threads, sink)
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    if !schema.has_table("sms") {
        bail!("not a supported Android mmssms.db: missing sms table");
    }
    let missing = schema.missing_columns("sms", &["_id", "date", "type"]);
    if !missing.is_empty() {
        bail!(
            "not a supported Android mmssms.db: missing required columns: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

/// `canonical_addresses._id` -> address text, used to resolve thread recipients.
fn load_canonical_addresses(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
) -> Result<BTreeMap<i64, String>> {
    let mut out = BTreeMap::new();
    if !schema.has_table("canonical_addresses")
        || !schema.has_column("canonical_addresses", "address")
    {
        return Ok(out);
    }
    conn.query_rows("SELECT _id, address FROM canonical_addresses;", |row| {
        if let (Some(id), Some(address)) = (row.i64(0), non_empty(row.text(1))) {
            out.insert(id, address);
        }
        Ok(())
    })?;
    Ok(out)
}

#[derive(Debug, Clone, Default)]
struct ThreadInfo {
    recipients: Vec<String>,
    snippet: Option<String>,
}

/// `threads.recipient_ids` is a space-separated list of canonical address ids,
/// which is how Android represents group conversations.
fn load_threads(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    addresses: &BTreeMap<i64, String>,
) -> Result<BTreeMap<i64, ThreadInfo>> {
    let mut out = BTreeMap::new();
    if !schema.has_table("threads") {
        return Ok(out);
    }
    let sql = format!(
        "SELECT _id, {}, {} FROM threads;",
        select_column(
            schema,
            "threads",
            "threads",
            "recipient_ids",
            "recipient_ids"
        ),
        select_column(schema, "threads", "threads", "snippet", "snippet"),
    );
    conn.query_rows(&sql, |row| {
        let Some(id) = row.i64(0) else { return Ok(()) };
        let recipients = row
            .text(1)
            .map(|ids| {
                ids.split_whitespace()
                    .filter_map(|token| token.parse::<i64>().ok())
                    .filter_map(|address_id| addresses.get(&address_id).cloned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        out.insert(
            id,
            ThreadInfo {
                recipients,
                snippet: non_empty(row.text(2)),
            },
        );
        Ok(())
    })?;
    Ok(out)
}

fn emit_messages(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    threads: &BTreeMap<i64, ThreadInfo>,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let sql = format!(
        r#"
        SELECT
            s._id AS sms_id,
            s.date AS date,
            s.type AS type_code,
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
        FROM sms s
        ORDER BY s.date, s._id;
        "#,
        select_column(schema, "sms", "s", "thread_id", "thread_id"),
        select_column(schema, "sms", "s", "address", "address"),
        select_column(schema, "sms", "s", "body", "body"),
        select_column(schema, "sms", "s", "date_sent", "date_sent"),
        select_column(schema, "sms", "s", "read", "read"),
        select_column(schema, "sms", "s", "seen", "seen"),
        select_column(schema, "sms", "s", "status", "status"),
        select_column(schema, "sms", "s", "protocol", "protocol"),
        select_column(schema, "sms", "s", "subject", "subject"),
        select_column(schema, "sms", "s", "service_center", "service_center"),
        select_column(schema, "sms", "s", "person", "person"),
    );

    conn.query_rows(&sql, |row| {
        let sms_id = row.i64(0).context("sms row missing _id")?;
        let date_ms = row.i64(1);
        let type_code = row.i64(2);
        let thread_id = row.i64(3);
        let address = non_empty(row.text(4));
        let body = non_empty(row.text(5));
        let direction = direction_from_type(type_code);

        let thread = thread_id.and_then(|id| threads.get(&id));
        let participants = thread
            .map(|t| {
                t.recipients
                    .iter()
                    .map(|address| Party {
                        id: Some(address.clone()),
                        display_name: None,
                        is_self: false,
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // Thread id is the stable conversation key; fall back to the address
        // so a message orphaned from its thread still groups sensibly.
        let conversation_id = thread_id
            .map(|id| id.to_string())
            .or_else(|| address.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let conversation_name = participants
            .first()
            .and_then(|p| p.id.clone())
            .or_else(|| address.clone());

        let outgoing = direction == Direction::Outgoing;
        let sender = Party {
            id: if outgoing { None } else { address.clone() },
            display_name: None,
            is_self: outgoing,
        };

        let message = ChatMessage {
            parser: PARSER_NAME,
            platform: "android",
            app: APP,
            conversation: Conversation {
                id: conversation_id,
                display_name: conversation_name,
                participants,
            },
            direction,
            sender,
            // Android records both in epoch milliseconds already.
            timestamp: unix_millis_to_json(date_ms),
            sent: unix_millis_to_json(row.i64(6)),
            received: if outgoing {
                Value::Null
            } else {
                unix_millis_to_json(date_ms)
            },
            body,
            attachments: Vec::new(), // MMS parts live in `pdu`/`part`, not `sms`
            state: MessageState {
                read: row.bool(7),
                delivered: delivered_from_status(row.i64(9)),
                deleted: None,
            },
            source: source_json(evidence, sms_id),
            details: json!({
                "sms": {
                    "id": sms_id,
                    "thread_id": thread_id,
                    "type_code": type_code,
                    "type": type_label(type_code),
                    "status_code": row.i64(9),
                    "protocol_code": row.i64(10),
                    "subject": non_empty(row.text(11)),
                    "service_center": non_empty(row.text(12)),
                    "person_id": row.i64(13),
                    "seen": row.bool(8),
                },
                "thread": {
                    "snippet": thread.and_then(|t| t.snippet.clone()),
                },
            }),
        };

        sink(message.into())
    })
}

/// Android `sms.type`: 1 inbox, 2 sent, 3 draft, 4 outbox, 5 failed, 6 queued.
fn direction_from_type(type_code: Option<i64>) -> Direction {
    match type_code {
        Some(1) => Direction::Incoming,
        Some(2) | Some(4) | Some(5) | Some(6) => Direction::Outgoing,
        _ => Direction::Unknown,
    }
}

fn type_label(type_code: Option<i64>) -> &'static str {
    match type_code {
        Some(1) => "inbox",
        Some(2) => "sent",
        Some(3) => "draft",
        Some(4) => "outbox",
        Some(5) => "failed",
        Some(6) => "queued",
        _ => "unknown",
    }
}

/// `sms.status`: -1 none, 0 complete, 32 pending, 64 failed.
fn delivered_from_status(status: Option<i64>) -> Option<bool> {
    match status {
        Some(0) => Some(true),
        Some(64) => Some(false),
        _ => None, // no delivery report requested — not the same as "not delivered"
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

fn source_json(evidence: &SqliteEvidence, rowid: i64) -> Value {
    json!({
        "path": evidence.source_label(),
        "table": "sms",
        "rowid": rowid,
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

#[cfg(test)]
mod tests {
    use super::AndroidSmsParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::parsers::mobile::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_mmssms() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("mmssms.db");

        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE canonical_addresses (_id INTEGER PRIMARY KEY, address TEXT);
                CREATE TABLE threads (
                    _id INTEGER PRIMARY KEY,
                    date INTEGER,
                    message_count INTEGER,
                    recipient_ids TEXT,
                    snippet TEXT,
                    read INTEGER
                );
                CREATE TABLE sms (
                    _id INTEGER PRIMARY KEY,
                    thread_id INTEGER,
                    address TEXT,
                    person INTEGER,
                    date INTEGER,
                    date_sent INTEGER,
                    protocol INTEGER,
                    read INTEGER,
                    status INTEGER,
                    type INTEGER,
                    subject TEXT,
                    body TEXT,
                    service_center TEXT,
                    seen INTEGER
                );

                INSERT INTO canonical_addresses (_id, address) VALUES (3, '+201172137258');
                INSERT INTO threads (_id, date, message_count, recipient_ids, snippet, read)
                VALUES (3, 1695240589000, 1, '3', 'pay back the money', 0);

                INSERT INTO sms (_id, thread_id, address, person, date, date_sent, protocol, read, status, type, subject, body, service_center, seen)
                VALUES (1, 3, '+201172137258', 6, 1695240589641, 1695244189000, 0, 0, -1, 1, '', 'pay back the money', '', 1);

                INSERT INTO sms (_id, thread_id, address, date, date_sent, read, status, type, body, seen)
                VALUES (2, 3, '+201172137258', 1695250000000, 1695250000000, 1, 0, 2, 'no', 1);
                "#,
            )?;
        }

        let parser = AndroidSmsParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 2);

        // Incoming message maps onto the canonical envelope.
        let incoming = &objects[0];
        assert_eq!(incoming.kind, "mobile.communication.message");
        assert_eq!(incoming.json["schema"], "chat.v1");
        assert_eq!(incoming.json["platform"], "android");
        assert_eq!(incoming.json["app"]["label"], "SMS");
        assert_eq!(incoming.json["direction"], "incoming");
        assert_eq!(incoming.json["conversation"]["id"], "3");
        assert_eq!(
            incoming.json["conversation"]["participants"][0]["id"],
            "+201172137258"
        );
        assert_eq!(incoming.json["sender"]["id"], "+201172137258");
        assert_eq!(incoming.json["sender"]["is_self"], false);
        assert_eq!(incoming.json["body"], "pay back the money");
        assert_eq!(incoming.json["state"]["read"], false);
        // Epoch milliseconds converted through the shared helper.
        assert_eq!(
            incoming.json["timestamps"]["message"]["unix_ms"],
            1_695_240_589_641i64
        );
        assert_eq!(
            incoming.json["timestamps"]["message"]["original_epoch"],
            "unix_milliseconds"
        );
        // App-specific detail preserved.
        assert_eq!(incoming.json["details"]["sms"]["type"], "inbox");
        assert_eq!(
            incoming.json["details"]["thread"]["snippet"],
            "pay back the money"
        );

        // Outgoing flips sender/self and leaves `received` null.
        let outgoing = &objects[1];
        assert_eq!(outgoing.json["direction"], "outgoing");
        assert_eq!(outgoing.json["sender"]["is_self"], true);
        assert!(outgoing.json["timestamps"]["received"].is_null());
        assert_eq!(outgoing.json["state"]["delivered"], true);

        // The timeline extraction is app-agnostic.
        let events = parser.extract_timeline_events(incoming);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "mobile.communication.message");
        assert_eq!(events[0].actor.as_deref(), Some("+201172137258"));

        Ok(())
    }
}
