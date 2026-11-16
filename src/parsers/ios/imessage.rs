//! iOS Apple Messages adapter for the shared application engine.

use crate::core::records::AppInfo;
use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::parsers::apps::imessage::{MessagesConfig, extract_message_timeline, run_messages};
use anyhow::Result;

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

const IOS_CONFIG: MessagesConfig = MessagesConfig {
    parser_name: PARSER_NAME,
    platform: "ios",
    app_label: "imessage",
    app: APP,
    schema_variant: SCHEMA_VARIANT,
    filename: "sms.db",
};

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

#[cfg(test)]
mod tests {
    use super::IosIMessageParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::formats::sqlite::SqliteConnection;
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
