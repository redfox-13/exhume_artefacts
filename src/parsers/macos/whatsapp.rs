//! macOS WhatsApp desktop `ChatStorage.sqlite` parser.
//!
//! The desktop app stores the same Core Data `ChatStorage.sqlite` schema
//! (`ZWAMESSAGE` / `ZWACHATSESSION` / `ZWAMEDIAITEM`) as iOS WhatsApp, under
//! `~/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/`. This parser
//! reuses the shared WhatsApp engine
//! ([`crate::parsers::mobile::ios::whatsapp`]) with a macOS config and emits the
//! canonical `chat.v1` envelope.

use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::parsers::mobile::common::records::AppInfo;
use crate::parsers::mobile::ios::whatsapp::{
    WhatsAppConfig, extract_whatsapp_timeline, run_whatsapp,
};
use anyhow::Result;

const PARSER_NAME: &str = "macos_whatsapp";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

const MACOS_CONFIG: WhatsAppConfig = WhatsAppConfig {
    parser_name: PARSER_NAME,
    platform: "macos",
    app_label: "whatsapp",
    app: AppInfo {
        bundle_id: "net.whatsapp.WhatsApp",
        label: "WhatsApp",
    },
    schema_variant: "macos_whatsapp_chatstorage_coredata_v1",
};

#[derive(Default)]
pub struct MacosWhatsAppParser;

impl Parser for MacosWhatsAppParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse WhatsApp desktop ChatStorage.sqlite chats, messages, and media references on macOS."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        extract_whatsapp_timeline(obj)
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        run_whatsapp(&MACOS_CONFIG, input, sink)
    }
}

#[cfg(test)]
mod tests {
    use super::MacosWhatsAppParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::parsers::mobile::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_chatstorage() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("ChatStorage.sqlite");

        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE ZWACHATSESSION (
                    Z_PK INTEGER PRIMARY KEY,
                    ZCONTACTJID TEXT,
                    ZPARTNERNAME TEXT,
                    ZSESSIONTYPE INTEGER,
                    ZLASTMESSAGEDATE REAL
                );
                CREATE TABLE ZWAMESSAGE (
                    Z_PK INTEGER PRIMARY KEY,
                    ZTEXT TEXT,
                    ZISFROMME INTEGER,
                    ZMESSAGETYPE INTEGER,
                    ZMESSAGESTATUS INTEGER,
                    ZCHATSESSION INTEGER,
                    ZMESSAGEDATE REAL,
                    ZSENTDATE REAL,
                    ZFROMJID TEXT,
                    ZTOJID TEXT
                );

                INSERT INTO ZWACHATSESSION VALUES (1, '15551234567@s.whatsapp.net', 'Alice', 0, 700000000.0);
                INSERT INTO ZWAMESSAGE (Z_PK, ZTEXT, ZISFROMME, ZMESSAGETYPE, ZMESSAGESTATUS, ZCHATSESSION, ZMESSAGEDATE, ZSENTDATE, ZFROMJID, ZTOJID)
                VALUES (10, 'hi there', 0, 0, 0, 1, 700000000.0, 700000000.0, '15551234567@s.whatsapp.net', NULL);
                "#,
            )?;
        }

        let parser = MacosWhatsAppParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        // 1 chat + 1 message
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].kind, "mobile.communication.chat");
        assert_eq!(objects[0].json["platform"], "macos");
        let message = &objects[1];
        assert_eq!(message.kind, "mobile.communication.message");
        assert_eq!(message.json["schema"], "chat.v1");
        assert_eq!(message.json["platform"], "macos");
        assert_eq!(message.json["body"], "hi there");
        assert_eq!(message.json["direction"], "incoming");
        assert_eq!(message.json["app"]["label"], "WhatsApp");

        let events = parser.extract_timeline_events(message);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].description.as_deref(), Some("hi there"));

        Ok(())
    }
}
