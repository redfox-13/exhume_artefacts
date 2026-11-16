//! iOS WhatsApp adapter for the shared application engine.

use crate::core::records::AppInfo;
use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::parsers::apps::whatsapp::apple::{
    WhatsAppConfig, extract_whatsapp_timeline, run_whatsapp,
};
use anyhow::Result;

const PARSER_NAME: &str = "mobile_ios_whatsapp";
const APP: AppInfo = AppInfo {
    bundle_id: "net.whatsapp.WhatsApp",
    label: "WhatsApp",
};
const SCHEMA_VARIANT: &str = "ios_whatsapp_chatstorage_coredata_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

const IOS_CONFIG: WhatsAppConfig = WhatsAppConfig {
    parser_name: PARSER_NAME,
    platform: "ios",
    app_label: "whatsapp",
    app: APP,
    schema_variant: SCHEMA_VARIANT,
};

#[derive(Default)]
pub struct IosWhatsAppParser;

impl Parser for IosWhatsAppParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse WhatsApp for iOS ChatStorage.sqlite chats, messages, and media references."
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
        run_whatsapp(&IOS_CONFIG, input, sink)
    }
}

#[cfg(test)]
mod tests {
    use super::IosWhatsAppParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::formats::sqlite::SqliteConnection;
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
                    ZCONTACTJID VARCHAR,
                    ZPARTNERNAME VARCHAR,
                    ZSESSIONTYPE INTEGER,
                    ZLASTMESSAGEDATE TIMESTAMP
                );

                CREATE TABLE ZWAMESSAGE (
                    Z_PK INTEGER PRIMARY KEY,
                    ZISFROMME INTEGER,
                    ZMESSAGETYPE INTEGER,
                    ZMESSAGESTATUS INTEGER,
                    ZCHATSESSION INTEGER,
                    ZMEDIAITEM INTEGER,
                    ZMESSAGEDATE TIMESTAMP,
                    ZSENTDATE TIMESTAMP,
                    ZSTANZAID VARCHAR,
                    ZTEXT VARCHAR
                );

                CREATE TABLE ZWAMEDIAITEM (
                    Z_PK INTEGER PRIMARY KEY,
                    ZMESSAGE INTEGER,
                    ZMEDIALOCALPATH VARCHAR,
                    ZFILESIZE INTEGER
                );

                INSERT INTO ZWACHATSESSION (
                    Z_PK,
                    ZCONTACTJID,
                    ZPARTNERNAME,
                    ZSESSIONTYPE,
                    ZLASTMESSAGEDATE
                ) VALUES (1, '15551234567@s.whatsapp.net', 'Example Chat', 0, 0);

                INSERT INTO ZWAMEDIAITEM (
                    Z_PK,
                    ZMESSAGE,
                    ZMEDIALOCALPATH,
                    ZFILESIZE
                ) VALUES (2, 10, 'Message/Media/example.jpg', 1234);

                INSERT INTO ZWAMEDIAITEM (
                    Z_PK,
                    ZMESSAGE,
                    ZMEDIALOCALPATH,
                    ZFILESIZE
                ) VALUES (3, 11, 'Message/Media/not-an-attachment.jpg', 0);

                INSERT INTO ZWAMESSAGE (
                    Z_PK,
                    ZISFROMME,
                    ZMESSAGETYPE,
                    ZMESSAGESTATUS,
                    ZCHATSESSION,
                    ZMEDIAITEM,
                    ZMESSAGEDATE,
                    ZSENTDATE,
                    ZSTANZAID,
                    ZTEXT
                ) VALUES (10, 1, 1, 8, 1, 2, 0, 1, 'ABC123', 'hello');

                INSERT INTO ZWAMESSAGE (
                    Z_PK,
                    ZISFROMME,
                    ZMESSAGETYPE,
                    ZMESSAGESTATUS,
                    ZCHATSESSION,
                    ZMEDIAITEM,
                    ZMESSAGEDATE,
                    ZSENTDATE,
                    ZSTANZAID,
                    ZTEXT
                ) VALUES (11, 0, 0, 8, 1, 3, 2, 3, 'TEXT123', 'plain text');
                "#,
            )?;
        }

        let parser = IosWhatsAppParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 4);
        assert_eq!(objects[0].kind, "mobile.communication.chat");
        assert_eq!(objects[1].kind, "mobile.communication.message");
        assert_eq!(objects[2].kind, "mobile.communication.attachment");
        assert_eq!(objects[3].kind, "mobile.communication.message");
        assert_eq!(objects[1].json["direction"], "outgoing");
        assert_eq!(objects[1].json["schema"], "chat.v1");
        assert_eq!(objects[1].json["app"]["label"], "WhatsApp");
        assert_eq!(objects[1].json["body"], "hello");
        assert_eq!(objects[1].json["details"]["message"]["stanza_id"], "ABC123");
        assert_eq!(
            objects[1].json["timestamps"]["message"]["rfc3339"],
            "2001-01-01T00:00:00+00:00"
        );
        assert_eq!(objects[1].json["details"]["media"]["file_size"], 1234);
        assert_eq!(objects[2].json["attachment"]["kind"], "image");
        assert_eq!(
            objects[2].json["attachment"]["local_path"],
            "Message/Media/example.jpg"
        );
        assert_eq!(objects[2].json["message"]["rowid"], 10);
        assert_eq!(objects[3].json["details"]["message"]["type_family"], "text");
        assert_eq!(objects[3].json["body"], "plain text");

        Ok(())
    }
}
