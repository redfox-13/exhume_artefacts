use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::formats::sqlite::{SqliteConnection, SqliteEvidence, SqliteSchema, select_column};
use crate::formats::timestamps::apple_absolute_to_json;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

const PARSER_NAME: &str = "mobile_ios_interactionc";
const SCHEMA_VARIANT: &str = "ios_interactionc_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

#[derive(Default)]
pub struct IosInteractionCParser;

impl Parser for IosInteractionCParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse CoreDuet interactionC.db per-app communication interactions (ZINTERACTIONS)."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        if obj.kind != "mobile.communication.interaction" {
            return Vec::new();
        }
        let Some(ts_unix_ms) = obj.json["timestamps"]["start"]["unix_ms"].as_i64() else {
            return Vec::new();
        };
        let bundle = obj.json["interaction"]["bundle_id"]
            .as_str()
            .unwrap_or("unknown app");
        let counterpart = obj.json["counterpart"]["display_name"]
            .as_str()
            .or_else(|| obj.json["counterpart"]["identifier"].as_str());
        let direction = obj.json["interaction"]["direction"]
            .as_str()
            .unwrap_or("interaction");
        let description = match counterpart {
            Some(c) => Some(format!("{bundle} {direction}: {c}")),
            None => Some(format!("{bundle} {direction}")),
        };
        let actor = obj.json["counterpart"]["identifier"]
            .as_str()
            .map(str::to_owned);
        vec![TimelineEvent {
            ts_unix_ms,
            event_type: "mobile.communication.interaction",
            description,
            actor,
        }]
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = SqliteEvidence::from_input(input, "interactionC.db")?;
        let conn = SqliteConnection::open(evidence.path())?;
        let schema = conn.schema()?;
        validate_schema(&schema)?;

        emit_interactions(&conn, &schema, &evidence, sink)
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    if !schema.has_table("ZINTERACTIONS") {
        bail!("not a supported iOS interactionC.db: missing ZINTERACTIONS table");
    }
    let missing = schema.missing_columns("ZINTERACTIONS", &["Z_PK", "ZSTARTDATE"]);
    if !missing.is_empty() {
        bail!(
            "not a supported iOS interactionC.db: missing required columns: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

fn emit_interactions(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let has_sender_join = schema.has_table("ZCONTACTS")
        && schema.has_column("ZCONTACTS", "Z_PK")
        && schema.has_column("ZINTERACTIONS", "ZSENDER");
    let sender_join = if has_sender_join {
        "LEFT JOIN ZCONTACTS c ON c.Z_PK = i.ZSENDER"
    } else {
        ""
    };
    let sender_name = if has_sender_join {
        select_column(schema, "ZCONTACTS", "c", "ZDISPLAYNAME", "sender_name")
    } else {
        "NULL AS sender_name".to_string()
    };
    let sender_identifier = if has_sender_join {
        select_column(schema, "ZCONTACTS", "c", "ZIDENTIFIER", "sender_identifier")
    } else {
        "NULL AS sender_identifier".to_string()
    };

    let sql = format!(
        r#"
        SELECT
            i.Z_PK AS interaction_pk,
            i.ZSTARTDATE AS start_date,
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {sender_name},
            {sender_identifier}
        FROM ZINTERACTIONS i
        {sender_join}
        ORDER BY i.ZSTARTDATE, i.Z_PK;
        "#,
        select_column(schema, "ZINTERACTIONS", "i", "ZBUNDLEID", "bundle_id"),
        select_column(
            schema,
            "ZINTERACTIONS",
            "i",
            "ZTARGETBUNDLEID",
            "target_bundle_id"
        ),
        select_column(schema, "ZINTERACTIONS", "i", "ZDIRECTION", "direction"),
        select_column(schema, "ZINTERACTIONS", "i", "ZENDDATE", "end_date"),
        select_column(
            schema,
            "ZINTERACTIONS",
            "i",
            "ZCREATIONDATE",
            "creation_date"
        ),
        select_column(
            schema,
            "ZINTERACTIONS",
            "i",
            "ZRECIPIENTCOUNT",
            "recipient_count"
        ),
        select_column(schema, "ZINTERACTIONS", "i", "ZMECHANISM", "mechanism"),
        select_column(
            schema,
            "ZINTERACTIONS",
            "i",
            "ZDOMAINIDENTIFIER",
            "domain_identifier"
        ),
        select_column(schema, "ZINTERACTIONS", "i", "ZGROUPNAME", "group_name"),
    );

    conn.query_rows(&sql, |row| {
        let interaction_pk = row.i64(0).context("interaction row missing Z_PK")?;
        let direction_code = row.i64(4);
        let bundle_id = non_empty(row.text(2));
        let sender_name = non_empty(row.text(11));
        let sender_identifier = non_empty(row.text(12));

        let text = format!(
            "{} {}",
            bundle_id.clone().unwrap_or_else(|| "?".to_string()),
            direction_label(direction_code),
        );
        let json = json!({
            "platform": "ios",
            "app": "interactionc",
            "record_type": "interaction",
            "source": source_json(evidence, interaction_pk),
            "timestamps": {
                "start": apple_absolute_to_json(row.f64(1)),
                "end": apple_absolute_to_json(row.f64(5)),
                "creation": apple_absolute_to_json(row.f64(6)),
            },
            "interaction": {
                "pk": interaction_pk,
                "bundle_id": bundle_id,
                "target_bundle_id": non_empty(row.text(3)),
                "direction": direction_label(direction_code),
                "direction_code": direction_code,
                "recipient_count": row.i64(7),
                "mechanism_code": row.i64(8),
                "domain_identifier": non_empty(row.text(9)),
                "group_name": non_empty(row.text(10)),
            },
            "counterpart": {
                "display_name": sender_name,
                "identifier": sender_identifier,
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "mobile.communication.interaction",
            text,
            json,
        })
    })
}

/// interactionC `ZDIRECTION`: 0 = incoming, 1 = outgoing.
fn direction_label(direction: Option<i64>) -> &'static str {
    match direction {
        Some(0) => "incoming",
        Some(1) => "outgoing",
        _ => "unknown",
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
        "table": "ZINTERACTIONS",
        "rowid": rowid,
        "schema_variant": SCHEMA_VARIANT,
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
    use super::IosInteractionCParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::formats::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_interactionc() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("interactionC.db");

        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE ZCONTACTS (
                    Z_PK INTEGER PRIMARY KEY,
                    ZDISPLAYNAME TEXT,
                    ZIDENTIFIER TEXT
                );

                CREATE TABLE ZINTERACTIONS (
                    Z_PK INTEGER PRIMARY KEY,
                    ZDIRECTION INTEGER,
                    ZRECIPIENTCOUNT INTEGER,
                    ZMECHANISM INTEGER,
                    ZSENDER INTEGER,
                    ZSTARTDATE FLOAT,
                    ZENDDATE FLOAT,
                    ZCREATIONDATE FLOAT,
                    ZBUNDLEID TEXT,
                    ZTARGETBUNDLEID TEXT,
                    ZDOMAINIDENTIFIER TEXT,
                    ZGROUPNAME TEXT
                );

                INSERT INTO ZCONTACTS (Z_PK, ZDISPLAYNAME, ZIDENTIFIER)
                VALUES (1, 'Alice', '+15551234567');

                INSERT INTO ZINTERACTIONS
                    (Z_PK, ZDIRECTION, ZRECIPIENTCOUNT, ZMECHANISM, ZSENDER, ZSTARTDATE, ZENDDATE, ZCREATIONDATE, ZBUNDLEID, ZTARGETBUNDLEID)
                VALUES
                    (10, 0, 1, 2, 1, 0.0, 1.0, 2.0, 'net.whatsapp.WhatsApp', 'net.whatsapp.WhatsApp');

                INSERT INTO ZINTERACTIONS
                    (Z_PK, ZDIRECTION, ZRECIPIENTCOUNT, ZSTARTDATE, ZBUNDLEID)
                VALUES
                    (11, 1, 2, 5.0, 'com.apple.MobileSMS');
                "#,
            )?;
        }

        let parser = IosInteractionCParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 2);
        let first = &objects[0];
        assert_eq!(first.kind, "mobile.communication.interaction");
        assert_eq!(
            first.json["interaction"]["bundle_id"],
            "net.whatsapp.WhatsApp"
        );
        assert_eq!(first.json["interaction"]["direction"], "incoming");
        assert_eq!(first.json["counterpart"]["display_name"], "Alice");
        assert_eq!(first.json["counterpart"]["identifier"], "+15551234567");
        assert_eq!(
            first.json["timestamps"]["start"]["rfc3339"],
            "2001-01-01T00:00:00+00:00"
        );

        assert_eq!(objects[1].json["interaction"]["direction"], "outgoing");
        assert!(objects[1].json["counterpart"]["display_name"].is_null());

        let events = parser.extract_timeline_events(first);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].description.as_deref(),
            Some("net.whatsapp.WhatsApp incoming: Alice")
        );

        Ok(())
    }
}
