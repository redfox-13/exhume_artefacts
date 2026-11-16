use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::formats::sqlite::{SqliteConnection, SqliteEvidence, SqliteSchema, select_column};
use crate::formats::timestamps::apple_absolute_to_json;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

const PARSER_NAME: &str = "mobile_ios_callhistory";
const SCHEMA_VARIANT: &str = "ios_callhistory_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

#[derive(Default)]
pub struct IosCallHistoryParser;

impl Parser for IosCallHistoryParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse Apple CallHistory.storedata cellular, FaceTime and third-party CallKit call records."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        if obj.kind != "mobile.communication.call" {
            return Vec::new();
        }
        let Some(ts_unix_ms) = obj.json["timestamps"]["call"]["unix_ms"].as_i64() else {
            return Vec::new();
        };

        let direction = obj.json["direction"].as_str().unwrap_or("unknown");
        let party = obj.json["remote_party"]["name"]
            .as_str()
            .or_else(|| obj.json["remote_party"]["address"].as_str())
            .unwrap_or("unknown party");
        let state = if obj.json["missed"].as_bool() == Some(true) {
            "missed "
        } else {
            ""
        };
        let description = Some(format!("{state}{direction} call - {party}"));

        let actor = if direction == "incoming" {
            obj.json["remote_party"]["address"]
                .as_str()
                .map(str::to_owned)
        } else {
            None
        };

        vec![TimelineEvent {
            ts_unix_ms,
            event_type: "mobile.communication.call",
            description,
            actor,
        }]
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = SqliteEvidence::from_input(input, "CallHistory.storedata")?;
        let conn = SqliteConnection::open(evidence.path())?;
        let schema = conn.schema()?;
        validate_schema(&schema)?;

        emit_calls(&conn, &schema, &evidence, sink)
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    if !schema.has_table("ZCALLRECORD") {
        bail!("not a supported iOS CallHistory.storedata: missing ZCALLRECORD table");
    }

    let missing = schema.missing_columns(
        "ZCALLRECORD",
        &["Z_PK", "ZDATE", "ZADDRESS", "ZORIGINATED", "ZANSWERED"],
    );
    if !missing.is_empty() {
        bail!(
            "not a supported iOS CallHistory.storedata: missing required columns: {}",
            missing.join(", ")
        );
    }

    Ok(())
}

fn emit_calls(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let sql = format!(
        r#"
        SELECT
            r.Z_PK AS call_pk,
            {},
            r.ZADDRESS AS address,
            {},
            r.ZDATE AS call_date,
            {},
            r.ZORIGINATED AS originated,
            r.ZANSWERED AS answered,
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {}
        FROM ZCALLRECORD r
        ORDER BY r.ZDATE, r.Z_PK;
        "#,
        select_column(schema, "ZCALLRECORD", "r", "ZUNIQUE_ID", "unique_id"),
        select_column(schema, "ZCALLRECORD", "r", "ZNAME", "name"),
        select_column(schema, "ZCALLRECORD", "r", "ZDURATION", "duration"),
        select_column(schema, "ZCALLRECORD", "r", "ZCALLTYPE", "call_type"),
        select_column(
            schema,
            "ZCALLRECORD",
            "r",
            "ZCALL_CATEGORY",
            "call_category"
        ),
        select_column(
            schema,
            "ZCALLRECORD",
            "r",
            "ZSERVICE_PROVIDER",
            "service_provider"
        ),
        select_column(schema, "ZCALLRECORD", "r", "ZLOCATION", "location"),
        select_column(
            schema,
            "ZCALLRECORD",
            "r",
            "ZISO_COUNTRY_CODE",
            "iso_country_code"
        ),
        select_column(schema, "ZCALLRECORD", "r", "ZREAD", "read"),
        select_column(
            schema,
            "ZCALLRECORD",
            "r",
            "ZDISCONNECTED_CAUSE",
            "disconnected_cause"
        ),
        select_column(
            schema,
            "ZCALLRECORD",
            "r",
            "ZNUMBER_AVAILABILITY",
            "number_availability"
        ),
        select_column(schema, "ZCALLRECORD", "r", "ZHANDLE_TYPE", "handle_type"),
    );

    conn.query_rows(&sql, |row| {
        let call_pk = row.i64(0).context("call record missing Z_PK")?;
        let address = non_empty(row.text(2));
        let name = non_empty(row.text(3));
        let originated = row.bool(6);
        let answered = row.bool(7);
        let direction = direction_label(originated);
        let missed = originated == Some(false) && answered == Some(false);
        let call_type_code = row.i64(8);
        let service_provider = non_empty(row.text(10));

        let text = name.clone().or_else(|| address.clone()).unwrap_or_default();
        let json = json!({
            "platform": "ios",
            "app": "callhistory",
            "record_type": "call",
            "source": source_json(evidence, call_pk),
            "timestamps": {
                "call": apple_absolute_to_json(row.f64(4)),
            },
            "direction": direction,
            "answered": answered,
            "missed": missed,
            "call": {
                "pk": call_pk,
                "unique_id": row.text(1),
                "duration_seconds": row.f64(5),
                "type_code": call_type_code,
                "type_family": call_type_family(call_type_code, service_provider.as_deref()),
                "category_code": row.i64(9),
                "read": row.bool(13),
                "disconnected_cause_code": row.i64(14),
                "number_availability_code": row.i64(15),
                "handle_type_code": row.i64(16),
            },
            "remote_party": {
                "address": address,
                "name": name,
                "location": row.text(11),
                "iso_country_code": non_empty(row.text(12)),
            },
            "service": {
                "provider": service_provider,
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "mobile.communication.call",
            text,
            json,
        })
    })
}

/// Known `ZCALLTYPE` codes; third-party CallKit apps (WhatsApp, Signal, ...)
/// report their own codes, so fall back to the service provider bundle.
fn call_type_family(code: Option<i64>, service_provider: Option<&str>) -> &'static str {
    match code {
        Some(1) => "cellular",
        Some(8) => "facetime_video",
        Some(16) => "facetime_audio",
        _ => match service_provider {
            Some(provider) if provider.contains("com.apple") => "apple_other",
            Some(_) => "third_party_voip",
            None => "unknown",
        },
    }
}

fn direction_label(originated: Option<bool>) -> &'static str {
    match originated {
        Some(true) => "outgoing",
        Some(false) => "incoming",
        None => "unknown",
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
        "table": "ZCALLRECORD",
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
    use super::IosCallHistoryParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::formats::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_callhistory() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("CallHistory.storedata");

        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE ZCALLRECORD (
                    Z_PK INTEGER PRIMARY KEY,
                    ZANSWERED INTEGER,
                    ZCALL_CATEGORY INTEGER,
                    ZCALLTYPE INTEGER,
                    ZDISCONNECTED_CAUSE INTEGER,
                    ZHANDLE_TYPE INTEGER,
                    ZNUMBER_AVAILABILITY INTEGER,
                    ZORIGINATED INTEGER,
                    ZREAD INTEGER,
                    ZDATE TIMESTAMP,
                    ZDURATION FLOAT,
                    ZADDRESS VARCHAR,
                    ZISO_COUNTRY_CODE VARCHAR,
                    ZLOCATION VARCHAR,
                    ZNAME VARCHAR,
                    ZSERVICE_PROVIDER VARCHAR,
                    ZUNIQUE_ID VARCHAR
                );

                INSERT INTO ZCALLRECORD (
                    Z_PK, ZANSWERED, ZCALLTYPE, ZORIGINATED, ZREAD, ZDATE, ZDURATION,
                    ZADDRESS, ZNAME, ZSERVICE_PROVIDER, ZUNIQUE_ID
                ) VALUES (
                    1, 1, 1, 1, 1, 0.0, 65.5,
                    '+15551234567', 'Alice', 'com.apple.Telephony', 'CALL-1'
                );

                INSERT INTO ZCALLRECORD (
                    Z_PK, ZANSWERED, ZCALLTYPE, ZORIGINATED, ZREAD, ZDATE, ZDURATION,
                    ZADDRESS, ZSERVICE_PROVIDER, ZUNIQUE_ID
                ) VALUES (
                    2, 0, 0, 0, 0, 1.0, 0.0,
                    '+15559876543', 'UKFA9XBX6K.net.whatsapp.WhatsApp', 'CALL-2'
                );
                "#,
            )?;
        }

        let parser = IosCallHistoryParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].kind, "mobile.communication.call");
        assert_eq!(objects[0].json["direction"], "outgoing");
        assert_eq!(objects[0].json["missed"], false);
        assert_eq!(objects[0].json["call"]["type_family"], "cellular");
        assert_eq!(objects[0].json["remote_party"]["name"], "Alice");
        assert_eq!(
            objects[0].json["timestamps"]["call"]["rfc3339"],
            "2001-01-01T00:00:00+00:00"
        );

        assert_eq!(objects[1].json["direction"], "incoming");
        assert_eq!(objects[1].json["missed"], true);
        assert_eq!(objects[1].json["call"]["type_family"], "third_party_voip");

        let events = parser.extract_timeline_events(&objects[1]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "mobile.communication.call");
        assert_eq!(
            events[0].description.as_deref(),
            Some("missed incoming call - +15559876543")
        );
        assert_eq!(events[0].actor.as_deref(), Some("+15559876543"));

        Ok(())
    }
}
