use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::formats::sqlite::{SqliteConnection, SqliteEvidence, SqliteSchema, select_column};
use crate::formats::timestamps::apple_absolute_to_json;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

const PARSER_NAME: &str = "mobile_ios_datausage";
const SCHEMA_VARIANT: &str = "ios_datausage_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

#[derive(Default)]
pub struct IosDataUsageParser;

impl Parser for IosDataUsageParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse DataUsage.sqlite per-process cellular (WWAN) and Wi-Fi network usage (ZLIVEUSAGE)."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        if obj.kind != "mobile.network.usage" {
            return Vec::new();
        }
        let Some(ts_unix_ms) = obj.json["timestamps"]["usage"]["unix_ms"].as_i64() else {
            return Vec::new();
        };
        let process = obj.json["process"]["bundle_name"]
            .as_str()
            .or_else(|| obj.json["process"]["name"].as_str())
            .unwrap_or("unknown process");
        let wwan_in = obj.json["usage"]["wwan_in"].as_f64().unwrap_or(0.0);
        let wwan_out = obj.json["usage"]["wwan_out"].as_f64().unwrap_or(0.0);
        let description = Some(format!(
            "network usage: {process} (cell {} in / {} out bytes)",
            wwan_in as i64, wwan_out as i64
        ));
        vec![TimelineEvent {
            ts_unix_ms,
            event_type: "mobile.network.usage",
            description,
            actor: None,
        }]
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = SqliteEvidence::from_input(input, "DataUsage.sqlite")?;
        let conn = SqliteConnection::open(evidence.path())?;
        let schema = conn.schema()?;
        validate_schema(&schema)?;

        emit_usage(&conn, &schema, &evidence, sink)
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    if !schema.has_table("ZLIVEUSAGE") {
        bail!("not a supported iOS DataUsage.sqlite: missing ZLIVEUSAGE table");
    }
    let missing = schema.missing_columns("ZLIVEUSAGE", &["Z_PK", "ZTIMESTAMP"]);
    if !missing.is_empty() {
        bail!(
            "not a supported iOS DataUsage.sqlite: missing required columns: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

fn emit_usage(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let has_process_join = schema.has_table("ZPROCESS")
        && schema.has_column("ZPROCESS", "Z_PK")
        && schema.has_column("ZLIVEUSAGE", "ZHASPROCESS");
    let process_join = if has_process_join {
        "LEFT JOIN ZPROCESS p ON p.Z_PK = l.ZHASPROCESS"
    } else {
        ""
    };
    let proc_name = if has_process_join {
        select_column(schema, "ZPROCESS", "p", "ZPROCNAME", "proc_name")
    } else {
        "NULL AS proc_name".to_string()
    };
    let bundle_name = if has_process_join {
        select_column(schema, "ZPROCESS", "p", "ZBUNDLENAME", "bundle_name")
    } else {
        "NULL AS bundle_name".to_string()
    };
    let proc_first = if has_process_join {
        select_column(schema, "ZPROCESS", "p", "ZFIRSTTIMESTAMP", "proc_first_ts")
    } else {
        "NULL AS proc_first_ts".to_string()
    };

    let sql = format!(
        r#"
        SELECT
            l.Z_PK AS usage_pk,
            l.ZTIMESTAMP AS usage_ts,
            {},
            {},
            {},
            {},
            {},
            {proc_name},
            {bundle_name},
            {proc_first}
        FROM ZLIVEUSAGE l
        {process_join}
        ORDER BY l.ZTIMESTAMP, l.Z_PK;
        "#,
        select_column(schema, "ZLIVEUSAGE", "l", "ZWIFIIN", "wifi_in"),
        select_column(schema, "ZLIVEUSAGE", "l", "ZWIFIOUT", "wifi_out"),
        select_column(schema, "ZLIVEUSAGE", "l", "ZWWANIN", "wwan_in"),
        select_column(schema, "ZLIVEUSAGE", "l", "ZWWANOUT", "wwan_out"),
        select_column(schema, "ZLIVEUSAGE", "l", "ZKIND", "kind_code"),
    );

    conn.query_rows(&sql, |row| {
        let usage_pk = row.i64(0).context("usage row missing Z_PK")?;
        let proc_name = non_empty(row.text(7));
        let bundle_name = non_empty(row.text(8));

        let text = bundle_name
            .clone()
            .or_else(|| proc_name.clone())
            .unwrap_or_default();
        let json = json!({
            "platform": "ios",
            "app": "datausage",
            "record_type": "network_usage",
            "source": source_json(evidence, usage_pk),
            "timestamps": {
                "usage": apple_absolute_to_json(row.f64(1)),
                "process_first_seen": apple_absolute_to_json(row.f64(9)),
            },
            "process": {
                "name": proc_name,
                "bundle_name": bundle_name,
            },
            "usage": {
                "pk": usage_pk,
                "wifi_in": row.f64(2),
                "wifi_out": row.f64(3),
                "wwan_in": row.f64(4),
                "wwan_out": row.f64(5),
                "kind_code": row.i64(6),
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "mobile.network.usage",
            text,
            json,
        })
    })
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
        "table": "ZLIVEUSAGE",
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
    use super::IosDataUsageParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::formats::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_datausage() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("DataUsage.sqlite");

        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE ZPROCESS (
                    Z_PK INTEGER PRIMARY KEY,
                    ZFIRSTTIMESTAMP FLOAT,
                    ZBUNDLENAME TEXT,
                    ZPROCNAME TEXT
                );

                CREATE TABLE ZLIVEUSAGE (
                    Z_PK INTEGER PRIMARY KEY,
                    ZKIND INTEGER,
                    ZHASPROCESS INTEGER,
                    ZTIMESTAMP FLOAT,
                    ZWIFIIN FLOAT,
                    ZWIFIOUT FLOAT,
                    ZWWANIN FLOAT,
                    ZWWANOUT FLOAT
                );

                INSERT INTO ZPROCESS (Z_PK, ZFIRSTTIMESTAMP, ZBUNDLENAME, ZPROCNAME)
                VALUES (1, 0.0, 'net.whatsapp.WhatsApp', 'WhatsApp');

                INSERT INTO ZLIVEUSAGE (Z_PK, ZKIND, ZHASPROCESS, ZTIMESTAMP, ZWIFIIN, ZWIFIOUT, ZWWANIN, ZWWANOUT)
                VALUES (10, 1, 1, 0.0, 1000.0, 500.0, 20000.0, 8000.0);
                "#,
            )?;
        }

        let parser = IosDataUsageParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 1);
        let row = &objects[0];
        assert_eq!(row.kind, "mobile.network.usage");
        assert_eq!(row.json["process"]["bundle_name"], "net.whatsapp.WhatsApp");
        assert_eq!(row.json["usage"]["wwan_in"], 20000.0);
        assert_eq!(row.json["usage"]["wwan_out"], 8000.0);
        assert_eq!(
            row.json["timestamps"]["usage"]["rfc3339"],
            "2001-01-01T00:00:00+00:00"
        );

        let events = parser.extract_timeline_events(row);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].description.as_deref(),
            Some("network usage: net.whatsapp.WhatsApp (cell 20000 in / 8000 out bytes)")
        );

        Ok(())
    }
}
