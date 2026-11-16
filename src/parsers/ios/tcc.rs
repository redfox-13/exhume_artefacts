use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::formats::sqlite::{SqliteConnection, SqliteEvidence, SqliteSchema, select_column};
use crate::formats::timestamps::unix_seconds_to_json;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

const PARSER_NAME: &str = "mobile_ios_tcc";
const SCHEMA_VARIANT: &str = "ios_tcc_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

#[derive(Default)]
pub struct IosTccParser;

impl Parser for IosTccParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse Apple TCC.db privacy permission grants (which app was allowed or denied each protected resource)."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        if obj.kind != "mobile.config.privacy_permission" {
            return Vec::new();
        }
        let Some(ts_unix_ms) = obj.json["timestamps"]["last_modified"]["unix_ms"].as_i64() else {
            return Vec::new();
        };
        let service = obj.json["permission"]["service_name"]
            .as_str()
            .unwrap_or("privacy resource");
        let decision = obj.json["permission"]["decision"].as_str().unwrap_or("set");
        let client = obj.json["client"]["id"].as_str().unwrap_or("unknown app");
        let description = Some(format!("{client}: {service} {decision}"));

        vec![TimelineEvent {
            ts_unix_ms,
            event_type: "mobile.config.privacy_permission",
            description,
            actor: Some(client.to_owned()),
        }]
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = SqliteEvidence::from_input(input, "TCC.db")?;
        let conn = SqliteConnection::open(evidence.path())?;
        let schema = conn.schema()?;
        validate_schema(&schema)?;

        emit_access(&conn, &schema, &evidence, sink)
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    if !schema.has_table("access") {
        bail!("not a supported iOS TCC.db: missing access table");
    }
    let missing = schema.missing_columns("access", &["service", "client"]);
    if !missing.is_empty() {
        bail!(
            "not a supported iOS TCC.db: missing required columns: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

fn emit_access(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    // TCC has no stable single-column primary key across iOS versions; the
    // (service, client) pair identifies a grant, so use rowid for provenance.
    let sql = format!(
        r#"
        SELECT
            a.rowid AS access_rowid,
            a.service AS service,
            a.client AS client,
            {},
            {},
            {},
            {},
            {}
        FROM access a
        ORDER BY a.service, a.client;
        "#,
        select_column(schema, "access", "a", "client_type", "client_type"),
        select_column(schema, "access", "a", "auth_value", "auth_value"),
        select_column(schema, "access", "a", "auth_reason", "auth_reason"),
        select_column(schema, "access", "a", "last_modified", "last_modified"),
        select_column(
            schema,
            "access",
            "a",
            "indirect_object_identifier",
            "indirect_object_identifier"
        ),
    );

    conn.query_rows(&sql, |row| {
        let access_rowid = row.i64(0).context("access row missing rowid")?;
        let service = row.text(1);
        let client = row.text(2);
        let client_type = row.i64(3);
        let auth_value = row.i64(4);

        let text = format!(
            "{} -> {}",
            client.as_deref().unwrap_or("?"),
            service.as_deref().unwrap_or("?")
        );
        let json = json!({
            "platform": "ios",
            "app": "tcc",
            "record_type": "privacy_permission",
            "source": source_json(evidence, access_rowid),
            "timestamps": {
                "last_modified": unix_seconds_to_json(row.i64(6)),
            },
            "client": {
                "id": client,
                "type_code": client_type,
                "type": client_type_label(client_type),
            },
            "permission": {
                "service": service,
                "service_name": service.as_deref().map(friendly_service),
                "auth_value_code": auth_value,
                "decision": auth_value_label(auth_value),
                "auth_reason_code": row.i64(5),
                "indirect_object": non_empty(row.text(7)),
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "mobile.config.privacy_permission",
            text,
            json,
        })
    })
}

/// TCC `auth_value` semantics (iOS 14+/macOS 11+ four-state model).
fn auth_value_label(auth_value: Option<i64>) -> &'static str {
    match auth_value {
        Some(0) => "denied",
        Some(1) => "unknown",
        Some(2) => "allowed",
        Some(3) => "limited",
        _ => "unspecified",
    }
}

fn client_type_label(client_type: Option<i64>) -> &'static str {
    match client_type {
        Some(0) => "bundle_id",
        Some(1) => "absolute_path",
        _ => "unknown",
    }
}

/// Strip the `kTCCService` prefix to a readable resource name, e.g.
/// `kTCCServiceCamera` -> `Camera`.
fn friendly_service(service: &str) -> String {
    service
        .strip_prefix("kTCCService")
        .unwrap_or(service)
        .to_string()
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
        "table": "access",
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
    use super::IosTccParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::formats::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_tcc() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("TCC.db");

        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE access (
                    service TEXT,
                    client TEXT,
                    client_type INTEGER,
                    auth_value INTEGER,
                    auth_reason INTEGER,
                    last_modified INTEGER,
                    indirect_object_identifier TEXT
                );

                INSERT INTO access (service, client, client_type, auth_value, auth_reason, last_modified)
                VALUES ('kTCCServiceCamera', 'com.example.app', 0, 2, 4, 978307200);

                INSERT INTO access (service, client, client_type, auth_value, auth_reason, last_modified)
                VALUES ('kTCCServiceMicrophone', 'com.example.app', 0, 0, 4, 978307200);
                "#,
            )?;
        }

        let parser = IosTccParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 2);
        let camera = &objects[0];
        assert_eq!(camera.kind, "mobile.config.privacy_permission");
        assert_eq!(camera.json["permission"]["service_name"], "Camera");
        assert_eq!(camera.json["permission"]["decision"], "allowed");
        assert_eq!(camera.json["client"]["type"], "bundle_id");
        assert_eq!(
            camera.json["timestamps"]["last_modified"]["rfc3339"],
            "2001-01-01T00:00:00+00:00"
        );
        assert_eq!(
            camera.json["timestamps"]["last_modified"]["original_epoch"],
            "unix_seconds"
        );

        assert_eq!(objects[1].json["permission"]["decision"], "denied");

        let events = parser.extract_timeline_events(camera);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].description.as_deref(),
            Some("com.example.app: Camera allowed")
        );

        Ok(())
    }
}
