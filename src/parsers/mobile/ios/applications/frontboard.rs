use super::FRONTBOARD_STATE_KIND;
use super::support::{plist_to_json, sqlite_source_json};
use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput};
use crate::parsers::mobile::sqlite::{SqliteConnection, SqliteEvidence, SqliteSchema};
use anyhow::{Context, Result, bail};
use plist::Value as Plist;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::io::Cursor;

const PARSER_NAME: &str = "mobile_ios_frontboard";
const SCHEMA_VARIANT: &str = "ios_frontboard_application_state_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

#[derive(Default)]
pub struct IosFrontboardParser;

impl Parser for IosFrontboardParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse iOS FrontBoard applicationState.db runtime application observations."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = SqliteEvidence::from_input(input, "applicationState.db")?;
        let conn = SqliteConnection::open(evidence.path())?;
        let schema = conn.schema()?;
        validate_schema(&schema)?;

        emit_states(&conn, &evidence, sink)
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    for (table, columns) in [
        (
            "application_identifier_tab",
            &["id", "application_identifier"][..],
        ),
        ("key_tab", &["id", "key"][..]),
        ("kvs", &["id", "application_identifier", "key", "value"][..]),
    ] {
        if !schema.has_table(table) {
            bail!("not a supported FrontBoard applicationState.db: missing {table} table");
        }
        let missing = schema.missing_columns(table, columns);
        if !missing.is_empty() {
            bail!(
                "not a supported FrontBoard applicationState.db: missing required columns: {}",
                missing.join(", ")
            );
        }
    }
    Ok(())
}

#[derive(Default)]
struct StateAccumulator {
    record_id: i64,
    bundle_id: String,
    rowids: Vec<i64>,
    values: Map<String, Value>,
    bundle_path: Option<String>,
    bundle_container_path: Option<String>,
    data_container_path: Option<String>,
}

fn emit_states(
    conn: &SqliteConnection,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let mut applications = BTreeMap::<i64, StateAccumulator>::new();
    conn.query_rows(
        r#"
        SELECT
            a.id,
            a.application_identifier,
            v.id,
            k.key,
            typeof(v.value),
            v.value
        FROM application_identifier_tab a
        LEFT JOIN kvs v ON v.application_identifier = a.id
        LEFT JOIN key_tab k ON k.id = v.key
        ORDER BY a.id, v.id;
        "#,
        |row| {
            let record_id = row
                .i64(0)
                .context("FrontBoard application identifier missing id")?;
            let bundle_id = row
                .text(1)
                .context("FrontBoard application identifier missing value")?;
            let application = applications
                .entry(record_id)
                .or_insert_with(|| StateAccumulator {
                    record_id,
                    bundle_id,
                    ..StateAccumulator::default()
                });

            let (Some(rowid), Some(key), Some(storage_type)) =
                (row.i64(2), row.text(3), row.text(4))
            else {
                return Ok(());
            };
            application.rowids.push(rowid);
            let decoded = decode_sqlite_value(row, 5, &storage_type);
            if key == "compatibilityInfo" {
                let paths = extract_paths_from_sqlite_value(row, 5, &storage_type);
                application.bundle_path = paths.bundle_path;
                application.bundle_container_path = paths.bundle_container_path;
                application.data_container_path = paths.data_container_path;
            }
            application.values.insert(key, decoded);
            Ok(())
        },
    )?;

    for application in applications.into_values() {
        let scenes = object_or_array_len(application.values.get("_SBScenes"));
        let shortcuts = object_or_array_len(application.values.get("SBApplicationShortcutItems"));
        let recently_updated = application
            .values
            .get("SBApplicationRecentlyUpdated")
            .and_then(Value::as_i64)
            .map(|value| value != 0);
        let badge = application
            .values
            .get("SBApplicationBadgeKey")
            .and_then(Value::as_i64);
        let observation_key = format!(
            "ios-frontboard:{}:{}",
            application.record_id, application.bundle_id
        );
        let json = json!({
            "schema": "ios.application_frontboard_state.v1",
            "platform": "ios",
            "record_type": "frontboard_state",
            "observation_key": observation_key,
            "presence": {
                "frontboard_registered": true,
                "application_presence_authority": false,
            },
            "identity": {
                "bundle_id": application.bundle_id,
            },
            "paths": {
                "bundle": application.bundle_path,
                "bundle_container": application.bundle_container_path,
                "data_container": application.data_container_path,
            },
            "state": {
                "recently_updated": recently_updated,
                "badge": badge,
                "scene_count": scenes,
                "shortcut_item_count": shortcuts,
            },
            "timestamps": {},
            "source": sqlite_source_json(
                evidence,
                "application_identifier",
                application.record_id,
                &application.rowids,
                SCHEMA_VARIANT,
            ),
            "raw_values": application.values,
        });
        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: FRONTBOARD_STATE_KIND,
            text: json["identity"]["bundle_id"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            json,
        })?;
    }
    Ok(())
}

fn decode_sqlite_value(
    row: &crate::parsers::mobile::sqlite::SqliteStatement<'_>,
    index: i32,
    storage_type: &str,
) -> Value {
    match storage_type {
        "integer" => row.i64(index).map_or(Value::Null, |value| json!(value)),
        "real" => row.f64(index).map_or(Value::Null, |value| json!(value)),
        "text" => row.text(index).map_or(Value::Null, Value::String),
        "blob" => row
            .blob(index)
            .map(|bytes| decode_plist_blob(&bytes).0)
            .unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

fn decode_plist_blob(bytes: &[u8]) -> (Value, Option<Plist>) {
    let Ok(first) = Plist::from_reader(Cursor::new(bytes)) else {
        return (
            json!({
                "encoding": "hex",
                "length": bytes.len(),
                "data": hex::encode(&bytes[..bytes.len().min(4096)]),
                "truncated": bytes.len() > 4096,
            }),
            None,
        );
    };
    let selected = match &first {
        Plist::Data(nested) if nested.starts_with(b"bplist00") || nested.starts_with(b"<?xml") => {
            Plist::from_reader(Cursor::new(nested)).unwrap_or(first)
        }
        _ => first,
    };
    (plist_to_json(&selected), Some(selected))
}

#[derive(Default)]
struct CompatibilityPaths {
    bundle_path: Option<String>,
    bundle_container_path: Option<String>,
    data_container_path: Option<String>,
}

fn extract_paths_from_sqlite_value(
    row: &crate::parsers::mobile::sqlite::SqliteStatement<'_>,
    index: i32,
    storage_type: &str,
) -> CompatibilityPaths {
    if storage_type != "blob" {
        return CompatibilityPaths::default();
    }
    let Some(bytes) = row.blob(index) else {
        return CompatibilityPaths::default();
    };
    let (_, parsed) = decode_plist_blob(&bytes);
    let Some(parsed) = parsed else {
        return CompatibilityPaths::default();
    };
    let mut strings = Vec::new();
    collect_strings(&parsed, &mut strings, 0);

    let bundle_path = strings
        .iter()
        .find(|value| value.contains("/Bundle/Application/") && value.ends_with(".app"))
        .cloned();
    let data_container_path = strings
        .iter()
        .find(|value| value.contains("/Containers/Data/Application/"))
        .cloned();
    let bundle_container_path = strings
        .iter()
        .filter(|value| value.contains("/Bundle/Application/") && !value.ends_with(".app"))
        .min_by_key(|value| value.matches('/').count())
        .cloned();
    CompatibilityPaths {
        bundle_path,
        bundle_container_path,
        data_container_path,
    }
}

fn collect_strings(value: &Plist, output: &mut Vec<String>, depth: usize) {
    if depth > 12 {
        return;
    }
    match value {
        Plist::String(value) if value != "$null" => output.push(value.clone()),
        Plist::Array(values) => {
            for value in values {
                collect_strings(value, output, depth + 1);
            }
        }
        Plist::Dictionary(values) => {
            for value in values.values() {
                collect_strings(value, output, depth + 1);
            }
        }
        Plist::Data(bytes) if bytes.starts_with(b"bplist00") || bytes.starts_with(b"<?xml") => {
            if let Ok(nested) = Plist::from_reader(Cursor::new(bytes)) {
                collect_strings(&nested, output, depth + 1);
            }
        }
        _ => {}
    }
}

fn object_or_array_len(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Array(values)) => u64::try_from(values.len()).ok(),
        Some(Value::Object(values)) => u64::try_from(values.len()).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::IosFrontboardParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::parsers::mobile::sqlite::SqliteConnection;
    use anyhow::Result;
    use plist::{Dictionary, Value};

    #[test]
    fn parses_synthetic_frontboard_and_nested_compatibility_archive() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let path = tempdir.path().join("applicationState.db");
        let nested = compatibility_archive()?;
        let mut outer = Vec::new();
        plist::to_writer_binary(&mut outer, &Value::Data(nested))?;
        let encoded = hex::encode(outer);
        {
            let conn = SqliteConnection::create_for_test(&path)?;
            conn.execute_batch(&format!(
                r#"
                CREATE TABLE application_identifier_tab (
                    id INTEGER PRIMARY KEY,
                    application_identifier TEXT NOT NULL UNIQUE
                );
                CREATE TABLE key_tab (id INTEGER PRIMARY KEY, key TEXT NOT NULL UNIQUE);
                CREATE TABLE kvs (
                    id INTEGER PRIMARY KEY,
                    application_identifier INTEGER,
                    key INTEGER,
                    value BLOB
                );
                INSERT INTO application_identifier_tab VALUES (1, 'net.example.Forensic');
                INSERT INTO key_tab VALUES (1, 'compatibilityInfo');
                INSERT INTO key_tab VALUES (2, 'SBApplicationRecentlyUpdated');
                INSERT INTO kvs VALUES (10, 1, 1, X'{encoded}');
                INSERT INTO kvs VALUES (11, 1, 2, 0);
                "#
            ))?;
        }

        let mut objects = Vec::new();
        IosFrontboardParser.run_into(ParserInput::Path(path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 1);
        let object = &objects[0];
        assert_eq!(object.kind, "mobile.application.frontboard_state");
        assert_eq!(object.json["identity"]["bundle_id"], "net.example.Forensic");
        assert_eq!(object.json["state"]["recently_updated"], false);
        assert_eq!(
            object.json["paths"]["data_container"],
            "/private/var/mobile/Containers/Data/Application/DATA-UUID"
        );
        assert_eq!(object.json["source"]["rowids"], serde_json::json!([10, 11]));
        assert_eq!(
            object.json["presence"]["application_presence_authority"],
            false
        );
        Ok(())
    }

    #[test]
    fn declares_frontboard_wal_and_shm_companions() {
        let specs = IosFrontboardParser.companion_specs();
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].role, "sqlite_wal");
        assert_eq!(specs[1].role, "sqlite_shm");
    }

    fn compatibility_archive() -> Result<Vec<u8>> {
        let mut root = Dictionary::new();
        root.insert(
            "$objects".into(),
            Value::Array(vec![
                Value::String("$null".into()),
                Value::String("net.example.Forensic".into()),
                Value::String(
                    "/private/var/containers/Bundle/Application/BUNDLE-UUID/Forensic.app".into(),
                ),
                Value::String("/private/var/mobile/Containers/Data/Application/DATA-UUID".into()),
                Value::String("/private/var/containers/Bundle/Application/BUNDLE-UUID".into()),
            ]),
        );
        let mut bytes = Vec::new();
        plist::to_writer_binary(&mut bytes, &Value::Dictionary(root))?;
        Ok(bytes)
    }
}
