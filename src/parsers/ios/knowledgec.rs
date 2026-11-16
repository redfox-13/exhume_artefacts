use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::formats::sqlite::{SqliteConnection, SqliteEvidence, SqliteSchema, select_column};
use crate::formats::timestamps::apple_absolute_to_json;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

const PARSER_NAME: &str = "mobile_ios_knowledgec";
const SCHEMA_VARIANT: &str = "ios_knowledgec_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

#[derive(Default)]
pub struct IosKnowledgeCParser;

impl Parser for IosKnowledgeCParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse CoreDuet knowledgeC.db behavioural events (app usage, web usage, device lock, backlight, notifications)."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        if obj.kind != "mobile.usage.event" {
            return Vec::new();
        }
        let Some(ts_unix_ms) = obj.json["timestamps"]["start"]["unix_ms"].as_i64() else {
            return Vec::new();
        };
        vec![TimelineEvent {
            ts_unix_ms,
            event_type: "mobile.usage.event",
            description: obj.json["summary"].as_str().map(str::to_owned),
            actor: obj.json["event"]["bundle_id"].as_str().map(str::to_owned),
        }]
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = SqliteEvidence::from_input(input, "knowledgeC.db")?;
        let conn = SqliteConnection::open(evidence.path())?;
        let schema = conn.schema()?;
        validate_schema(&schema)?;

        emit_objects(&conn, &schema, &evidence, sink)
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    if !schema.has_table("ZOBJECT") {
        bail!("not a supported iOS knowledgeC.db: missing ZOBJECT table");
    }
    let missing = schema.missing_columns("ZOBJECT", &["Z_PK", "ZSTREAMNAME", "ZSTARTDATE"]);
    if !missing.is_empty() {
        bail!(
            "not a supported iOS knowledgeC.db: missing required columns: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

fn emit_objects(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let has_source_join = schema.has_table("ZSOURCE")
        && schema.has_column("ZSOURCE", "ZBUNDLEID")
        && schema.has_column("ZOBJECT", "ZSOURCE");
    let source_bundle = if has_source_join {
        "src.ZBUNDLEID AS source_bundle_id"
    } else {
        "NULL AS source_bundle_id"
    };
    let source_join = if has_source_join {
        "LEFT JOIN ZSOURCE src ON src.Z_PK = o.ZSOURCE"
    } else {
        ""
    };

    let sql = format!(
        r#"
        SELECT
            o.Z_PK AS object_pk,
            o.ZSTREAMNAME AS stream_name,
            o.ZSTARTDATE AS start_date,
            {},
            {},
            {},
            {},
            {},
            {},
            {source_bundle}
        FROM ZOBJECT o
        {source_join}
        ORDER BY o.ZSTARTDATE, o.Z_PK;
        "#,
        select_column(schema, "ZOBJECT", "o", "ZENDDATE", "end_date"),
        select_column(schema, "ZOBJECT", "o", "ZCREATIONDATE", "creation_date"),
        select_column(schema, "ZOBJECT", "o", "ZVALUESTRING", "value_string"),
        select_column(schema, "ZOBJECT", "o", "ZVALUEINTEGER", "value_integer"),
        select_column(schema, "ZOBJECT", "o", "ZINTEGERVALUE", "integer_value"),
        select_column(schema, "ZOBJECT", "o", "ZVALUEDOUBLE", "value_double"),
    );

    conn.query_rows(&sql, |row| {
        let object_pk = row.i64(0).context("ZOBJECT row missing Z_PK")?;
        let stream = row.text(1).unwrap_or_default();
        let start = row.f64(2);
        let end = row.f64(3);
        let value_string = non_empty(row.text(5));
        // Boolean/state streams populate one of two integer columns.
        let value_int = row.i64(6).or_else(|| row.i64(7));
        let source_bundle = non_empty(row.text(9));

        let bundle_id =
            bundle_for_stream(&stream, value_string.as_deref(), source_bundle.as_deref());
        let duration_seconds = duration_seconds(start, end);
        let summary = summarize(
            &stream,
            value_string.as_deref(),
            value_int,
            duration_seconds,
        );

        let json = json!({
            "platform": "ios",
            "app": "knowledgec",
            "record_type": "usage_event",
            "source": source_json(evidence, object_pk),
            "summary": summary,
            "timestamps": {
                "start": apple_absolute_to_json(start),
                "end": apple_absolute_to_json(end),
                "creation": apple_absolute_to_json(row.f64(4)),
            },
            "event": {
                "pk": object_pk,
                "stream": stream,
                "family": stream_family(&stream),
                "bundle_id": bundle_id,
                "value_string": value_string,
                "value_int": value_int,
                "value_double": row.f64(8),
                "source_bundle_id": source_bundle,
                "duration_seconds": duration_seconds,
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "mobile.usage.event",
            text: summary_text(&json),
            json,
        })
    })
}

fn summary_text(json: &Value) -> String {
    json["summary"].as_str().unwrap_or_default().to_string()
}

/// Coarse grouping of the leading path segment of a knowledgeC stream name.
fn stream_family(stream: &str) -> &'static str {
    match stream.split('/').nth(1) {
        Some("app") => "app",
        Some("display") => "display",
        Some("device") => "device",
        Some("media") => "media",
        Some("notification") => "notification",
        Some("event") => "event",
        Some("discoverability") => "discoverability",
        Some("portrait") => "portrait",
        _ => "other",
    }
}

/// For app/web streams the bundle id lives in ZVALUESTRING; otherwise fall back
/// to the joined ZSOURCE bundle id.
fn bundle_for_stream(
    stream: &str,
    value_string: Option<&str>,
    source_bundle: Option<&str>,
) -> Option<String> {
    if stream.starts_with("/app/") || stream == "/media/nowPlaying" {
        value_string
            .map(str::to_owned)
            .or_else(|| source_bundle.map(str::to_owned))
    } else {
        source_bundle.map(str::to_owned)
    }
}

fn duration_seconds(start: Option<f64>, end: Option<f64>) -> Option<f64> {
    match (start, end) {
        (Some(start), Some(end)) if end >= start => Some(end - start),
        _ => None,
    }
}

/// Build a human timeline summary tailored to the well-known streams.
fn summarize(
    stream: &str,
    value_string: Option<&str>,
    value_int: Option<i64>,
    duration_seconds: Option<f64>,
) -> String {
    let dur = duration_seconds
        .map(|d| format!(" ({}s)", d.round() as i64))
        .unwrap_or_default();
    match stream {
        "/app/usage" => format!("app usage: {}{dur}", value_string.unwrap_or("unknown app")),
        "/app/webUsage" => format!("web usage: {}{dur}", value_string.unwrap_or("unknown app")),
        "/app/inFocus" => format!(
            "app in focus: {}{dur}",
            value_string.unwrap_or("unknown app")
        ),
        "/app/activity" => format!(
            "app activity: {}{dur}",
            value_string.unwrap_or("unknown app")
        ),
        "/display/isBacklit" => {
            format!("display backlit: {}{dur}", on_off(value_int))
        }
        "/device/isLocked" => format!("device: {}{dur}", locked_state(value_int)),
        "/media/nowPlaying" => {
            format!(
                "media now playing: {}{dur}",
                value_string.unwrap_or("unknown")
            )
        }
        "/notification/usage" => {
            format!(
                "notification: {}{dur}",
                value_string.unwrap_or("unknown app")
            )
        }
        other => {
            let value = value_string
                .map(str::to_owned)
                .or_else(|| value_int.map(|v| v.to_string()))
                .unwrap_or_default();
            if value.is_empty() {
                format!("{other}{dur}")
            } else {
                format!("{other}: {value}{dur}")
            }
        }
    }
}

fn on_off(value_int: Option<i64>) -> &'static str {
    match value_int {
        Some(0) => "off",
        Some(_) => "on",
        None => "unknown",
    }
}

fn locked_state(value_int: Option<i64>) -> &'static str {
    match value_int {
        Some(0) => "unlocked",
        Some(_) => "locked",
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
        "table": "ZOBJECT",
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
    use super::IosKnowledgeCParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::formats::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_knowledgec() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("knowledgeC.db");

        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE ZSOURCE (
                    Z_PK INTEGER PRIMARY KEY,
                    ZBUNDLEID TEXT
                );

                CREATE TABLE ZOBJECT (
                    Z_PK INTEGER PRIMARY KEY,
                    ZSTREAMNAME TEXT,
                    ZSOURCE INTEGER,
                    ZVALUESTRING TEXT,
                    ZVALUEINTEGER INTEGER,
                    ZINTEGERVALUE INTEGER,
                    ZVALUEDOUBLE REAL,
                    ZSTARTDATE REAL,
                    ZENDDATE REAL,
                    ZCREATIONDATE REAL
                );

                INSERT INTO ZSOURCE (Z_PK, ZBUNDLEID) VALUES (1, 'com.apple.springboard');

                INSERT INTO ZOBJECT (Z_PK, ZSTREAMNAME, ZSOURCE, ZVALUESTRING, ZSTARTDATE, ZENDDATE, ZCREATIONDATE)
                VALUES (1, '/app/usage', 1, 'com.apple.Fitness', 0.0, 60.0, 61.0);

                INSERT INTO ZOBJECT (Z_PK, ZSTREAMNAME, ZSOURCE, ZVALUEINTEGER, ZSTARTDATE, ZENDDATE)
                VALUES (2, '/display/isBacklit', 1, 0, 100.0, 104.0);

                INSERT INTO ZOBJECT (Z_PK, ZSTREAMNAME, ZSOURCE, ZVALUEINTEGER, ZSTARTDATE)
                VALUES (3, '/device/isLocked', 1, 1, 200.0);
                "#,
            )?;
        }

        let parser = IosKnowledgeCParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 3);

        let usage = &objects[0];
        assert_eq!(usage.kind, "mobile.usage.event");
        assert_eq!(usage.json["event"]["family"], "app");
        assert_eq!(usage.json["event"]["bundle_id"], "com.apple.Fitness");
        assert_eq!(usage.json["event"]["duration_seconds"], 60.0);
        assert_eq!(usage.json["summary"], "app usage: com.apple.Fitness (60s)");
        assert_eq!(
            usage.json["timestamps"]["start"]["rfc3339"],
            "2001-01-01T00:00:00+00:00"
        );

        assert_eq!(objects[1].json["summary"], "display backlit: off (4s)");
        assert_eq!(objects[2].json["summary"], "device: locked");

        let events = parser.extract_timeline_events(usage);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "mobile.usage.event");
        assert_eq!(events[0].actor.as_deref(), Some("com.apple.Fitness"));

        Ok(())
    }
}
