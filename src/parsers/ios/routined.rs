use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::formats::sqlite::{SqliteConnection, SqliteEvidence, SqliteSchema, select_column};
use crate::formats::timestamps::apple_absolute_to_json;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

const PARSER_NAME: &str = "mobile_ios_routined";
const SCHEMA_VARIANT: &str = "ios_routined_cache_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

#[derive(Default)]
pub struct IosRoutinedParser;

impl Parser for IosRoutinedParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse Apple routined Cache.sqlite significant-location GPS fixes (ZRTCLLOCATIONMO)."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        if obj.kind != "mobile.location.fix" {
            return Vec::new();
        }
        let Some(ts_unix_ms) = obj.json["timestamps"]["fix"]["unix_ms"].as_i64() else {
            return Vec::new();
        };
        let description = match (
            obj.json["location"]["latitude"].as_f64(),
            obj.json["location"]["longitude"].as_f64(),
        ) {
            (Some(lat), Some(lon)) => Some(format!("location fix {lat:.5}, {lon:.5}")),
            _ => Some("location fix".to_string()),
        };
        vec![TimelineEvent {
            ts_unix_ms,
            event_type: "mobile.location.fix",
            description,
            actor: None,
        }]
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = SqliteEvidence::from_input(input, "Cache.sqlite")?;
        let conn = SqliteConnection::open(evidence.path())?;
        let schema = conn.schema()?;
        validate_schema(&schema)?;

        emit_fixes(&conn, &schema, &evidence, sink)
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    if !schema.has_table("ZRTCLLOCATIONMO") {
        bail!("not a supported iOS routined Cache.sqlite: missing ZRTCLLOCATIONMO table");
    }
    let missing = schema.missing_columns(
        "ZRTCLLOCATIONMO",
        &["Z_PK", "ZTIMESTAMP", "ZLATITUDE", "ZLONGITUDE"],
    );
    if !missing.is_empty() {
        bail!(
            "not a supported iOS routined Cache.sqlite: missing required columns: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

fn emit_fixes(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let sql = format!(
        r#"
        SELECT
            l.Z_PK AS fix_pk,
            l.ZTIMESTAMP AS fix_ts,
            l.ZLATITUDE AS latitude,
            l.ZLONGITUDE AS longitude,
            {},
            {},
            {},
            {},
            {},
            {}
        FROM ZRTCLLOCATIONMO l
        ORDER BY l.ZTIMESTAMP, l.Z_PK;
        "#,
        select_column(schema, "ZRTCLLOCATIONMO", "l", "ZALTITUDE", "altitude"),
        select_column(schema, "ZRTCLLOCATIONMO", "l", "ZSPEED", "speed"),
        select_column(schema, "ZRTCLLOCATIONMO", "l", "ZCOURSE", "course"),
        select_column(
            schema,
            "ZRTCLLOCATIONMO",
            "l",
            "ZHORIZONTALACCURACY",
            "horizontal_accuracy"
        ),
        select_column(
            schema,
            "ZRTCLLOCATIONMO",
            "l",
            "ZVERTICALACCURACY",
            "vertical_accuracy"
        ),
        select_column(schema, "ZRTCLLOCATIONMO", "l", "ZTYPE", "type_code"),
    );

    conn.query_rows(&sql, |row| {
        let fix_pk = row.i64(0).context("location row missing Z_PK")?;
        let horizontal_accuracy = row.f64(7);
        let json = json!({
            "platform": "ios",
            "app": "routined",
            "record_type": "location_fix",
            "source": source_json(evidence, fix_pk),
            "timestamps": {
                "fix": apple_absolute_to_json(row.f64(1)),
            },
            "location": {
                "pk": fix_pk,
                "latitude": row.f64(2),
                "longitude": row.f64(3),
                "altitude": row.f64(4),
                // CLLocation reports -1 for speed/course when unavailable.
                "speed": non_negative(row.f64(5)),
                "course": non_negative(row.f64(6)),
                "horizontal_accuracy": horizontal_accuracy,
                "vertical_accuracy": row.f64(8),
                "valid": horizontal_accuracy.map(|a| a >= 0.0),
                "type_code": row.i64(9),
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "mobile.location.fix",
            text: format!(
                "{:.5}, {:.5}",
                row.f64(2).unwrap_or_default(),
                row.f64(3).unwrap_or_default()
            ),
            json,
        })
    })
}

fn non_negative(value: Option<f64>) -> Option<f64> {
    value.filter(|v| *v >= 0.0)
}

fn source_json(evidence: &SqliteEvidence, rowid: i64) -> Value {
    json!({
        "path": evidence.source_label(),
        "table": "ZRTCLLOCATIONMO",
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
    use super::IosRoutinedParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::formats::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_routined() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("Cache.sqlite");

        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE ZRTCLLOCATIONMO (
                    Z_PK INTEGER PRIMARY KEY,
                    ZTYPE INTEGER,
                    ZALTITUDE FLOAT,
                    ZCOURSE FLOAT,
                    ZHORIZONTALACCURACY FLOAT,
                    ZLATITUDE FLOAT,
                    ZLONGITUDE FLOAT,
                    ZSPEED FLOAT,
                    ZVERTICALACCURACY FLOAT,
                    ZTIMESTAMP FLOAT
                );

                INSERT INTO ZRTCLLOCATIONMO
                    (Z_PK, ZTYPE, ZALTITUDE, ZCOURSE, ZHORIZONTALACCURACY, ZLATITUDE, ZLONGITUDE, ZSPEED, ZVERTICALACCURACY, ZTIMESTAMP)
                VALUES
                    (1, 1, 120.0, -1.0, 65.0, 50.6452, 3.1281, -1.0, 10.0, 0.0);

                INSERT INTO ZRTCLLOCATIONMO
                    (Z_PK, ZTYPE, ZALTITUDE, ZCOURSE, ZHORIZONTALACCURACY, ZLATITUDE, ZLONGITUDE, ZSPEED, ZVERTICALACCURACY, ZTIMESTAMP)
                VALUES
                    (2, 1, 100.0, 90.0, -1.0, 48.8566, 2.3522, 5.5, 8.0, 1.0);
                "#,
            )?;
        }

        let parser = IosRoutinedParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 2);
        let first = &objects[0];
        assert_eq!(first.kind, "mobile.location.fix");
        assert_eq!(first.json["location"]["latitude"], 50.6452);
        // speed -1 and course -1 become null; horizontal accuracy 65 is valid.
        assert!(first.json["location"]["speed"].is_null());
        assert!(first.json["location"]["course"].is_null());
        assert_eq!(first.json["location"]["valid"], true);
        assert_eq!(
            first.json["timestamps"]["fix"]["rfc3339"],
            "2001-01-01T00:00:00+00:00"
        );

        // Second fix: valid speed/course kept, negative accuracy -> not valid.
        assert_eq!(objects[1].json["location"]["speed"], 5.5);
        assert_eq!(objects[1].json["location"]["course"], 90.0);
        assert_eq!(objects[1].json["location"]["valid"], false);

        let events = parser.extract_timeline_events(first);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "mobile.location.fix");

        Ok(())
    }
}
