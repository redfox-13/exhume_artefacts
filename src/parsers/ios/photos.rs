use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::formats::sqlite::{SqliteConnection, SqliteEvidence, SqliteSchema, select_column};
use crate::formats::timestamps::apple_absolute_to_json;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

const PARSER_NAME: &str = "mobile_ios_photos";
const SCHEMA_VARIANT: &str = "ios_photos_zasset_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

#[derive(Default)]
pub struct IosPhotosParser;

impl Parser for IosPhotosParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse Apple Photos.sqlite asset inventory (ZASSET): filenames, capture dates, GPS and flags."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        if obj.kind != "mobile.media.asset" {
            return Vec::new();
        }
        // Prefer capture date; fall back to date added to the library.
        let ts_unix_ms = obj.json["timestamps"]["created"]["unix_ms"]
            .as_i64()
            .or_else(|| obj.json["timestamps"]["added"]["unix_ms"].as_i64());
        let Some(ts_unix_ms) = ts_unix_ms else {
            return Vec::new();
        };
        let description = obj.json["asset"]["filename"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(|f| format!("media: {f}"));
        vec![TimelineEvent {
            ts_unix_ms,
            event_type: "mobile.media.asset",
            description,
            actor: None,
        }]
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = SqliteEvidence::from_input(input, "Photos.sqlite")?;
        let conn = SqliteConnection::open(evidence.path())?;
        let schema = conn.schema()?;
        validate_schema(&schema)?;

        emit_assets(&conn, &schema, &evidence, sink)
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    if !schema.has_table("ZASSET") {
        bail!("not a supported iOS Photos.sqlite: missing ZASSET table");
    }
    let missing = schema.missing_columns("ZASSET", &["Z_PK", "ZDATECREATED"]);
    if !missing.is_empty() {
        bail!(
            "not a supported iOS Photos.sqlite: missing required columns: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

fn emit_assets(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let sql = format!(
        r#"
        SELECT
            a.Z_PK AS asset_pk,
            a.ZDATECREATED AS date_created,
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {}
        FROM ZASSET a
        ORDER BY a.ZDATECREATED, a.Z_PK;
        "#,
        select_column(schema, "ZASSET", "a", "ZFILENAME", "filename"),
        select_column(schema, "ZASSET", "a", "ZDIRECTORY", "directory"),
        select_column(schema, "ZASSET", "a", "ZADDEDDATE", "added_date"),
        select_column(
            schema,
            "ZASSET",
            "a",
            "ZMODIFICATIONDATE",
            "modification_date"
        ),
        select_column(schema, "ZASSET", "a", "ZTRASHEDDATE", "trashed_date"),
        select_column(schema, "ZASSET", "a", "ZLATITUDE", "latitude"),
        select_column(schema, "ZASSET", "a", "ZLONGITUDE", "longitude"),
        select_column(schema, "ZASSET", "a", "ZWIDTH", "width"),
        select_column(schema, "ZASSET", "a", "ZHEIGHT", "height"),
        select_column(schema, "ZASSET", "a", "ZDURATION", "duration"),
        select_column(schema, "ZASSET", "a", "ZKIND", "kind_code"),
        select_column(schema, "ZASSET", "a", "ZFAVORITE", "favorite"),
        select_column(schema, "ZASSET", "a", "ZHIDDEN", "hidden"),
        select_column(schema, "ZASSET", "a", "ZTRASHEDSTATE", "trashed_state"),
    );

    conn.query_rows(&sql, |row| {
        let asset_pk = row.i64(0).context("asset row missing Z_PK")?;
        let filename = non_empty(row.text(2));
        let directory = non_empty(row.text(3));
        let kind_code = row.i64(12);

        let relative_path = match (&directory, &filename) {
            (Some(dir), Some(name)) => Some(format!("{dir}/{name}")),
            _ => None,
        };
        let text = filename.clone().unwrap_or_default();
        let json = json!({
            "platform": "ios",
            "app": "photos",
            "record_type": "asset",
            "source": source_json(evidence, asset_pk),
            "timestamps": {
                "created": apple_absolute_to_json(row.f64(1)),
                "added": apple_absolute_to_json(row.f64(4)),
                "modified": apple_absolute_to_json(row.f64(5)),
                "trashed": apple_absolute_to_json(row.f64(6)),
            },
            "asset": {
                "pk": asset_pk,
                "filename": filename,
                "directory": directory,
                "relative_path": relative_path,
                "kind_code": kind_code,
                "kind": media_kind(kind_code),
                "width": row.i64(9),
                "height": row.i64(10),
                "duration_seconds": non_zero(row.f64(11)),
                "favorite": row.bool(13),
                "hidden": row.bool(14),
                "trashed": row.bool(15),
            },
            "location": {
                "latitude": valid_coord(row.f64(7)),
                "longitude": valid_coord(row.f64(8)),
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "mobile.media.asset",
            text,
            json,
        })
    })
}

/// Photos `ZKIND`: 0 = image (photo), 1 = video.
fn media_kind(kind_code: Option<i64>) -> &'static str {
    match kind_code {
        Some(0) => "image",
        Some(1) => "video",
        _ => "unknown",
    }
}

/// Photos stores -180.0 in ZLATITUDE/ZLONGITUDE when no location is known.
fn valid_coord(value: Option<f64>) -> Option<f64> {
    value.filter(|v| v.is_finite() && *v > -180.0)
}

fn non_zero(value: Option<f64>) -> Option<f64> {
    value.filter(|v| *v != 0.0)
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
        "table": "ZASSET",
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
    use super::IosPhotosParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::formats::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_photos() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("Photos.sqlite");

        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE ZASSET (
                    Z_PK INTEGER PRIMARY KEY,
                    ZKIND INTEGER,
                    ZWIDTH INTEGER,
                    ZHEIGHT INTEGER,
                    ZFAVORITE INTEGER,
                    ZHIDDEN INTEGER,
                    ZTRASHEDSTATE INTEGER,
                    ZDATECREATED FLOAT,
                    ZADDEDDATE FLOAT,
                    ZMODIFICATIONDATE FLOAT,
                    ZTRASHEDDATE FLOAT,
                    ZDURATION FLOAT,
                    ZLATITUDE FLOAT,
                    ZLONGITUDE FLOAT,
                    ZDIRECTORY TEXT,
                    ZFILENAME TEXT
                );

                INSERT INTO ZASSET
                    (Z_PK, ZKIND, ZWIDTH, ZHEIGHT, ZFAVORITE, ZHIDDEN, ZTRASHEDSTATE, ZDATECREATED, ZADDEDDATE, ZDURATION, ZLATITUDE, ZLONGITUDE, ZDIRECTORY, ZFILENAME)
                VALUES
                    (1, 0, 4032, 3024, 1, 0, 0, 0.0, 1.0, 0.0, 48.8566, 2.3522, 'DCIM/100APPLE', 'IMG_0001.HEIC');

                INSERT INTO ZASSET
                    (Z_PK, ZKIND, ZWIDTH, ZHEIGHT, ZFAVORITE, ZHIDDEN, ZTRASHEDSTATE, ZDATECREATED, ZADDEDDATE, ZDURATION, ZLATITUDE, ZLONGITUDE, ZDIRECTORY, ZFILENAME)
                VALUES
                    (2, 1, 1920, 1080, 0, 0, 0, 5.0, 6.0, 12.5, -180.0, -180.0, 'DCIM/100APPLE', 'IMG_0002.MOV');
                "#,
            )?;
        }

        let parser = IosPhotosParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 2);
        let photo = &objects[0];
        assert_eq!(photo.kind, "mobile.media.asset");
        assert_eq!(photo.json["asset"]["kind"], "image");
        assert_eq!(photo.json["asset"]["filename"], "IMG_0001.HEIC");
        assert_eq!(
            photo.json["asset"]["relative_path"],
            "DCIM/100APPLE/IMG_0001.HEIC"
        );
        assert_eq!(photo.json["asset"]["favorite"], true);
        assert_eq!(photo.json["location"]["latitude"], 48.8566);
        assert_eq!(
            photo.json["timestamps"]["created"]["rfc3339"],
            "2001-01-01T00:00:00+00:00"
        );

        // Video with sentinel -180 coords -> null location, duration kept.
        let video = &objects[1];
        assert_eq!(video.json["asset"]["kind"], "video");
        assert_eq!(video.json["asset"]["duration_seconds"], 12.5);
        assert!(video.json["location"]["latitude"].is_null());
        assert!(video.json["location"]["longitude"].is_null());

        let events = parser.extract_timeline_events(photo);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].description.as_deref(),
            Some("media: IMG_0001.HEIC")
        );

        Ok(())
    }
}
