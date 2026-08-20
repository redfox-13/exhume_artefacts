//! Firefox `places.sqlite` history parser.
//!
//! Targets `moz_places` / `moz_historyvisits`. Timestamps are Firefox PRTime
//! (microseconds since 1970-01-01 UTC). Emits `macos.browser.site` and
//! `macos.browser.visit`.

use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::parsers::macos::common::timestamps::firefox_prtime_to_json;
use crate::parsers::macos::common::util::{host_from_url, non_empty, sqlite_source_json};
use crate::parsers::mobile::sqlite::{
    SqliteConnection, SqliteEvidence, SqliteSchema, select_column,
};
use anyhow::{Context, Result, bail};
use serde_json::json;

const PARSER_NAME: &str = "macos_firefox";
const SCHEMA_VARIANT: &str = "firefox_places_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

#[derive(Default)]
pub struct MacosFirefoxParser;

impl Parser for MacosFirefoxParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse Firefox places.sqlite browsing sites and individual visit records."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        if obj.kind != "macos.browser.visit" {
            return Vec::new();
        }
        let Some(ts_unix_ms) = obj.json["timestamps"]["visit"]["unix_ms"].as_i64() else {
            return Vec::new();
        };
        let description = obj.json["site"]["title"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .or_else(|| obj.json["site"]["url"].as_str().map(str::to_owned));
        vec![TimelineEvent {
            ts_unix_ms,
            event_type: "macos.browser.visit",
            description,
            actor: None,
        }]
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = SqliteEvidence::from_input(input, "places.sqlite")?;
        let conn = SqliteConnection::open(evidence.path())?;
        let schema = conn.schema()?;
        validate_schema(&schema)?;

        emit_sites(&conn, &schema, &evidence, sink)?;
        emit_visits(&conn, &schema, &evidence, sink)?;

        Ok(())
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    for table in ["moz_places", "moz_historyvisits"] {
        if !schema.has_table(table) {
            bail!("not a supported Firefox places.sqlite: missing {table} table");
        }
    }
    let missing = schema.missing_columns("moz_historyvisits", &["id", "place_id", "visit_date"]);
    if !missing.is_empty() {
        bail!(
            "not a supported Firefox places.sqlite: missing required columns: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

fn emit_sites(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let sql = format!(
        r#"
        SELECT
            p.id AS id,
            p.url AS url,
            {},
            {},
            {}
        FROM moz_places p
        ORDER BY p.id;
        "#,
        select_column(schema, "moz_places", "p", "title", "title"),
        select_column(schema, "moz_places", "p", "visit_count", "visit_count"),
        select_column(
            schema,
            "moz_places",
            "p",
            "last_visit_date",
            "last_visit_date"
        ),
    );

    conn.query_rows(&sql, |row| {
        let id = row.i64(0).context("moz_places row missing id")?;
        let url = row.text(1);
        let title = non_empty(row.text(2));
        let text = title.clone().or_else(|| url.clone()).unwrap_or_default();
        let json = json!({
            "platform": "macos",
            "app": "firefox",
            "record_type": "site",
            "source": sqlite_source_json(evidence, "moz_places", id, SCHEMA_VARIANT),
            "timestamps": {
                "last_visit": firefox_prtime_to_json(row.i64(4)),
            },
            "site": {
                "id": id,
                "url": url.clone(),
                "host": url.as_deref().and_then(host_from_url),
                "title": title,
                "visit_count": row.i64(3),
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "macos.browser.site",
            text,
            json,
        })
    })
}

fn emit_visits(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let sql = format!(
        r#"
        SELECT
            v.id AS id,
            v.place_id AS place_id,
            p.url AS url,
            p.title AS title,
            v.visit_date AS visit_date,
            {},
            {}
        FROM moz_historyvisits v
        LEFT JOIN moz_places p ON p.id = v.place_id
        ORDER BY v.visit_date, v.id;
        "#,
        select_column(schema, "moz_historyvisits", "v", "visit_type", "visit_type"),
        select_column(schema, "moz_historyvisits", "v", "from_visit", "from_visit"),
    );

    conn.query_rows(&sql, |row| {
        let id = row.i64(0).context("moz_historyvisits row missing id")?;
        let url = row.text(2);
        let title = non_empty(row.text(3));
        let text = title.clone().or_else(|| url.clone()).unwrap_or_default();
        let json = json!({
            "platform": "macos",
            "app": "firefox",
            "record_type": "visit",
            "source": sqlite_source_json(evidence, "moz_historyvisits", id, SCHEMA_VARIANT),
            "timestamps": {
                "visit": firefox_prtime_to_json(row.i64(4)),
            },
            "visit": {
                "visit_id": id,
                "from_visit_id": row.i64(6),
                "visit_type_code": row.i64(5),
            },
            "site": {
                "place_id": row.i64(1),
                "url": url.clone(),
                "host": url.as_deref().and_then(host_from_url),
                "title": title,
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "macos.browser.visit",
            text,
            json,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::MacosFirefoxParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::parsers::mobile::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_places() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("places.sqlite");

        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE moz_places (
                    id INTEGER PRIMARY KEY,
                    url TEXT,
                    title TEXT,
                    visit_count INTEGER,
                    last_visit_date INTEGER
                );
                CREATE TABLE moz_historyvisits (
                    id INTEGER PRIMARY KEY,
                    place_id INTEGER,
                    visit_date INTEGER,
                    visit_type INTEGER,
                    from_visit INTEGER
                );

                INSERT INTO moz_places VALUES (1, 'https://www.example.org/', 'Example Org', 4, 1000000);
                INSERT INTO moz_historyvisits VALUES (7, 1, 1000000, 1, 0);
                "#,
            )?;
        }

        let parser = MacosFirefoxParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].kind, "macos.browser.site");
        assert_eq!(objects[0].json["site"]["host"], "www.example.org");
        assert_eq!(objects[1].kind, "macos.browser.visit");
        assert_eq!(
            objects[1].json["timestamps"]["visit"]["rfc3339"],
            "1970-01-01T00:00:01+00:00"
        );
        let events = parser.extract_timeline_events(&objects[1]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].description.as_deref(), Some("Example Org"));

        Ok(())
    }
}
