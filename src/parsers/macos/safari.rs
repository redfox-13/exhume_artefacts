//! macOS Safari `~/Library/Safari/History.db` parser.
//!
//! The desktop Safari history store uses the same `history_items` /
//! `history_visits` schema as iOS Safari, with WebKit/CFAbsoluteTime visit
//! timestamps. Emits `macos.browser.site` and `macos.browser.visit` objects.

use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::parsers::macos::common::timestamps::apple_absolute_to_json;
use crate::parsers::macos::common::util::{host_from_url, non_empty, sqlite_source_json};
use crate::parsers::mobile::sqlite::{
    SqliteConnection, SqliteEvidence, SqliteSchema, select_column,
};
use anyhow::{Context, Result, bail};
use serde_json::json;

const PARSER_NAME: &str = "macos_safari";
const SCHEMA_VARIANT: &str = "macos_safari_history_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

#[derive(Default)]
pub struct MacosSafariParser;

impl Parser for MacosSafariParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse macOS Safari History.db browsing sites and individual visit records."
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
        let description = obj.json["visit"]["title"]
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
        let evidence = SqliteEvidence::from_input(input, "History.db")?;
        let conn = SqliteConnection::open(evidence.path())?;
        let schema = conn.schema()?;
        validate_schema(&schema)?;

        emit_sites(&conn, &schema, &evidence, sink)?;
        emit_visits(&conn, &schema, &evidence, sink)?;

        Ok(())
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    for table in ["history_items", "history_visits"] {
        if !schema.has_table(table) {
            bail!("not a supported macOS Safari History.db: missing {table} table");
        }
    }
    let missing = schema.missing_columns("history_visits", &["id", "history_item", "visit_time"]);
    if !missing.is_empty() {
        bail!(
            "not a supported macOS Safari History.db: missing required columns: {}",
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
            i.id AS item_id,
            i.url AS url,
            {},
            {}
        FROM history_items i
        ORDER BY i.id;
        "#,
        select_column(schema, "history_items", "i", "visit_count", "visit_count"),
        select_column(
            schema,
            "history_items",
            "i",
            "domain_expansion",
            "domain_expansion"
        ),
    );

    conn.query_rows(&sql, |row| {
        let item_id = row.i64(0).context("history_items row missing id")?;
        let url = row.text(1);
        let text = url.clone().unwrap_or_default();
        let json = json!({
            "platform": "macos",
            "app": "safari",
            "record_type": "site",
            "source": sqlite_source_json(evidence, "history_items", item_id, SCHEMA_VARIANT),
            "site": {
                "item_id": item_id,
                "url": url,
                "host": url.as_deref().and_then(host_from_url),
                "visit_count": row.i64(2),
                "domain_expansion": non_empty(row.text(3)),
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
            v.id AS visit_id,
            v.history_item AS item_id,
            i.url AS url,
            v.visit_time AS visit_time,
            {},
            {},
            {},
            {},
            {}
        FROM history_visits v
        LEFT JOIN history_items i ON i.id = v.history_item
        ORDER BY v.visit_time, v.id;
        "#,
        select_column(schema, "history_visits", "v", "title", "title"),
        select_column(
            schema,
            "history_visits",
            "v",
            "load_successful",
            "load_successful"
        ),
        select_column(schema, "history_visits", "v", "origin", "origin"),
        select_column(
            schema,
            "history_visits",
            "v",
            "redirect_source",
            "redirect_source"
        ),
        select_column(
            schema,
            "history_visits",
            "v",
            "redirect_destination",
            "redirect_destination"
        ),
    );

    conn.query_rows(&sql, |row| {
        let visit_id = row.i64(0).context("history_visits row missing id")?;
        let url = row.text(2);
        let title = non_empty(row.text(4));
        let text = title.clone().or_else(|| url.clone()).unwrap_or_default();
        let redirect_source = row.i64(7);
        let redirect_destination = row.i64(8);
        let json = json!({
            "platform": "macos",
            "app": "safari",
            "record_type": "visit",
            "source": sqlite_source_json(evidence, "history_visits", visit_id, SCHEMA_VARIANT),
            "timestamps": {
                "visit": apple_absolute_to_json(row.f64(3)),
            },
            "visit": {
                "visit_id": visit_id,
                "title": title,
                "load_successful": row.bool(5),
                "origin_code": row.i64(6),
                "redirect_source_visit_id": redirect_source,
                "redirect_destination_visit_id": redirect_destination,
                "is_redirect": redirect_source.is_some() || redirect_destination.is_some(),
            },
            "site": {
                "item_id": row.i64(1),
                "url": url.clone(),
                "host": url.as_deref().and_then(host_from_url),
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
    use super::MacosSafariParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::parsers::mobile::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_history() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("History.db");

        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE history_items (
                    id INTEGER PRIMARY KEY,
                    url TEXT,
                    domain_expansion TEXT,
                    visit_count INTEGER
                );

                CREATE TABLE history_visits (
                    id INTEGER PRIMARY KEY,
                    history_item INTEGER,
                    visit_time REAL,
                    title TEXT,
                    load_successful INTEGER,
                    redirect_source INTEGER,
                    redirect_destination INTEGER,
                    origin INTEGER
                );

                INSERT INTO history_items (id, url, domain_expansion, visit_count)
                VALUES (1, 'https://user@www.example.com:443/path?q=1', 'example', 3);

                INSERT INTO history_visits (id, history_item, visit_time, title, load_successful, origin)
                VALUES (10, 1, 0.0, 'Example Domain', 1, 0);
                INSERT INTO history_visits (id, history_item, visit_time, title, load_successful, redirect_destination)
                VALUES (11, 1, 1.0, 'Example Domain', 1, 12);
                "#,
            )?;
        }

        let parser = MacosSafariParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 3);
        assert_eq!(objects[0].kind, "macos.browser.site");
        assert_eq!(objects[0].json["site"]["host"], "www.example.com");
        assert_eq!(objects[0].json["site"]["visit_count"], 3);

        assert_eq!(objects[1].kind, "macos.browser.visit");
        assert_eq!(objects[1].json["visit"]["title"], "Example Domain");
        assert_eq!(objects[1].json["visit"]["is_redirect"], false);
        assert_eq!(
            objects[1].json["timestamps"]["visit"]["rfc3339"],
            "2001-01-01T00:00:00+00:00"
        );
        assert_eq!(objects[2].json["visit"]["is_redirect"], true);

        let events = parser.extract_timeline_events(&objects[1]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "macos.browser.visit");
        assert_eq!(events[0].description.as_deref(), Some("Example Domain"));
        assert!(parser.extract_timeline_events(&objects[0]).is_empty());

        Ok(())
    }
}
