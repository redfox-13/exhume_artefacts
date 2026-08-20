//! Chromium-family browser `History` parser (Chrome, Brave, Edge, Chromium).
//!
//! Targets the `History` SQLite database (`urls`, `visits`, `downloads`).
//! Timestamps are WebKit epoch (microseconds since 1601-01-01 UTC). Emits
//! `macos.browser.site`, `macos.browser.visit` and `macos.browser.download`.

use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::parsers::macos::common::timestamps::chrome_webkit_to_json;
use crate::parsers::macos::common::util::{host_from_url, non_empty, sqlite_source_json};
use crate::parsers::mobile::sqlite::{
    SqliteConnection, SqliteEvidence, SqliteSchema, select_column,
};
use anyhow::{Context, Result, bail};
use serde_json::json;

const PARSER_NAME: &str = "macos_chromium";
const SCHEMA_VARIANT: &str = "chromium_history_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

#[derive(Default)]
pub struct MacosChromiumParser;

impl Parser for MacosChromiumParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse Chromium-family (Chrome/Brave/Edge) History database: sites, visits and downloads."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        match obj.kind {
            "macos.browser.visit" => {
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
            "macos.browser.download" => {
                let Some(ts_unix_ms) = obj.json["timestamps"]["start"]["unix_ms"].as_i64() else {
                    return Vec::new();
                };
                let description = obj.json["download"]["target_path"]
                    .as_str()
                    .or_else(|| obj.json["download"]["url"].as_str())
                    .map(str::to_owned);
                vec![TimelineEvent {
                    ts_unix_ms,
                    event_type: "macos.browser.download",
                    description,
                    actor: None,
                }]
            }
            _ => Vec::new(),
        }
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = SqliteEvidence::from_input(input, "History")?;
        let conn = SqliteConnection::open(evidence.path())?;
        let schema = conn.schema()?;
        validate_schema(&schema)?;

        emit_sites(&conn, &schema, &evidence, sink)?;
        emit_visits(&conn, &schema, &evidence, sink)?;
        if schema.has_table("downloads") {
            emit_downloads(&conn, &schema, &evidence, sink)?;
        }

        Ok(())
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    for table in ["urls", "visits"] {
        if !schema.has_table(table) {
            bail!("not a supported Chromium History database: missing {table} table");
        }
    }
    let missing = schema.missing_columns("urls", &["id", "url"]);
    if !missing.is_empty() {
        bail!(
            "not a supported Chromium History database: missing required columns: {}",
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
            u.id AS id,
            u.url AS url,
            {},
            {},
            {},
            {}
        FROM urls u
        ORDER BY u.id;
        "#,
        select_column(schema, "urls", "u", "title", "title"),
        select_column(schema, "urls", "u", "visit_count", "visit_count"),
        select_column(schema, "urls", "u", "typed_count", "typed_count"),
        select_column(schema, "urls", "u", "last_visit_time", "last_visit_time"),
    );

    conn.query_rows(&sql, |row| {
        let id = row.i64(0).context("urls row missing id")?;
        let url = row.text(1);
        let title = non_empty(row.text(2));
        let text = title.clone().or_else(|| url.clone()).unwrap_or_default();
        let json = json!({
            "platform": "macos",
            "app": "chromium",
            "record_type": "site",
            "source": sqlite_source_json(evidence, "urls", id, SCHEMA_VARIANT),
            "timestamps": {
                "last_visit": chrome_webkit_to_json(row.i64(5)),
            },
            "site": {
                "id": id,
                "url": url.clone(),
                "host": url.as_deref().and_then(host_from_url),
                "title": title,
                "visit_count": row.i64(3),
                "typed_count": row.i64(4),
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
            v.url AS url_id,
            u.url AS url,
            u.title AS title,
            {},
            {},
            {}
        FROM visits v
        LEFT JOIN urls u ON u.id = v.url
        ORDER BY v.visit_time, v.id;
        "#,
        select_column(schema, "visits", "v", "visit_time", "visit_time"),
        select_column(schema, "visits", "v", "from_visit", "from_visit"),
        select_column(schema, "visits", "v", "transition", "transition"),
    );

    conn.query_rows(&sql, |row| {
        let id = row.i64(0).context("visits row missing id")?;
        let url = row.text(2);
        let title = non_empty(row.text(3));
        let text = title.clone().or_else(|| url.clone()).unwrap_or_default();
        let transition = row.i64(6);
        let json = json!({
            "platform": "macos",
            "app": "chromium",
            "record_type": "visit",
            "source": sqlite_source_json(evidence, "visits", id, SCHEMA_VARIANT),
            "timestamps": {
                "visit": chrome_webkit_to_json(row.i64(4)),
            },
            "visit": {
                "visit_id": id,
                "from_visit_id": row.i64(5),
                "transition_code": transition,
                "transition_core": transition.map(|t| core_transition(t)),
            },
            "site": {
                "url_id": row.i64(1),
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

fn emit_downloads(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let sql = format!(
        r#"
        SELECT
            d.id AS id,
            {},
            {},
            {},
            {},
            {},
            {}
        FROM downloads d
        ORDER BY d.id;
        "#,
        select_column(schema, "downloads", "d", "target_path", "target_path"),
        select_column(schema, "downloads", "d", "tab_url", "tab_url"),
        select_column(schema, "downloads", "d", "start_time", "start_time"),
        select_column(schema, "downloads", "d", "end_time", "end_time"),
        select_column(schema, "downloads", "d", "received_bytes", "received_bytes"),
        select_column(schema, "downloads", "d", "total_bytes", "total_bytes"),
    );

    conn.query_rows(&sql, |row| {
        let id = row.i64(0).context("downloads row missing id")?;
        let target = non_empty(row.text(1));
        let tab_url = non_empty(row.text(2));
        let text = target
            .clone()
            .or_else(|| tab_url.clone())
            .unwrap_or_default();
        let json = json!({
            "platform": "macos",
            "app": "chromium",
            "record_type": "download",
            "source": sqlite_source_json(evidence, "downloads", id, SCHEMA_VARIANT),
            "timestamps": {
                "start": chrome_webkit_to_json(row.i64(3)),
                "end": chrome_webkit_to_json(row.i64(4)),
            },
            "download": {
                "id": id,
                "target_path": target,
                "url": tab_url.clone(),
                "host": tab_url.as_deref().and_then(host_from_url),
                "received_bytes": row.i64(5),
                "total_bytes": row.i64(6),
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "macos.browser.download",
            text,
            json,
        })
    })
}

/// The low byte of a Chromium page-transition value is the "core" type.
fn core_transition(transition: i64) -> &'static str {
    match transition & 0xff {
        0 => "link",
        1 => "typed",
        2 => "auto_bookmark",
        3 => "auto_subframe",
        4 => "manual_subframe",
        5 => "generated",
        6 => "start_page",
        7 => "form_submit",
        8 => "reload",
        9 => "keyword",
        10 => "keyword_generated",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::MacosChromiumParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::parsers::mobile::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_history() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("History");

        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE urls (
                    id INTEGER PRIMARY KEY,
                    url TEXT,
                    title TEXT,
                    visit_count INTEGER,
                    typed_count INTEGER,
                    last_visit_time INTEGER
                );
                CREATE TABLE visits (
                    id INTEGER PRIMARY KEY,
                    url INTEGER,
                    visit_time INTEGER,
                    from_visit INTEGER,
                    transition INTEGER
                );
                CREATE TABLE downloads (
                    id INTEGER PRIMARY KEY,
                    target_path TEXT,
                    tab_url TEXT,
                    start_time INTEGER,
                    end_time INTEGER,
                    received_bytes INTEGER,
                    total_bytes INTEGER
                );

                INSERT INTO urls VALUES (1, 'https://www.example.com/', 'Example', 2, 1, 11644473600000000);
                INSERT INTO visits VALUES (10, 1, 11644473600000000, 0, 1);
                INSERT INTO downloads VALUES (5, '/Users/u/Downloads/a.zip', 'https://dl.example.com/a.zip', 11644473600000000, 11644473600000000, 1024, 1024);
                "#,
            )?;
        }

        let parser = MacosChromiumParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        // 1 site + 1 visit + 1 download
        assert_eq!(objects.len(), 3);
        let site = &objects[0];
        assert_eq!(site.kind, "macos.browser.site");
        assert_eq!(site.json["site"]["host"], "www.example.com");
        // The WebKit epoch anchor (µs since 1601 equal to the 1601→1970 offset)
        // maps exactly to the Unix epoch.
        assert_eq!(
            site.json["timestamps"]["last_visit"]["rfc3339"],
            "1970-01-01T00:00:00+00:00"
        );

        let visit = &objects[1];
        assert_eq!(visit.kind, "macos.browser.visit");
        assert_eq!(visit.json["visit"]["transition_core"], "typed");
        let events = parser.extract_timeline_events(visit);
        assert_eq!(events.len(), 1);

        let download = &objects[2];
        assert_eq!(download.kind, "macos.browser.download");
        assert_eq!(download.json["download"]["total_bytes"], 1024);

        Ok(())
    }
}
