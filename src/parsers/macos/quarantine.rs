//! macOS LaunchServices quarantine database
//! (`com.apple.LaunchServices.QuarantineEventsV2`) parser.
//!
//! Records the provenance of downloaded files: which agent (browser/app)
//! fetched each file, the data URL, the originating page, and when. Emits
//! `macos.download.quarantine`. Timestamps are CFAbsoluteTime.

use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::parsers::macos::common::timestamps::apple_absolute_to_json;
use crate::parsers::macos::common::util::{non_empty, sqlite_source_json};
use crate::parsers::mobile::sqlite::{
    SqliteConnection, SqliteEvidence, SqliteSchema, select_column,
};
use anyhow::{Context, Result, bail};
use serde_json::json;

const PARSER_NAME: &str = "macos_quarantine";
const SCHEMA_VARIANT: &str = "macos_quarantine_eventsv2_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

#[derive(Default)]
pub struct MacosQuarantineParser;

impl Parser for MacosQuarantineParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse the macOS LaunchServices QuarantineEventsV2 database of downloaded-file provenance."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        if obj.kind != "macos.download.quarantine" {
            return Vec::new();
        }
        let Some(ts_unix_ms) = obj.json["timestamps"]["quarantine"]["unix_ms"].as_i64() else {
            return Vec::new();
        };
        let actor = obj.json["event"]["agent_name"]
            .as_str()
            .or_else(|| obj.json["event"]["agent_bundle_id"].as_str())
            .map(str::to_owned);
        let url = obj.json["event"]["data_url"]
            .as_str()
            .or_else(|| obj.json["event"]["origin_url"].as_str())
            .unwrap_or("(no url)");
        let description = match actor.as_deref() {
            Some(actor) => format!("{actor} downloaded {url}"),
            None => format!("Downloaded {url}"),
        };
        vec![TimelineEvent {
            ts_unix_ms,
            event_type: "macos.download.quarantine",
            description: Some(description),
            actor,
        }]
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = SqliteEvidence::from_input(input, "QuarantineEventsV2")?;
        let conn = SqliteConnection::open(evidence.path())?;
        let schema = conn.schema()?;
        if !schema.has_table("LSQuarantineEvent")
            || !schema.has_column("LSQuarantineEvent", "LSQuarantineTimeStamp")
        {
            bail!(
                "not a supported QuarantineEventsV2 database: missing LSQuarantineEvent table or timestamp column"
            );
        }
        emit_events(&conn, &schema, &evidence, sink)
    }
}

fn emit_events(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let t = "LSQuarantineEvent";
    let sql = format!(
        r#"
        SELECT
            e.rowid AS rowid,
            {}, {}, {}, {}, {}, {}, {}, {}, {}, {}
        FROM LSQuarantineEvent e
        ORDER BY e.LSQuarantineTimeStamp, e.rowid;
        "#,
        select_column(schema, t, "e", "LSQuarantineEventIdentifier", "id"),
        select_column(schema, t, "e", "LSQuarantineTimeStamp", "ts"),
        select_column(schema, t, "e", "LSQuarantineAgentName", "agent_name"),
        select_column(
            schema,
            t,
            "e",
            "LSQuarantineAgentBundleIdentifier",
            "agent_bundle"
        ),
        select_column(schema, t, "e", "LSQuarantineDataURLString", "data_url"),
        select_column(schema, t, "e", "LSQuarantineOriginURLString", "origin_url"),
        select_column(schema, t, "e", "LSQuarantineOriginTitle", "origin_title"),
        select_column(schema, t, "e", "LSQuarantineSenderName", "sender_name"),
        select_column(
            schema,
            t,
            "e",
            "LSQuarantineSenderAddress",
            "sender_address"
        ),
        select_column(schema, t, "e", "LSQuarantineTypeNumber", "type_number"),
    );

    conn.query_rows(&sql, |row| {
        let rowid = row.i64(0).context("quarantine row missing rowid")?;
        let agent = non_empty(row.text(3));
        let data_url = non_empty(row.text(5));
        let origin_url = non_empty(row.text(6));
        let text = data_url
            .clone()
            .or_else(|| origin_url.clone())
            .or_else(|| agent.clone())
            .unwrap_or_default();
        let json = json!({
            "platform": "macos",
            "app": "quarantine",
            "record_type": "quarantine_event",
            "source": sqlite_source_json(evidence, "LSQuarantineEvent", rowid, SCHEMA_VARIANT),
            "timestamps": {
                "quarantine": apple_absolute_to_json(row.f64(2)),
            },
            "event": {
                "event_id": non_empty(row.text(1)),
                "agent_name": agent,
                "agent_bundle_id": non_empty(row.text(4)),
                "data_url": data_url,
                "origin_url": origin_url,
                "origin_title": non_empty(row.text(7)),
                "sender_name": non_empty(row.text(8)),
                "sender_address": non_empty(row.text(9)),
                "type_number": row.i64(10),
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "macos.download.quarantine",
            text,
            json,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::MacosQuarantineParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::parsers::mobile::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_quarantine() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("QuarantineEventsV2");
        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE LSQuarantineEvent (
                    LSQuarantineEventIdentifier TEXT PRIMARY KEY,
                    LSQuarantineTimeStamp REAL,
                    LSQuarantineAgentBundleIdentifier TEXT,
                    LSQuarantineAgentName TEXT,
                    LSQuarantineDataURLString TEXT,
                    LSQuarantineSenderName TEXT,
                    LSQuarantineSenderAddress TEXT,
                    LSQuarantineTypeNumber INTEGER,
                    LSQuarantineOriginTitle TEXT,
                    LSQuarantineOriginURLString TEXT,
                    LSQuarantineOriginAlias BLOB
                );
                INSERT INTO LSQuarantineEvent
                    (LSQuarantineEventIdentifier, LSQuarantineTimeStamp, LSQuarantineAgentName,
                     LSQuarantineDataURLString, LSQuarantineOriginURLString, LSQuarantineTypeNumber)
                VALUES
                    ('UUID-1', 0.0, 'Safari',
                     'https://dl.example.com/tool.dmg', 'https://example.com/', 0);
                INSERT INTO LSQuarantineEvent
                    (LSQuarantineEventIdentifier, LSQuarantineTimeStamp,
                     LSQuarantineAgentBundleIdentifier, LSQuarantineDataURLString,
                     LSQuarantineTypeNumber)
                VALUES
                    ('UUID-2', 1.0, 'com.example.downloader',
                     'https://dl.example.com/bundle-only.dmg', 0);
                INSERT INTO LSQuarantineEvent
                    (LSQuarantineEventIdentifier, LSQuarantineTimeStamp,
                     LSQuarantineDataURLString, LSQuarantineTypeNumber)
                VALUES
                    ('UUID-3', 2.0, 'https://dl.example.com/anonymous.dmg', 0);
                "#,
            )?;
        }

        let parser = MacosQuarantineParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |o| {
            objects.push(o);
            Ok(())
        })?;

        assert_eq!(objects.len(), 3);
        let e = &objects[0];
        assert_eq!(e.kind, "macos.download.quarantine");
        assert_eq!(e.json["event"]["agent_name"], "Safari");
        assert_eq!(
            e.json["event"]["data_url"],
            "https://dl.example.com/tool.dmg"
        );
        assert_eq!(
            e.json["timestamps"]["quarantine"]["rfc3339"],
            "2001-01-01T00:00:00+00:00"
        );

        let events = parser.extract_timeline_events(e);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor.as_deref(), Some("Safari"));

        let bundle_events = parser.extract_timeline_events(&objects[1]);
        assert_eq!(bundle_events.len(), 1);
        assert_eq!(
            bundle_events[0].actor.as_deref(),
            Some("com.example.downloader")
        );

        let anonymous_events = parser.extract_timeline_events(&objects[2]);
        assert_eq!(anonymous_events.len(), 1);
        assert_eq!(anonymous_events[0].actor, None);
        assert_eq!(
            anonymous_events[0].description.as_deref(),
            Some("Downloaded https://dl.example.com/anonymous.dmg")
        );

        Ok(())
    }
}
