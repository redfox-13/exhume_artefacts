use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::formats::sqlite::{SqliteConnection, SqliteEvidence, SqliteSchema, select_column};
use crate::formats::timestamps::apple_absolute_to_json;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

const PARSER_NAME: &str = "mobile_ios_calendar";
const SCHEMA_VARIANT: &str = "ios_calendar_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

#[derive(Default)]
pub struct IosCalendarParser;

impl Parser for IosCalendarParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse Apple Calendar.sqlitedb events (CalendarItem) with times, location and attendees."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        if obj.kind != "mobile.calendar.event" {
            return Vec::new();
        }
        let Some(ts_unix_ms) = obj.json["timestamps"]["start"]["unix_ms"].as_i64() else {
            return Vec::new();
        };
        let description = obj.json["event"]["summary"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .or_else(|| Some("calendar event".to_string()));
        vec![TimelineEvent {
            ts_unix_ms,
            event_type: "mobile.calendar.event",
            description,
            actor: None,
        }]
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = SqliteEvidence::from_input(input, "Calendar.sqlitedb")?;
        let conn = SqliteConnection::open(evidence.path())?;
        let schema = conn.schema()?;
        validate_schema(&schema)?;

        emit_events(&conn, &schema, &evidence, sink)
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    if !schema.has_table("CalendarItem") {
        bail!("not a supported iOS Calendar.sqlitedb: missing CalendarItem table");
    }
    let missing = schema.missing_columns("CalendarItem", &["ROWID", "start_date"]);
    if !missing.is_empty() {
        bail!(
            "not a supported iOS Calendar.sqlitedb: missing required columns: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

fn emit_events(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let has_location_join = schema.has_table("Location")
        && schema.has_column("Location", "ROWID")
        && schema.has_column("CalendarItem", "location_id");
    let location_join = if has_location_join {
        "LEFT JOIN Location loc ON loc.ROWID = ci.location_id"
    } else {
        ""
    };
    let location_title = if has_location_join {
        select_column(schema, "Location", "loc", "title", "location_title")
    } else {
        "NULL AS location_title".to_string()
    };
    let location_address = if has_location_join {
        select_column(schema, "Location", "loc", "address", "location_address")
    } else {
        "NULL AS location_address".to_string()
    };

    let sql = format!(
        r#"
        SELECT
            ci.ROWID AS item_rowid,
            ci.start_date AS start_date,
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
            {location_title},
            {location_address}
        FROM CalendarItem ci
        {location_join}
        ORDER BY ci.start_date, ci.ROWID;
        "#,
        select_column(schema, "CalendarItem", "ci", "summary", "summary"),
        select_column(schema, "CalendarItem", "ci", "end_date", "end_date"),
        select_column(schema, "CalendarItem", "ci", "all_day", "all_day"),
        select_column(schema, "CalendarItem", "ci", "status", "status"),
        select_column(schema, "CalendarItem", "ci", "availability", "availability"),
        select_column(schema, "CalendarItem", "ci", "url", "url"),
        select_column(
            schema,
            "CalendarItem",
            "ci",
            "creation_date",
            "creation_date"
        ),
        select_column(
            schema,
            "CalendarItem",
            "ci",
            "last_modified",
            "last_modified"
        ),
        select_column(
            schema,
            "CalendarItem",
            "ci",
            "has_attendees",
            "has_attendees"
        ),
        select_column(schema, "CalendarItem", "ci", "UUID", "uuid"),
    );

    conn.query_rows(&sql, |row| {
        let item_rowid = row.i64(0).context("CalendarItem row missing ROWID")?;
        let summary = non_empty(row.text(2));
        let status_code = row.i64(5);
        let availability_code = row.i64(6);

        let text = summary.clone().unwrap_or_default();
        let json = json!({
            "platform": "ios",
            "app": "calendar",
            "record_type": "event",
            "source": source_json(evidence, item_rowid),
            "timestamps": {
                "start": apple_absolute_to_json(row.f64(1)),
                "end": apple_absolute_to_json(row.f64(3)),
                "creation": apple_absolute_to_json(row.f64(8)),
                "last_modified": apple_absolute_to_json(row.f64(9)),
            },
            "event": {
                "rowid": item_rowid,
                "summary": summary,
                "all_day": row.bool(4),
                "status_code": status_code,
                "status": event_status(status_code),
                "availability_code": availability_code,
                "availability": availability_label(availability_code),
                "url": non_empty(row.text(7)),
                "has_attendees": row.bool(10),
                "uuid": non_empty(row.text(11)),
            },
            "location": {
                "title": non_empty(row.text(12)),
                "address": non_empty(row.text(13)),
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "mobile.calendar.event",
            text,
            json,
        })
    })
}

/// EventKit `EKEventStatus`.
fn event_status(status: Option<i64>) -> &'static str {
    match status {
        Some(0) => "none",
        Some(1) => "confirmed",
        Some(2) => "tentative",
        Some(3) => "cancelled",
        _ => "unknown",
    }
}

/// EventKit `EKEventAvailability`.
fn availability_label(availability: Option<i64>) -> &'static str {
    match availability {
        Some(0) => "busy",
        Some(1) => "free",
        Some(2) => "tentative",
        Some(3) => "unavailable",
        _ => "unknown",
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
        "table": "CalendarItem",
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
    use super::IosCalendarParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::formats::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_calendar() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("Calendar.sqlitedb");

        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE Location (
                    ROWID INTEGER PRIMARY KEY,
                    title TEXT,
                    address TEXT
                );

                CREATE TABLE CalendarItem (
                    ROWID INTEGER PRIMARY KEY,
                    summary TEXT,
                    location_id INTEGER,
                    start_date FLOAT,
                    end_date FLOAT,
                    all_day INTEGER,
                    status INTEGER,
                    availability INTEGER,
                    url TEXT,
                    creation_date FLOAT,
                    last_modified FLOAT,
                    has_attendees INTEGER,
                    UUID TEXT
                );

                INSERT INTO Location (ROWID, title, address)
                VALUES (1, 'Cafe Central', '10 Rue de la Paix, Paris');

                INSERT INTO CalendarItem
                    (ROWID, summary, location_id, start_date, end_date, all_day, status, availability, url, creation_date, last_modified, has_attendees, UUID)
                VALUES
                    (100, 'Meeting', 1, 0.0, 3600.0, 0, 1, 0, 'https://example.com', 0.0, 0.0, 1, 'UUID-1');

                INSERT INTO CalendarItem
                    (ROWID, summary, start_date, all_day, status, availability)
                VALUES
                    (101, 'Birthday', 5.0, 1, 0, 1);
                "#,
            )?;
        }

        let parser = IosCalendarParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 2);
        let meeting = &objects[0];
        assert_eq!(meeting.kind, "mobile.calendar.event");
        assert_eq!(meeting.json["event"]["summary"], "Meeting");
        assert_eq!(meeting.json["event"]["status"], "confirmed");
        assert_eq!(meeting.json["event"]["availability"], "busy");
        assert_eq!(meeting.json["event"]["has_attendees"], true);
        assert_eq!(meeting.json["location"]["title"], "Cafe Central");
        assert_eq!(
            meeting.json["location"]["address"],
            "10 Rue de la Paix, Paris"
        );
        assert_eq!(
            meeting.json["timestamps"]["start"]["rfc3339"],
            "2001-01-01T00:00:00+00:00"
        );

        assert_eq!(objects[1].json["event"]["summary"], "Birthday");
        assert_eq!(objects[1].json["event"]["all_day"], true);
        assert!(objects[1].json["location"]["title"].is_null());

        let events = parser.extract_timeline_events(meeting);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].description.as_deref(), Some("Meeting"));

        Ok(())
    }
}
