use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::formats::sqlite::{SqliteConnection, SqliteEvidence, SqliteSchema, select_column};
use crate::formats::timestamps::apple_absolute_to_json;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const PARSER_NAME: &str = "mobile_ios_contacts";
const SCHEMA_VARIANT: &str = "ios_addressbook_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

#[derive(Default)]
pub struct IosContactsParser;

impl Parser for IosContactsParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse Apple AddressBook.sqlitedb contact records with phone, email and address multi-values."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        if obj.kind != "mobile.contact.person" {
            return Vec::new();
        }

        let display = obj.json["contact"]["display_name"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned);

        let mut events = Vec::new();
        if let Some(ts) = obj.json["timestamps"]["created"]["unix_ms"].as_i64() {
            events.push(TimelineEvent {
                ts_unix_ms: ts,
                event_type: "mobile.contact.created",
                description: display.clone(),
                actor: None,
            });
        }
        if let Some(ts) = obj.json["timestamps"]["modified"]["unix_ms"].as_i64() {
            // Skip a modified event that duplicates creation (contact never edited).
            let created = obj.json["timestamps"]["created"]["unix_ms"].as_i64();
            if created != Some(ts) {
                events.push(TimelineEvent {
                    ts_unix_ms: ts,
                    event_type: "mobile.contact.modified",
                    description: display,
                    actor: None,
                });
            }
        }
        events
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = SqliteEvidence::from_input(input, "AddressBook.sqlitedb")?;
        let conn = SqliteConnection::open(evidence.path())?;
        let schema = conn.schema()?;
        validate_schema(&schema)?;

        let multivalues = load_multivalues(&conn, &schema)?;
        emit_persons(&conn, &schema, &evidence, &multivalues, sink)
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    if !schema.has_table("ABPerson") {
        bail!("not a supported iOS AddressBook.sqlitedb: missing ABPerson table");
    }
    let missing = schema.missing_columns("ABPerson", &["ROWID"]);
    if !missing.is_empty() {
        bail!(
            "not a supported iOS AddressBook.sqlitedb: missing required columns: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

#[derive(Default)]
struct MultiValue {
    property: Option<i64>,
    label: Option<String>,
    value: Option<String>,
}

/// Map iOS ABMultiValue property codes to a human category name.
fn property_kind(property: Option<i64>) -> &'static str {
    match property {
        Some(3) => "phone",
        Some(4) => "email",
        Some(5) => "address",
        Some(13) => "url",
        Some(22) => "social_profile",
        Some(23) => "instant_message",
        Some(46) => "related_name",
        _ => "other",
    }
}

fn load_multivalues(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
) -> Result<BTreeMap<i64, Vec<MultiValue>>> {
    let mut out: BTreeMap<i64, Vec<MultiValue>> = BTreeMap::new();
    if !schema.has_table("ABMultiValue") || !schema.has_column("ABMultiValue", "record_id") {
        return Ok(out);
    }

    let label_join = schema.has_table("ABMultiValueLabel")
        && schema.has_column("ABMultiValueLabel", "value")
        && schema.has_column("ABMultiValue", "label");
    let (label_select, label_from) = if label_join {
        (
            "l.value AS label_text",
            "LEFT JOIN ABMultiValueLabel l ON l.ROWID = mv.label",
        )
    } else {
        ("NULL AS label_text", "")
    };

    let sql = format!(
        r#"
        SELECT
            mv.record_id AS record_id,
            {},
            {},
            {label_select}
        FROM ABMultiValue mv
        {label_from}
        ORDER BY mv.record_id, mv.UID;
        "#,
        select_column(schema, "ABMultiValue", "mv", "property", "property"),
        select_column(schema, "ABMultiValue", "mv", "value", "value"),
    );

    conn.query_rows(&sql, |row| {
        let Some(record_id) = row.i64(0) else {
            return Ok(());
        };
        out.entry(record_id).or_default().push(MultiValue {
            property: row.i64(1),
            value: non_empty(row.text(2)),
            label: clean_label(row.text(3)),
        });
        Ok(())
    })?;

    Ok(out)
}

fn emit_persons(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    multivalues: &BTreeMap<i64, Vec<MultiValue>>,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let sql = format!(
        r#"
        SELECT
            p.ROWID AS person_rowid,
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
        FROM ABPerson p
        ORDER BY p.ROWID;
        "#,
        select_column(schema, "ABPerson", "p", "First", "first"),
        select_column(schema, "ABPerson", "p", "Last", "last"),
        select_column(schema, "ABPerson", "p", "Middle", "middle"),
        select_column(schema, "ABPerson", "p", "Nickname", "nickname"),
        select_column(schema, "ABPerson", "p", "Organization", "organization"),
        select_column(schema, "ABPerson", "p", "JobTitle", "job_title"),
        select_column(schema, "ABPerson", "p", "Note", "note"),
        select_column(schema, "ABPerson", "p", "Birthday", "birthday"),
        select_column(schema, "ABPerson", "p", "CreationDate", "creation_date"),
        select_column(
            schema,
            "ABPerson",
            "p",
            "ModificationDate",
            "modification_date"
        ),
    );

    conn.query_rows(&sql, |row| {
        let person_rowid = row.i64(0).context("ABPerson row missing ROWID")?;
        let first = non_empty(row.text(1));
        let last = non_empty(row.text(2));
        let middle = non_empty(row.text(3));
        let nickname = non_empty(row.text(4));
        let organization = non_empty(row.text(5));

        let display_name = compose_name(first.as_deref(), middle.as_deref(), last.as_deref())
            .or_else(|| nickname.clone())
            .or_else(|| organization.clone())
            .unwrap_or_default();

        let entries = multivalues.get(&person_rowid);
        let phones = collect_values(entries, "phone");
        let emails = collect_values(entries, "email");

        let json = json!({
            "platform": "ios",
            "app": "contacts",
            "record_type": "person",
            "source": source_json(evidence, person_rowid),
            "timestamps": {
                "created": apple_absolute_to_json(row.f64(9)),
                "modified": apple_absolute_to_json(row.f64(10)),
            },
            "contact": {
                "rowid": person_rowid,
                "display_name": display_name,
                "first": first,
                "middle": middle,
                "last": last,
                "nickname": nickname,
                "organization": organization,
                "job_title": non_empty(row.text(6)),
                "note": non_empty(row.text(7)),
                "phones": phones,
                "emails": emails,
                "entries": entries_json(entries),
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "mobile.contact.person",
            text: display_name_text(&json),
            json,
        })
    })
}

fn display_name_text(json: &Value) -> String {
    json["contact"]["display_name"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn collect_values(entries: Option<&Vec<MultiValue>>, kind: &str) -> Value {
    let Some(entries) = entries else {
        return Value::Array(Vec::new());
    };
    let values = entries
        .iter()
        .filter(|mv| property_kind(mv.property) == kind)
        .filter_map(|mv| {
            mv.value.as_ref().map(|value| {
                json!({
                    "value": value,
                    "label": mv.label,
                })
            })
        })
        .collect::<Vec<_>>();
    Value::Array(values)
}

fn entries_json(entries: Option<&Vec<MultiValue>>) -> Value {
    let Some(entries) = entries else {
        return Value::Array(Vec::new());
    };
    let values = entries
        .iter()
        .filter_map(|mv| {
            let value = mv.value.as_ref()?;
            Some(json!({
                "kind": property_kind(mv.property),
                "property_code": mv.property,
                "label": mv.label,
                "value": value,
            }))
        })
        .collect::<Vec<_>>();
    Value::Array(values)
}

fn compose_name(first: Option<&str>, middle: Option<&str>, last: Option<&str>) -> Option<String> {
    let parts: Vec<&str> = [first, middle, last].into_iter().flatten().collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

/// Strip Apple's `_$!<Label>!$_` decoration to a plain label like "Mobile".
fn clean_label(value: Option<String>) -> Option<String> {
    let value = non_empty(value)?;
    let trimmed = value
        .trim_start_matches("_$!<")
        .trim_end_matches(">!$_")
        .to_string();
    non_empty(Some(trimmed))
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
        "table": "ABPerson",
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
    use super::IosContactsParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::formats::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_addressbook() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("AddressBook.sqlitedb");

        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE ABPerson (
                    ROWID INTEGER PRIMARY KEY,
                    First TEXT,
                    Last TEXT,
                    Middle TEXT,
                    Nickname TEXT,
                    Organization TEXT,
                    JobTitle TEXT,
                    Note TEXT,
                    Birthday TEXT,
                    CreationDate FLOAT,
                    ModificationDate FLOAT
                );

                CREATE TABLE ABMultiValueLabel (
                    ROWID INTEGER PRIMARY KEY,
                    value TEXT
                );

                CREATE TABLE ABMultiValue (
                    UID INTEGER PRIMARY KEY,
                    record_id INTEGER,
                    property INTEGER,
                    label INTEGER,
                    value TEXT
                );

                INSERT INTO ABMultiValueLabel (ROWID, value) VALUES (1, '_$!<Mobile>!$_');
                INSERT INTO ABMultiValueLabel (ROWID, value) VALUES (2, '_$!<Home>!$_');

                INSERT INTO ABPerson (ROWID, First, Last, Organization, CreationDate, ModificationDate)
                VALUES (1, 'Alice', 'Smith', 'Acme', 0.0, 100.0);

                INSERT INTO ABPerson (ROWID, First, CreationDate, ModificationDate)
                VALUES (2, 'Bob', 50.0, 50.0);

                INSERT INTO ABMultiValue (UID, record_id, property, label, value)
                VALUES (1, 1, 3, 1, '+15551234567');
                INSERT INTO ABMultiValue (UID, record_id, property, label, value)
                VALUES (2, 1, 4, 2, 'alice@example.com');
                INSERT INTO ABMultiValue (UID, record_id, property, label, value)
                VALUES (3, 2, 3, 1, '+15559876543');
                "#,
            )?;
        }

        let parser = IosContactsParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 2);
        let alice = &objects[0];
        assert_eq!(alice.kind, "mobile.contact.person");
        assert_eq!(alice.json["contact"]["display_name"], "Alice Smith");
        assert_eq!(alice.json["contact"]["phones"][0]["value"], "+15551234567");
        assert_eq!(alice.json["contact"]["phones"][0]["label"], "Mobile");
        assert_eq!(
            alice.json["contact"]["emails"][0]["value"],
            "alice@example.com"
        );
        assert_eq!(alice.json["contact"]["emails"][0]["label"], "Home");
        assert_eq!(
            alice.json["timestamps"]["created"]["rfc3339"],
            "2001-01-01T00:00:00+00:00"
        );

        // Alice: created != modified -> both events; Bob: equal -> created only.
        assert_eq!(parser.extract_timeline_events(alice).len(), 2);
        let bob_events = parser.extract_timeline_events(&objects[1]);
        assert_eq!(bob_events.len(), 1);
        assert_eq!(bob_events[0].event_type, "mobile.contact.created");

        Ok(())
    }
}
