use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::formats::sqlite::{SqliteConnection, SqliteEvidence, SqliteSchema, select_column};
use crate::formats::timestamps::apple_absolute_to_json;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

const PARSER_NAME: &str = "mobile_ios_notes";
const SCHEMA_VARIANT: &str = "ios_notestore_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

#[derive(Default)]
pub struct IosNotesParser;

impl Parser for IosNotesParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse Apple Notes NoteStore.sqlite note metadata (title, snippet, folder, timestamps)."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        if obj.kind != "mobile.note" {
            return Vec::new();
        }
        let title = obj.json["note"]["title"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned);

        let mut events = Vec::new();
        if let Some(ts) = obj.json["timestamps"]["created"]["unix_ms"].as_i64() {
            events.push(TimelineEvent {
                ts_unix_ms: ts,
                event_type: "mobile.note.created",
                description: title.clone(),
                actor: None,
            });
        }
        if let Some(ts) = obj.json["timestamps"]["modified"]["unix_ms"].as_i64() {
            let created = obj.json["timestamps"]["created"]["unix_ms"].as_i64();
            if created != Some(ts) {
                events.push(TimelineEvent {
                    ts_unix_ms: ts,
                    event_type: "mobile.note.modified",
                    description: title,
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
        let evidence = SqliteEvidence::from_input(input, "NoteStore.sqlite")?;
        let conn = SqliteConnection::open(evidence.path())?;
        let schema = conn.schema()?;
        validate_schema(&schema)?;

        emit_notes(&conn, &schema, &evidence, sink)
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    if !schema.has_table("ZICCLOUDSYNCINGOBJECT") {
        bail!("not a supported iOS NoteStore.sqlite: missing ZICCLOUDSYNCINGOBJECT table");
    }
    if !schema.has_column("ZICCLOUDSYNCINGOBJECT", "ZNOTEDATA") {
        bail!("not a supported iOS NoteStore.sqlite: missing ZNOTEDATA column");
    }
    Ok(())
}

fn emit_notes(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    // Notes and folders share ZICCLOUDSYNCINGOBJECT; a note row has ZNOTEDATA set,
    // its parent folder row carries the folder name in ZTITLE2.
    let has_folder_join = schema.has_column("ZICCLOUDSYNCINGOBJECT", "ZFOLDER")
        && schema.has_column("ZICCLOUDSYNCINGOBJECT", "ZTITLE2");
    let folder_join = if has_folder_join {
        "LEFT JOIN ZICCLOUDSYNCINGOBJECT f ON f.Z_PK = o.ZFOLDER"
    } else {
        ""
    };
    let folder_name = if has_folder_join {
        "f.ZTITLE2 AS folder_name"
    } else {
        "NULL AS folder_name"
    };

    let sql = format!(
        r#"
        SELECT
            o.Z_PK AS note_pk,
            {},
            {},
            {},
            {},
            {},
            {},
            {folder_name}
        FROM ZICCLOUDSYNCINGOBJECT o
        {folder_join}
        WHERE o.ZNOTEDATA IS NOT NULL
        ORDER BY o.Z_PK;
        "#,
        select_column(schema, "ZICCLOUDSYNCINGOBJECT", "o", "ZTITLE1", "title"),
        select_column(schema, "ZICCLOUDSYNCINGOBJECT", "o", "ZSNIPPET", "snippet"),
        select_column(
            schema,
            "ZICCLOUDSYNCINGOBJECT",
            "o",
            "ZIDENTIFIER",
            "identifier"
        ),
        select_column(
            schema,
            "ZICCLOUDSYNCINGOBJECT",
            "o",
            "ZCREATIONDATE1",
            "creation_date"
        ),
        select_column(
            schema,
            "ZICCLOUDSYNCINGOBJECT",
            "o",
            "ZMODIFICATIONDATE1",
            "modification_date"
        ),
        select_column(
            schema,
            "ZICCLOUDSYNCINGOBJECT",
            "o",
            "ZMARKEDFORDELETION",
            "marked_for_deletion"
        ),
    );

    conn.query_rows(&sql, |row| {
        let note_pk = row.i64(0).context("note row missing Z_PK")?;
        let title = non_empty(row.text(1));
        let snippet = non_empty(row.text(2));

        let text = title.clone().unwrap_or_default();
        let json = json!({
            "platform": "ios",
            "app": "notes",
            "record_type": "note",
            "source": source_json(evidence, note_pk),
            "timestamps": {
                "created": apple_absolute_to_json(row.f64(4)),
                "modified": apple_absolute_to_json(row.f64(5)),
            },
            "note": {
                "pk": note_pk,
                "title": title,
                "snippet": snippet,
                "identifier": non_empty(row.text(3)),
                "folder": non_empty(row.text(7)),
                "deleted": row.bool(6),
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "mobile.note",
            text,
            json,
        })
    })
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
        "table": "ZICCLOUDSYNCINGOBJECT",
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
    use super::IosNotesParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::formats::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_notestore() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("NoteStore.sqlite");

        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE ZICCLOUDSYNCINGOBJECT (
                    Z_PK INTEGER PRIMARY KEY,
                    ZNOTEDATA INTEGER,
                    ZFOLDER INTEGER,
                    ZMARKEDFORDELETION INTEGER,
                    ZCREATIONDATE1 FLOAT,
                    ZMODIFICATIONDATE1 FLOAT,
                    ZTITLE1 TEXT,
                    ZTITLE2 TEXT,
                    ZSNIPPET TEXT,
                    ZIDENTIFIER TEXT
                );

                -- folder row (ZTITLE2 set, no ZNOTEDATA)
                INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, ZTITLE2) VALUES (1, 'Notes');

                -- note rows (ZNOTEDATA set)
                INSERT INTO ZICCLOUDSYNCINGOBJECT
                    (Z_PK, ZNOTEDATA, ZFOLDER, ZMARKEDFORDELETION, ZCREATIONDATE1, ZMODIFICATIONDATE1, ZTITLE1, ZSNIPPET, ZIDENTIFIER)
                VALUES
                    (2, 10, 1, 0, 0.0, 100.0, 'Shopping list', 'Milk, eggs, bread', 'UUID-A');

                INSERT INTO ZICCLOUDSYNCINGOBJECT
                    (Z_PK, ZNOTEDATA, ZFOLDER, ZMARKEDFORDELETION, ZCREATIONDATE1, ZMODIFICATIONDATE1, ZTITLE1, ZSNIPPET, ZIDENTIFIER)
                VALUES
                    (3, 11, 1, 0, 50.0, 50.0, 'Meeting notes', 'Discuss Q3', 'UUID-B');
                "#,
            )?;
        }

        let parser = IosNotesParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        // Only the two note rows (not the folder row) are emitted.
        assert_eq!(objects.len(), 2);
        let note = &objects[0];
        assert_eq!(note.kind, "mobile.note");
        assert_eq!(note.json["note"]["title"], "Shopping list");
        assert_eq!(note.json["note"]["snippet"], "Milk, eggs, bread");
        assert_eq!(note.json["note"]["folder"], "Notes");
        assert_eq!(
            note.json["timestamps"]["created"]["rfc3339"],
            "2001-01-01T00:00:00+00:00"
        );

        // note 2: created != modified -> 2 events; note 3: equal -> 1 event.
        assert_eq!(parser.extract_timeline_events(note).len(), 2);
        let n3 = parser.extract_timeline_events(&objects[1]);
        assert_eq!(n3.len(), 1);
        assert_eq!(n3[0].event_type, "mobile.note.created");

        Ok(())
    }
}
