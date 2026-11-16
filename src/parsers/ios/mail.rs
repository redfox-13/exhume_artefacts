use crate::core::{
    CompanionSpec, ObjectParsed, Parser, ParserFileProvider, ParserInput, ParserSource,
    TimelineEvent,
};
use crate::formats::sqlite::{SqliteConnection, SqliteSchema, select_column};
use crate::formats::timestamps::unix_seconds_to_json;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const PARSER_NAME: &str = "mobile_ios_mail";
const SCHEMA_VARIANT: &str = "ios_mail_envelope_v1";
const PROTECTED_INDEX: &str = "Protected Index";

// Apple Mail splits data across sibling databases: "Envelope Index" (structure,
// dates, flags, integer FKs) and "Protected Index" (subject/address text). Both
// are pulled in so message subjects and addresses can be resolved.
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
    CompanionSpec::optional_sibling("protected_index", "Protected Index"),
    CompanionSpec::optional_sibling("protected_index_wal", "Protected Index-wal"),
    CompanionSpec::optional_sibling("protected_index_shm", "Protected Index-shm"),
];

#[derive(Default)]
pub struct IosMailParser;

impl Parser for IosMailParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse Apple Mail Envelope Index messages, joined with the sibling Protected Index for subjects and addresses."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        if obj.kind != "mobile.communication.email" {
            return Vec::new();
        }
        let ts_unix_ms = obj.json["timestamps"]["received"]["unix_ms"]
            .as_i64()
            .or_else(|| obj.json["timestamps"]["sent"]["unix_ms"].as_i64());
        let Some(ts_unix_ms) = ts_unix_ms else {
            return Vec::new();
        };
        let subject = obj.json["message"]["subject"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or("(no subject)");
        vec![TimelineEvent {
            ts_unix_ms,
            event_type: "mobile.communication.email",
            description: Some(format!("email: {subject}")),
            actor: obj.json["from"]["address"].as_str().map(str::to_owned),
        }]
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let prepared = MailFiles::from_input(input)?;
        let conn = SqliteConnection::open(prepared.envelope_path())?;
        let schema = conn.schema()?;
        validate_schema(&schema)?;

        // Resolve subject/address text from the Protected Index when present.
        let (subjects, addresses) = match prepared.protected_path() {
            Some(path) => {
                let pconn = SqliteConnection::open(path)?;
                let pschema = pconn.schema()?;
                (
                    load_subjects(&pconn, &pschema)?,
                    load_addresses(&pconn, &pschema)?,
                )
            }
            None => (BTreeMap::new(), BTreeMap::new()),
        };

        let recipients = load_recipients(&conn, &schema)?;
        emit_messages(
            &conn,
            &schema,
            &prepared,
            &subjects,
            &addresses,
            &recipients,
            sink,
        )
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    if !schema.has_table("messages") {
        bail!("not a supported iOS Mail Envelope Index: missing messages table");
    }
    let missing = schema.missing_columns("messages", &["ROWID", "date_received"]);
    if !missing.is_empty() {
        bail!(
            "not a supported iOS Mail Envelope Index: missing required columns: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
struct AddressEntry {
    address: Option<String>,
    name: Option<String>,
}

fn load_subjects(conn: &SqliteConnection, schema: &SqliteSchema) -> Result<BTreeMap<i64, String>> {
    let mut out = BTreeMap::new();
    if !schema.has_table("subjects") || !schema.has_column("subjects", "subject") {
        return Ok(out);
    }
    conn.query_rows("SELECT ROWID, subject FROM subjects;", |row| {
        if let (Some(id), Some(subject)) = (row.i64(0), row.text(1)) {
            out.insert(id, subject);
        }
        Ok(())
    })?;
    Ok(out)
}

fn load_addresses(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
) -> Result<BTreeMap<i64, AddressEntry>> {
    let mut out = BTreeMap::new();
    if !schema.has_table("addresses") || !schema.has_column("addresses", "address") {
        return Ok(out);
    }
    let comment = select_column(schema, "addresses", "addresses", "comment", "comment");
    let sql = format!("SELECT ROWID AS id, address, {comment} FROM addresses;");
    conn.query_rows(&sql, |row| {
        if let Some(id) = row.i64(0) {
            out.insert(
                id,
                AddressEntry {
                    address: non_empty(row.text(1)),
                    name: non_empty(row.text(2)),
                },
            );
        }
        Ok(())
    })?;
    Ok(out)
}

fn load_recipients(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
) -> Result<BTreeMap<i64, Vec<(i64, i64)>>> {
    // message_rowid -> [(type, address_id)]
    let mut out: BTreeMap<i64, Vec<(i64, i64)>> = BTreeMap::new();
    if !schema.has_table("recipients")
        || !schema.has_column("recipients", "message")
        || !schema.has_column("recipients", "address")
    {
        return Ok(out);
    }
    conn.query_rows(
        "SELECT message, type, address FROM recipients ORDER BY message, position;",
        |row| {
            if let (Some(msg), Some(addr)) = (row.i64(0), row.i64(2)) {
                out.entry(msg)
                    .or_default()
                    .push((row.i64(1).unwrap_or(-1), addr));
            }
            Ok(())
        },
    )?;
    Ok(out)
}

fn emit_messages(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    prepared: &MailFiles,
    subjects: &BTreeMap<i64, String>,
    addresses: &BTreeMap<i64, AddressEntry>,
    recipients: &BTreeMap<i64, Vec<(i64, i64)>>,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let has_mailbox_join = schema.has_table("mailboxes")
        && schema.has_column("mailboxes", "url")
        && schema.has_column("messages", "mailbox");
    let mailbox_join = if has_mailbox_join {
        "LEFT JOIN mailboxes mb ON mb.ROWID = m.mailbox"
    } else {
        ""
    };
    let mailbox_col = if has_mailbox_join {
        "mb.url AS mailbox_url"
    } else {
        "NULL AS mailbox_url"
    };

    let sql = format!(
        r#"
        SELECT
            m.ROWID AS message_rowid,
            {},
            {},
            {},
            m.date_received AS date_received,
            {},
            {},
            {},
            {},
            {},
            {mailbox_col}
        FROM messages m
        {mailbox_join}
        ORDER BY m.date_received, m.ROWID;
        "#,
        select_column(schema, "messages", "m", "subject", "subject_id"),
        select_column(schema, "messages", "m", "sender", "sender_id"),
        select_column(schema, "messages", "m", "date_sent", "date_sent"),
        select_column(schema, "messages", "m", "read", "read"),
        select_column(schema, "messages", "m", "flagged", "flagged"),
        select_column(schema, "messages", "m", "deleted", "deleted"),
        select_column(schema, "messages", "m", "size", "size"),
        select_column(
            schema,
            "messages",
            "m",
            "conversation_id",
            "conversation_id"
        ),
    );

    conn.query_rows(&sql, |row| {
        let message_rowid = row.i64(0).context("message row missing ROWID")?;
        let subject = row.i64(1).and_then(|id| subjects.get(&id).cloned());
        let from = row
            .i64(2)
            .and_then(|id| addresses.get(&id))
            .cloned()
            .unwrap_or_default();

        let mut to: Vec<String> = Vec::new();
        let mut cc: Vec<String> = Vec::new();
        let mut bcc: Vec<String> = Vec::new();
        if let Some(list) = recipients.get(&message_rowid) {
            for (rtype, addr_id) in list {
                let Some(entry) = addresses.get(addr_id) else {
                    continue;
                };
                let Some(email) = entry.address.clone() else {
                    continue;
                };
                match rtype {
                    2 => cc.push(email),
                    3 => bcc.push(email),
                    _ => to.push(email), // 0/1/unknown -> primary recipients
                }
            }
        }
        let to_display = to.join(", ");

        let text = subject.clone().unwrap_or_default();
        let json = json!({
            "platform": "ios",
            "app": "mail",
            "record_type": "email",
            "source": source_json(prepared, message_rowid),
            "timestamps": {
                "received": unix_seconds_to_json(row.i64(4)),
                "sent": unix_seconds_to_json(row.i64(3)),
            },
            "message": {
                "rowid": message_rowid,
                "subject": subject,
                "mailbox": row.text(10),
                "read": row.bool(5),
                "flagged": row.bool(6),
                "deleted": row.bool(7),
                "size": row.i64(8),
                "conversation_id": row.i64(9),
            },
            "from": {
                "address": from.address,
                "name": from.name,
            },
            "to": to,
            "cc": cc,
            "bcc": bcc,
            "to_display": to_display,
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "mobile.communication.email",
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

fn source_json(prepared: &MailFiles, rowid: i64) -> Value {
    json!({
        "path": prepared.source_label(),
        "table": "messages",
        "rowid": rowid,
        "schema_variant": SCHEMA_VARIANT,
        "parser_confidence": "compatible_schema",
        "protected_index_present": prepared.protected_path().is_some(),
    })
}

/// Copies the Envelope Index (+ WAL/SHM) and, when available, the sibling
/// Protected Index into a temp directory for read-only querying.
struct MailFiles {
    _tempdir: TempDir,
    envelope: PathBuf,
    protected: Option<PathBuf>,
    source_label: String,
}

impl MailFiles {
    fn envelope_path(&self) -> &Path {
        &self.envelope
    }
    fn protected_path(&self) -> Option<&Path> {
        self.protected.as_deref()
    }
    fn source_label(&self) -> String {
        self.source_label.clone()
    }

    fn from_input(input: ParserInput) -> Result<Self> {
        let tempdir = tempfile::tempdir().context("failed to create temp dir for Mail")?;
        let envelope = tempdir.path().join("envelope.db");
        let protected = tempdir.path().join("protected.db");
        let mut source_label = "<in-memory>".to_string();
        let mut has_protected = false;

        match input {
            ParserInput::Path(path) => {
                source_label = path.display().to_string();
                fs::copy(&path, &envelope)
                    .with_context(|| format!("failed to copy {}", path.display()))?;
                copy_if_exists(&with_suffix(&path, "-wal"), &with_suffix(&envelope, "-wal"))?;
                copy_if_exists(&with_suffix(&path, "-shm"), &with_suffix(&envelope, "-shm"))?;

                if let Some(dir) = path.parent() {
                    let prot_src = dir.join(PROTECTED_INDEX);
                    if prot_src.exists() {
                        fs::copy(&prot_src, &protected)?;
                        copy_if_exists(
                            &dir.join(format!("{PROTECTED_INDEX}-wal")),
                            &with_suffix(&protected, "-wal"),
                        )?;
                        copy_if_exists(
                            &dir.join(format!("{PROTECTED_INDEX}-shm")),
                            &with_suffix(&protected, "-shm"),
                        )?;
                        has_protected = true;
                    }
                }
            }
            ParserInput::Bytes(bytes) => {
                fs::write(&envelope, bytes)?;
            }
            ParserInput::ReadSeek(mut reader) => {
                let mut bytes = Vec::new();
                reader.seek(SeekFrom::Start(0))?;
                reader.read_to_end(&mut bytes)?;
                fs::write(&envelope, bytes)?;
            }
            ParserInput::Compound(compound) => {
                source_label = compound.primary.original_path.clone();
                let crate::core::CompoundParserInput {
                    primary,
                    companions,
                    mut provider,
                } = compound;
                copy_source(&mut *provider, &primary, &envelope)?;
                for companion in &companions {
                    let target = match companion.role.as_str() {
                        "sqlite_wal" => with_suffix(&envelope, "-wal"),
                        "sqlite_shm" => with_suffix(&envelope, "-shm"),
                        "protected_index" => {
                            has_protected = true;
                            protected.clone()
                        }
                        "protected_index_wal" => with_suffix(&protected, "-wal"),
                        "protected_index_shm" => with_suffix(&protected, "-shm"),
                        _ => continue,
                    };
                    copy_source(&mut *provider, companion, &target)?;
                }
            }
        }

        Ok(Self {
            _tempdir: tempdir,
            envelope,
            protected: has_protected.then_some(protected),
            source_label,
        })
    }
}

fn copy_source(
    provider: &mut dyn ParserFileProvider,
    source: &ParserSource,
    target: &Path,
) -> Result<()> {
    let mut file = fs::File::create(target)
        .with_context(|| format!("failed to create {}", target.display()))?;
    provider.copy_to(source, &mut file)?;
    Ok(())
}

fn copy_if_exists(src: &Path, dst: &Path) -> Result<()> {
    if src.exists() {
        fs::copy(src, dst)?;
    }
    Ok(())
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::IosMailParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::formats::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_mail() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let env_path = tempdir.path().join("Envelope Index");
        let prot_path = tempdir.path().join("Protected Index");

        {
            let prot = SqliteConnection::create_for_test(&prot_path)?;
            prot.execute_batch(
                r#"
                CREATE TABLE subjects (ROWID INTEGER PRIMARY KEY, subject TEXT);
                CREATE TABLE addresses (ROWID INTEGER PRIMARY KEY, address TEXT, comment TEXT);
                INSERT INTO subjects (ROWID, subject) VALUES (1, 'visite du logement');
                INSERT INTO addresses (ROWID, address, comment) VALUES (1, 'kennydu107@gmail.com', 'Kenny');
                INSERT INTO addresses (ROWID, address, comment) VALUES (2, 'ilanazuyev@icloud.com', NULL);
                "#,
            )?;
        }
        {
            let env = SqliteConnection::create_for_test(&env_path)?;
            env.execute_batch(
                r#"
                CREATE TABLE mailboxes (ROWID INTEGER PRIMARY KEY, url TEXT);
                CREATE TABLE messages (
                    ROWID INTEGER PRIMARY KEY,
                    subject INTEGER,
                    sender INTEGER,
                    mailbox INTEGER,
                    date_sent INTEGER,
                    date_received INTEGER,
                    read INTEGER,
                    flagged INTEGER,
                    deleted INTEGER,
                    size INTEGER,
                    conversation_id INTEGER
                );
                CREATE TABLE recipients (ROWID INTEGER PRIMARY KEY, message INTEGER, address INTEGER, type INTEGER, position INTEGER);

                INSERT INTO mailboxes (ROWID, url) VALUES (1, 'imap://acct/INBOX');
                INSERT INTO messages (ROWID, subject, sender, mailbox, date_sent, date_received, read, flagged, deleted, size, conversation_id)
                VALUES (23, 1, 1, 1, 978307200, 978307200, 1, 0, 0, 163320, 5);
                INSERT INTO recipients (ROWID, message, address, type, position) VALUES (1, 23, 2, 1, 0);
                "#,
            )?;
        }

        let parser = IosMailParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(env_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 1);
        let m = &objects[0];
        assert_eq!(m.kind, "mobile.communication.email");
        assert_eq!(m.json["message"]["subject"], "visite du logement");
        assert_eq!(m.json["from"]["address"], "kennydu107@gmail.com");
        assert_eq!(m.json["from"]["name"], "Kenny");
        assert_eq!(m.json["to"][0], "ilanazuyev@icloud.com");
        assert_eq!(m.json["to_display"], "ilanazuyev@icloud.com");
        assert_eq!(m.json["message"]["mailbox"], "imap://acct/INBOX");
        assert_eq!(m.json["message"]["read"], true);
        assert_eq!(m.json["message"]["size"], 163320);
        // Unix-epoch timestamp (NOT Apple absolute).
        assert_eq!(
            m.json["timestamps"]["received"]["rfc3339"],
            "2001-01-01T00:00:00+00:00"
        );

        let events = parser.extract_timeline_events(m);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "mobile.communication.email");
        assert_eq!(events[0].actor.as_deref(), Some("kennydu107@gmail.com"));

        Ok(())
    }
}
