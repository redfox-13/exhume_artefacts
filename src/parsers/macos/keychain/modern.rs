//! Modern `keychain-2.db` (SQLite) metadata extraction.
//!
//! `securityd` stores items across `genp` (generic passwords), `inet`
//! (internet passwords), `cert` (certificates) and `keys` (cryptographic
//! keys). Searchable attributes are columns; the secret is the encrypted `data`
//! column, which we never touch. Timestamps `cdat`/`mdat` are CFAbsoluteTime.

use super::{KEYCHAIN_ITEM_KIND, PARSER_NAME};
use crate::core::ObjectParsed;
use crate::parsers::macos::common::timestamps::apple_absolute_to_json;
use crate::parsers::macos::common::util::sqlite_source_json;
use crate::parsers::mobile::sqlite::{
    SqliteConnection, SqliteEvidence, SqliteSchema, SqliteStatement, select_column,
};
use anyhow::Result;
use serde_json::{Value, json};

const SCHEMA_VARIANT: &str = "macos_keychain2_sqlite_v1";

pub(crate) fn parse(
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let conn = SqliteConnection::open(evidence.path())?;
    let schema = conn.schema()?;

    if schema.has_table("genp") {
        emit_generic(&conn, &schema, evidence, sink)?;
    }
    if schema.has_table("inet") {
        emit_internet(&conn, &schema, evidence, sink)?;
    }
    if schema.has_table("cert") {
        emit_simple(&conn, &schema, evidence, "cert", "certificate", sink)?;
    }
    if schema.has_table("keys") {
        emit_simple(&conn, &schema, evidence, "keys", "key", sink)?;
    }
    Ok(())
}

fn emit_generic(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let sql = format!(
        r#"
        SELECT g.rowid AS rowid, {}, {}, {}, {}, {}, {}, {}, {}, {}
        FROM genp g ORDER BY g.rowid;
        "#,
        select_column(schema, "genp", "g", "svce", "svce"),
        select_column(schema, "genp", "g", "acct", "acct"),
        select_column(schema, "genp", "g", "labl", "labl"),
        select_column(schema, "genp", "g", "desc", "desc"),
        select_column(schema, "genp", "g", "agrp", "agrp"),
        select_column(schema, "genp", "g", "pdmn", "pdmn"),
        select_column(schema, "genp", "g", "cdat", "cdat"),
        select_column(schema, "genp", "g", "mdat", "mdat"),
        select_column(schema, "genp", "g", "tomb", "tomb"),
    );

    conn.query_rows(&sql, |row| {
        let rowid = row.i64(0).unwrap_or_default();
        let service = blob_value(row, 1);
        let account = blob_value(row, 2);
        let text = display_text(&service, &account);
        let json = json!({
            "platform": "macos",
            "app": "keychain",
            "record_type": "keychain_item",
            "format": "keychain-2.db",
            "class": "generic_password",
            "source": sqlite_source_json(evidence, "genp", rowid, SCHEMA_VARIANT),
            "timestamps": {
                "created": apple_absolute_to_json(row.f64(7)),
                "modified": apple_absolute_to_json(row.f64(8)),
            },
            "item": {
                "service": service,
                "account": account,
                "label": blob_value(row, 3),
                "description": blob_value(row, 4),
                "access_group": row.text(5),
                "protection_class": row.text(6),
                "tombstone": row.bool(9),
            },
        });
        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: KEYCHAIN_ITEM_KIND,
            text,
            json,
        })
    })
}

fn emit_internet(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let sql = format!(
        r#"
        SELECT i.rowid AS rowid, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}
        FROM inet i ORDER BY i.rowid;
        "#,
        select_column(schema, "inet", "i", "srvr", "srvr"),
        select_column(schema, "inet", "i", "acct", "acct"),
        select_column(schema, "inet", "i", "labl", "labl"),
        select_column(schema, "inet", "i", "ptcl", "ptcl"),
        select_column(schema, "inet", "i", "port", "port"),
        select_column(schema, "inet", "i", "path", "path"),
        select_column(schema, "inet", "i", "agrp", "agrp"),
        select_column(schema, "inet", "i", "pdmn", "pdmn"),
        select_column(schema, "inet", "i", "cdat", "cdat"),
        select_column(schema, "inet", "i", "mdat", "mdat"),
        select_column(schema, "inet", "i", "tomb", "tomb"),
    );

    conn.query_rows(&sql, |row| {
        let rowid = row.i64(0).unwrap_or_default();
        let server = blob_value(row, 1);
        let account = blob_value(row, 2);
        let text = display_text(&server, &account);
        let json = json!({
            "platform": "macos",
            "app": "keychain",
            "record_type": "keychain_item",
            "format": "keychain-2.db",
            "class": "internet_password",
            "source": sqlite_source_json(evidence, "inet", rowid, SCHEMA_VARIANT),
            "timestamps": {
                "created": apple_absolute_to_json(row.f64(8)),
                "modified": apple_absolute_to_json(row.f64(9)),
            },
            "item": {
                "server": server,
                "account": account,
                "label": blob_value(row, 3),
                "protocol": blob_value(row, 4),
                "port": row.i64(5),
                "path": blob_value(row, 6),
                "access_group": row.text(7),
                "protection_class": row.text(8),
                "tombstone": row.bool(10),
            },
        });
        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: KEYCHAIN_ITEM_KIND,
            text,
            json,
        })
    })
}

/// Certificates and keys: label + access group + timestamps + tombstone.
fn emit_simple(
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    table: &str,
    class: &str,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let sql = format!(
        r#"
        SELECT t.rowid AS rowid, {}, {}, {}, {}, {}
        FROM {table} t ORDER BY t.rowid;
        "#,
        select_column(schema, table, "t", "labl", "labl"),
        select_column(schema, table, "t", "agrp", "agrp"),
        select_column(schema, table, "t", "cdat", "cdat"),
        select_column(schema, table, "t", "mdat", "mdat"),
        select_column(schema, table, "t", "tomb", "tomb"),
    );

    let class = class.to_string();
    conn.query_rows(&sql, |row| {
        let rowid = row.i64(0).unwrap_or_default();
        let label = blob_value(row, 1);
        let text = label
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{class} #{rowid}"));
        let json = json!({
            "platform": "macos",
            "app": "keychain",
            "record_type": "keychain_item",
            "format": "keychain-2.db",
            "class": class,
            "source": sqlite_source_json(evidence, table, rowid, SCHEMA_VARIANT),
            "timestamps": {
                "created": apple_absolute_to_json(row.f64(3)),
                "modified": apple_absolute_to_json(row.f64(4)),
            },
            "item": {
                "label": label,
                "access_group": row.text(2),
                "tombstone": row.bool(5),
            },
        });
        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: KEYCHAIN_ITEM_KIND,
            text,
            json,
        })
    })
}

/// Render a keychain BLOB attribute: as a string if it is valid UTF-8 text,
/// otherwise as `{ hex, len }` so binary account identifiers stay legible.
fn blob_value(row: &SqliteStatement<'_>, index: i32) -> Value {
    match row.blob(index) {
        None => Value::Null,
        Some(bytes) if bytes.is_empty() => Value::Null,
        Some(bytes) => match std::str::from_utf8(&bytes) {
            Ok(text)
                if text
                    .chars()
                    .all(|c| !c.is_control() || c == '\n' || c == '\t') =>
            {
                // Drop a trailing NUL some attributes carry.
                Value::String(text.trim_end_matches('\0').to_string())
            }
            _ => json!({ "hex": hex::encode(&bytes), "len": bytes.len() }),
        },
    }
}

fn display_text(primary: &Value, secondary: &Value) -> String {
    primary
        .as_str()
        .or_else(|| secondary.as_str())
        .unwrap_or("")
        .to_string()
}
