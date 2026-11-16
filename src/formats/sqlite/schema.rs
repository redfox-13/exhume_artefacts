//! Schema inspection and queries that tolerate optional columns.

use super::connection::SqliteConnection;
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub(crate) struct SqliteSchema {
    tables: BTreeMap<String, BTreeSet<String>>,
}

impl SqliteSchema {
    pub(super) fn load(conn: &SqliteConnection) -> Result<Self> {
        let mut table_names = Vec::new();
        conn.query_rows(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name;",
            |row| {
                if let Some(name) = row.text(0) {
                    table_names.push(name);
                }
                Ok(())
            },
        )?;

        let mut tables = BTreeMap::new();
        for table in table_names {
            let mut columns = BTreeSet::new();
            let sql = format!("PRAGMA table_info({});", quote_identifier(&table));
            // Some Apple databases ship FTS/virtual tables backed by proprietary
            // modules or tokenizers (e.g. AddressBook's `ab_cf_tokenizer`) that
            // stock SQLite cannot load. `PRAGMA table_info` on such a table
            // errors; skip it rather than aborting the whole schema load, since
            // parsers only care about the plain data tables.
            let result = conn.query_rows(&sql, |row| {
                if let Some(name) = row.text(1) {
                    columns.insert(name);
                }
                Ok(())
            });
            if let Err(err) = result {
                log::debug!("skipping table {table} during schema load: {err}");
                continue;
            }
            tables.insert(table, columns);
        }

        Ok(Self { tables })
    }

    pub(crate) fn has_table(&self, table: &str) -> bool {
        self.tables.contains_key(table)
    }

    pub(crate) fn has_column(&self, table: &str, column: &str) -> bool {
        self.tables
            .get(table)
            .map(|columns| columns.contains(column))
            .unwrap_or(false)
    }

    pub(crate) fn missing_columns(&self, table: &str, columns: &[&str]) -> Vec<String> {
        columns
            .iter()
            .filter(|column| !self.has_column(table, column))
            .map(|column| format!("{table}.{column}"))
            .collect()
    }
}

pub(crate) fn select_column(
    schema: &SqliteSchema,
    table: &str,
    alias: &str,
    column: &str,
    output_alias: &str,
) -> String {
    if schema.has_column(table, column) {
        format!("{alias}.{column} AS {output_alias}")
    } else {
        format!("NULL AS {output_alias}")
    }
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}
