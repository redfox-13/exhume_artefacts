//! Small helpers shared by the macOS parsers: string hygiene, URL host
//! extraction and a uniform SQLite provenance block.

use crate::parsers::mobile::sqlite::SqliteEvidence;
use serde_json::{Value, json};

/// Return `None` for `None` or all-whitespace strings, otherwise the original.
pub(crate) fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        if value.trim().is_empty() {
            None
        } else {
            Some(value)
        }
    })
}

/// Extract the host portion of a URL without pulling in a URL-parsing crate.
pub(crate) fn host_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = after_scheme
        .split(['/', '?', '#'])
        .next()?
        .split('@')
        .next_back()?
        .split(':')
        .next()?;
    non_empty(Some(host.to_string()))
}

/// The `files` provenance array describing the primary DB and any copied
/// sidecars, mirroring the shape the mobile parsers emit.
pub(crate) fn source_files_json(evidence: &SqliteEvidence) -> Value {
    Value::Array(
        evidence
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
            .collect(),
    )
}

/// Uniform provenance block for a row emitted from a SQLite-backed artefact.
pub(crate) fn sqlite_source_json(
    evidence: &SqliteEvidence,
    table: &str,
    rowid: i64,
    schema_variant: &str,
) -> Value {
    json!({
        "path": evidence.source_label(),
        "table": table,
        "rowid": rowid,
        "schema_variant": schema_variant,
        "parser_confidence": "compatible_schema",
        "copied_sidecars": evidence.copied_sidecars(),
        "files": source_files_json(evidence),
    })
}
