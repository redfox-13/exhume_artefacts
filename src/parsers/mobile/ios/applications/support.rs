use crate::core::{ParserInput, ParserSource};
use crate::parsers::mobile::sqlite::SqliteEvidence;
use anyhow::{Context, Result};
use plist::Value as Plist;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Cursor, Read, Seek, SeekFrom};

#[derive(Debug, Clone)]
pub(super) struct SourceFileRef {
    pub role: String,
    pub path: String,
    pub artifact_id: Option<i64>,
    pub system_file_id: Option<i64>,
    pub fs_identifier: Option<u64>,
}

impl SourceFileRef {
    fn standalone(path: String) -> Self {
        Self {
            role: "primary".to_string(),
            path,
            artifact_id: None,
            system_file_id: None,
            fs_identifier: None,
        }
    }

    fn from_source(source: &ParserSource) -> Self {
        Self {
            role: source.role.clone(),
            path: source.original_path.clone(),
            artifact_id: source.artifact_id,
            system_file_id: source.system_file_id,
            fs_identifier: source.fs_identifier,
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "role": &self.role,
            "path": &self.path,
            "artifact_id": self.artifact_id,
            "system_file_id": self.system_file_id,
            "fs_identifier": self.fs_identifier,
        })
    }
}

/// Primary bytes and immutable indexed-source provenance for non-SQLite files.
pub(super) struct PrimaryEvidence {
    pub bytes: Vec<u8>,
    pub source_label: String,
    pub source_files: Vec<SourceFileRef>,
}

impl PrimaryEvidence {
    pub fn read(input: ParserInput) -> Result<Self> {
        match input {
            ParserInput::Path(path) => {
                let bytes = fs::read(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                let label = path.display().to_string();
                Ok(Self {
                    bytes,
                    source_label: label.clone(),
                    source_files: vec![SourceFileRef::standalone(label)],
                })
            }
            ParserInput::Bytes(bytes) => Ok(Self {
                bytes,
                source_label: "<in-memory>".to_string(),
                source_files: vec![SourceFileRef::standalone("<in-memory>".to_string())],
            }),
            ParserInput::ReadSeek(mut reader) => {
                let mut bytes = Vec::new();
                reader.seek(SeekFrom::Start(0))?;
                reader.read_to_end(&mut bytes)?;
                Ok(Self {
                    bytes,
                    source_label: "<stream>".to_string(),
                    source_files: vec![SourceFileRef::standalone("<stream>".to_string())],
                })
            }
            ParserInput::Compound(mut compound) => {
                let mut bytes = Vec::new();
                compound
                    .provider
                    .copy_to(&compound.primary, &mut bytes)
                    .context("failed to read primary compound input")?;
                Ok(Self {
                    bytes,
                    source_label: compound.primary.original_path.clone(),
                    source_files: vec![SourceFileRef::from_source(&compound.primary)],
                })
            }
        }
    }

    pub fn source_json(&self, record: &str, index: i64, schema_variant: &str) -> Value {
        json!({
            "path": self.source_label,
            "record": record,
            "index": index,
            "schema_variant": schema_variant,
            "parser_confidence": "compatible_schema",
            "files": self.source_files.iter().map(SourceFileRef::to_json).collect::<Vec<_>>(),
        })
    }
}

pub(super) fn sqlite_source_json(
    evidence: &SqliteEvidence,
    record: &str,
    record_id: i64,
    rowids: &[i64],
    schema_variant: &str,
) -> Value {
    json!({
        "path": evidence.source_label(),
        "table": "application_identifier_tab+kvs+key_tab",
        "record": record,
        "record_id": record_id,
        "rowids": rowids,
        "schema_variant": schema_variant,
        "parser_confidence": "compatible_schema",
        "copied_sidecars": evidence.copied_sidecars(),
        "files": evidence.source_files().iter().map(|file| json!({
            "role": &file.role,
            "path": &file.path,
            "artifact_id": file.artifact_id,
            "system_file_id": file.system_file_id,
            "fs_identifier": file.fs_identifier,
        })).collect::<Vec<_>>(),
    })
}

pub(super) fn parse_plist(bytes: &[u8], label: &str) -> Result<Plist> {
    Plist::from_reader(Cursor::new(bytes))
        .with_context(|| format!("not a valid Apple property list: {label}"))
}

pub(super) fn plist_to_json(value: &Plist) -> Value {
    plist_to_json_at_depth(value, 0)
}

pub(super) fn optional_plist_to_json(value: Option<&Plist>) -> Value {
    value.map(plist_to_json).unwrap_or(Value::Null)
}

fn plist_to_json_at_depth(value: &Plist, depth: usize) -> Value {
    match value {
        Plist::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| plist_to_json_at_depth(value, depth + 1))
                .collect(),
        ),
        Plist::Dictionary(values) => {
            let mut object = Map::new();
            for (key, value) in values {
                object.insert(key.clone(), plist_to_json_at_depth(value, depth + 1));
            }
            Value::Object(object)
        }
        Plist::Boolean(value) => Value::Bool(*value),
        Plist::Data(bytes) => data_to_json(bytes, depth),
        Plist::Date(value) => Value::String(value.to_xml_format()),
        Plist::Real(value) => json!(*value),
        Plist::Integer(value) => value
            .as_signed()
            .map(|value| json!(value))
            .or_else(|| value.as_unsigned().map(|value| json!(value)))
            .unwrap_or(Value::Null),
        Plist::String(value) => Value::String(value.clone()),
        Plist::Uid(value) => json!(value.get()),
        _ => Value::Null,
    }
}

fn data_to_json(bytes: &[u8], depth: usize) -> Value {
    if depth < 8
        && (bytes.starts_with(b"bplist00") || bytes.starts_with(b"<?xml"))
        && let Ok(nested) = Plist::from_reader(Cursor::new(bytes))
    {
        return json!({
            "encoding": "nested_plist",
            "length": bytes.len(),
            "sha256": sha256_hex(bytes),
            "value": plist_to_json_at_depth(&nested, depth + 1),
        });
    }

    let preview_len = bytes.len().min(4096);
    json!({
        "encoding": "hex",
        "length": bytes.len(),
        "sha256": sha256_hex(bytes),
        "data": hex::encode(&bytes[..preview_len]),
        "truncated": preview_len < bytes.len(),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn string(dict: &plist::Dictionary, key: &str) -> Option<String> {
    dict.get(key)
        .and_then(Plist::as_string)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

pub(super) fn integer(value: Option<&Plist>) -> Option<i64> {
    let Plist::Integer(value) = value? else {
        return None;
    };
    value.as_signed().or_else(|| {
        value
            .as_unsigned()
            .and_then(|value| i64::try_from(value).ok())
    })
}

pub(super) fn strings(value: Option<&Plist>) -> Vec<String> {
    value
        .and_then(Plist::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Plist::as_string)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn parent_path(path: &str) -> Option<&str> {
    path.rsplit_once('/').map(|(parent, _)| parent)
}

pub(super) fn final_component(path: &str) -> Option<&str> {
    path.rsplit('/').next().filter(|value| !value.is_empty())
}
