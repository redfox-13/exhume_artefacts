//! Materialize database evidence and sidecars while retaining source metadata.

use crate::core::{CompoundParserInput, ParserFileProvider, ParserInput, ParserSource};
use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub(crate) struct SqliteEvidence {
    _tempdir: TempDir,
    path: PathBuf,
    source_label: String,
    copied_sidecars: Vec<String>,
    source_files: Vec<SqliteSourceFile>,
}

#[derive(Debug, Clone)]
pub(crate) struct SqliteSourceFile {
    pub(crate) role: String,
    pub(crate) path: String,
    pub(crate) artifact_id: Option<i64>,
    pub(crate) system_file_id: Option<i64>,
    pub(crate) fs_identifier: Option<u64>,
}

impl SqliteEvidence {
    pub(crate) fn from_input(input: ParserInput, filename: &str) -> Result<Self> {
        let tempdir = tempfile::tempdir().context("failed to create temporary SQLite directory")?;
        let path = tempdir.path().join(filename);
        let mut source_label = "<in-memory>".to_string();
        let mut copied_sidecars = Vec::new();
        let mut source_files = Vec::new();

        match input {
            ParserInput::Path(source) => {
                fs::copy(&source, &path).with_context(|| {
                    format!("failed to copy SQLite database from {}", source.display())
                })?;
                source_label = source.display().to_string();
                source_files.push(SqliteSourceFile {
                    role: "primary".to_string(),
                    path: source_label.clone(),
                    artifact_id: None,
                    system_file_id: None,
                    fs_identifier: None,
                });

                for suffix in ["-wal", "-shm"] {
                    let sidecar = append_suffix(&source, suffix)?;
                    if sidecar.exists() {
                        let target = append_suffix(&path, suffix)?;
                        fs::copy(&sidecar, &target).with_context(|| {
                            format!("failed to copy SQLite sidecar {}", sidecar.display())
                        })?;
                        copied_sidecars.push(suffix.trim_start_matches('-').to_string());
                        source_files.push(SqliteSourceFile {
                            role: sqlite_role_for_suffix(suffix).to_string(),
                            path: sidecar.display().to_string(),
                            artifact_id: None,
                            system_file_id: None,
                            fs_identifier: None,
                        });
                    }
                }
            }
            ParserInput::Bytes(bytes) => {
                fs::write(&path, bytes).context("failed to write SQLite bytes to temp file")?;
                source_files.push(SqliteSourceFile {
                    role: "primary".to_string(),
                    path: source_label.clone(),
                    artifact_id: None,
                    system_file_id: None,
                    fs_identifier: None,
                });
            }
            ParserInput::ReadSeek(mut reader) => {
                let mut bytes = Vec::new();
                reader.seek(SeekFrom::Start(0))?;
                reader.read_to_end(&mut bytes)?;
                fs::write(&path, bytes).context("failed to write SQLite stream to temp file")?;
                source_files.push(SqliteSourceFile {
                    role: "primary".to_string(),
                    path: source_label.clone(),
                    artifact_id: None,
                    system_file_id: None,
                    fs_identifier: None,
                });
            }
            ParserInput::Compound(compound) => {
                source_label = compound.primary.original_path.clone();
                write_compound_sqlite(compound, &path, &mut copied_sidecars, &mut source_files)?;
            }
        }

        Ok(Self {
            _tempdir: tempdir,
            path,
            source_label,
            copied_sidecars,
            source_files,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn source_label(&self) -> String {
        self.source_label.clone()
    }

    pub(crate) fn copied_sidecars(&self) -> &[String] {
        &self.copied_sidecars
    }

    pub(crate) fn source_files(&self) -> &[SqliteSourceFile] {
        &self.source_files
    }
}

fn write_compound_sqlite(
    mut compound: CompoundParserInput,
    path: &Path,
    copied_sidecars: &mut Vec<String>,
    source_files: &mut Vec<SqliteSourceFile>,
) -> Result<()> {
    let primary = compound.primary.clone();
    copy_source_to_path(&mut *compound.provider, &primary, path)?;
    source_files.push(source_file_from_parser_source(&primary));

    for companion in compound.companions {
        let Some(suffix) = sqlite_suffix_for_role(&companion.role) else {
            continue;
        };
        let target = append_suffix(path, suffix)?;
        copy_source_to_path(&mut *compound.provider, &companion, &target)?;
        copied_sidecars.push(suffix.trim_start_matches('-').to_string());
        source_files.push(source_file_from_parser_source(&companion));
    }

    Ok(())
}

fn copy_source_to_path(
    provider: &mut dyn ParserFileProvider,
    source: &ParserSource,
    path: &Path,
) -> Result<()> {
    let mut file = fs::File::create(path)
        .with_context(|| format!("failed to create SQLite temp file {}", path.display()))?;
    provider.copy_to(source, &mut file)?;
    Ok(())
}

fn source_file_from_parser_source(source: &ParserSource) -> SqliteSourceFile {
    SqliteSourceFile {
        role: source.role.clone(),
        path: source.original_path.clone(),
        artifact_id: source.artifact_id,
        system_file_id: source.system_file_id,
        fs_identifier: source.fs_identifier,
    }
}

fn sqlite_suffix_for_role(role: &str) -> Option<&'static str> {
    match role {
        "sqlite_wal" => Some("-wal"),
        "sqlite_shm" => Some("-shm"),
        _ => None,
    }
}

fn sqlite_role_for_suffix(suffix: &str) -> &'static str {
    match suffix {
        "-wal" => "sqlite_wal",
        "-shm" => "sqlite_shm",
        _ => "sqlite_companion",
    }
}

fn append_suffix(path: &Path, suffix: &str) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("SQLite path has no file name: {}", path.display()))?;
    let mut sidecar_name = file_name.to_os_string();
    sidecar_name.push(suffix);
    Ok(path.with_file_name(sidecar_name))
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
