use anyhow::{Context, Result};
use notatin::cell::{Cell, CellState};
use notatin::parser::{Parser as HiveParser, ParserIterator};
use notatin::parser_builder::ParserBuilder;
use serde_json::json;
use std::io::{Cursor, Seek, SeekFrom};
use std::path::PathBuf;

use crate::TimelineEvent;
use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput};

const HIVE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("hive_log", ".LOG"),
    CompanionSpec::optional_suffix("hive_log1", ".LOG1"),
    CompanionSpec::optional_suffix("hive_log2", ".LOG2"),
];

/// Parser implementation for Windows Hive files.
///
/// This type wraps the `notatin` crate and adapts it to the crate's
/// `Parser` trait, emitting one [`ObjectParsed`] per hive key and key value.
#[derive(Default)]
pub struct WindowsHiveParser {
    //enable recovery of deleted cells
    recover_cells: bool,
}

impl WindowsHiveParser {
    fn run_with_parser(
        &self,
        parser: HiveParser,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let parser_iter = ParserIterator::new(&parser);

        for cell in parser_iter {
            let filetime = cell.last_key_written_date_and_time();

            let ts_unix: i64 = filetime.timestamp();
            let ts_unix_ms: i64 = filetime.timestamp_millis();
            let ts_rfc3339 = filetime.to_rfc3339();

            let key_state = match cell.cell_state {
                CellState::Allocated => "live",
                CellState::ModifiedTransactionLog => "live_modified_by_log",
                CellState::DeletedPrimaryFile => "deleted_recovered",
                CellState::DeletedPrimaryFileSlack => "deleted_slack",
                CellState::DeletedTransactionLog => "deleted_in_log",
            };

            let values: Vec<_> = cell
                .value_iter()
                .map(|cell_value| {
                    let (value, _) = cell_value.get_content();

                    json!({
                        "value_name": cell_value.detail.value_name(),
                        "data_type": value.get_type(),
                        "data_length": cell_value.detail.size().abs(),
                        "value_decoded": value.to_string(),
                        "value_raw_hex": hex::encode(cell_value.detail.value_bytes().unwrap_or_default()),
                        "data_offset": cell_value.data_offsets_absolute,
                        "slack": hex::encode(cell_value.detail.slack()),
                    })
                })
                .collect();

            sink(ObjectParsed {
                parser: self.name(),
                kind: "windows.hive.key",
                text: format!(
                    "[KEY {}] {} (last modified {})",
                    cell.key_name, cell.path, ts_rfc3339,
                ),
                json: json!({
                    "key_name": cell.key_name,
                    "full_path": cell.path,
                    "signature": cell.detail.signature(),
                    "last_writen_timestamp": ts_rfc3339,
                    "last_writen_timestamp_unix": ts_unix,
                    "last_writen_timestamp_unix_ms": ts_unix_ms,
                    "is_recovered": cell.has_or_is_recovered(),
                    "key_state": key_state,
                    "size": cell.detail.size().abs(),
                    "subkeys_count": cell.detail.number_of_sub_keys(),
                    "values_count": cell.detail.number_of_key_values(),
                    "values": values,
                    "slack": hex::encode(cell.detail.slack()),
                }),
            })?;
        }

        Ok(())
    }
}

impl Parser for WindowsHiveParser {
    fn name(&self) -> &'static str {
        "windows_hive"
    }

    fn description(&self) -> &'static str {
        "Parse Windows Hive files and emit one JSON object for base block data and per hive key."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        HIVE_COMPANIONS
    }

    fn extract_timeline_events(&self, _obj: &ObjectParsed) -> Vec<TimelineEvent> {
        let Some(ts_unix_ms) = _obj.json["timestamp_unix_ms"].as_i64() else {
            return Vec::new();
        };

        let description = match _obj.kind {
            "windows.hive.key" => {
                let key_name = _obj.json["key_name"].as_str().unwrap_or_default();
                let key_path = _obj.json["key_path"].as_str().unwrap_or_default();
                let key_state = _obj.json["key_state"].as_str().unwrap_or_default();

                Some(format!("[KEY {}] {} ({})", key_name, key_path, key_state))
            }
            "windows.hive.value" => {
                let value_name = _obj.json["value_name"].as_str().unwrap_or_default();
                let value_type = _obj.json["value_type"].as_str().unwrap_or_default();
                let value_decoded = _obj.json["value_decoded"].as_str().unwrap_or_default();

                Some(format!(
                    "[KEY VALUE {}] {} ({})",
                    value_name, value_decoded, value_type
                ))
            }
            _ => Option::None,
        };

        vec![TimelineEvent {
            ts_unix_ms,
            event_type: _obj.kind,
            description,
            actor: None,
        }]
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        match input {
            ParserInput::Path(path_buf) => {
                let companion_paths = path_buf.parent().map(|parent_path| {
                    HIVE_COMPANIONS
                        .iter()
                        .map(|companion| {
                            parent_path.join(hive_suffix_for_role(companion.role).unwrap())
                        })
                        .collect::<PathBuf>()
                });

                let mut parser_builder = ParserBuilder::from_path(path_buf);
                parser_builder.recover_deleted(self.recover_cells);

                if let Some(companion_path) = companion_paths {
                    if companion_path.exists() {
                        parser_builder.with_transaction_log(companion_path);
                    }
                }

                self.run_with_parser(
                    parser_builder
                        .build()
                        .context("Failed to open Hive from Path")?,
                    sink,
                )
            }
            ParserInput::Bytes(items) => {
                let mut parser_builder = ParserBuilder::from_file(Cursor::new(items));
                parser_builder.recover_deleted(self.recover_cells);

                self.run_with_parser(
                    parser_builder
                        .build()
                        .context("Failed to open Hive from Compound")?,
                    sink,
                )
            }
            ParserInput::ReadSeek(mut read_seek) => {
                let mut hive_file =
                    tempfile::tempfile().context("Failed to create a temporary Hive file")?;
                std::io::copy(&mut read_seek, &mut hive_file)
                    .context("Failed to copy Hive stream to temporary file")?;

                hive_file.seek(SeekFrom::Start(0))?;

                let mut parser_builder = ParserBuilder::from_file(hive_file);
                parser_builder.recover_deleted(self.recover_cells);

                self.run_with_parser(
                    parser_builder
                        .build()
                        .context("Failed to open Hive from Compound")?,
                    sink,
                )
            }
            ParserInput::Compound(compound) => {
                let mut compound = compound;
                let mut primary =
                    tempfile::tempfile().context("Failed to create a temporary Hive file")?;
                compound.provider.copy_to(&compound.primary, &mut primary)?;
                primary.seek(SeekFrom::Start(0))?;

                let mut parser_builder = ParserBuilder::from_file(primary);
                for companion in compound.companions {
                    if hive_suffix_for_role(&companion.role).is_none() {
                        continue;
                    }

                    let mut sidecar = tempfile::tempfile()
                        .context("Failed to create a temporary Hive LOG file")?;
                    compound.provider.copy_to(&companion, &mut sidecar)?;
                    sidecar.seek(SeekFrom::Start(0))?;

                    parser_builder.with_transaction_log(sidecar);
                }

                self.run_with_parser(
                    parser_builder
                        .build()
                        .context("Failed to open Hive from Compound")?,
                    sink,
                )
            }
        }
    }
}

fn hive_suffix_for_role(role: &str) -> Option<&'static str> {
    match role {
        "hive_log" => Some(".LOG"),
        "hive_log1" => Some(".LOG1"),
        "hive_log2" => Some(".LOG2"),
        _ => None,
    }
}
