use anyhow::{Context, Ok, Result};
use notatin::cell::{Cell, CellState};
use notatin::cell_key_node::CellKeyNode;
use notatin::cell_key_value::CellKeyValue;
use notatin::parser::{Parser as HiveParser, ParserIterator};
use notatin::parser_builder::ParserBuilder;
use regex::Regex;
use serde_json::{Value, json};
use std::io::{Cursor, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::LazyLock;

use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput};

const HIVE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("hive_log", ".LOG"),
    CompanionSpec::optional_suffix("hive_log1", ".LOG1"),
    CompanionSpec::optional_suffix("hive_log2", ".LOG2"),
];

enum PathSegment {
    Literal(&'static str),
    Pattern(Regex),
    Any,
}

impl PathSegment {
    pub fn matches(&self, name: &str) -> bool {
        match self {
            PathSegment::Literal(string) => string.eq_ignore_ascii_case(name),
            PathSegment::Pattern(regex) => regex.is_match(name),
            PathSegment::Any => true
        }
    }
}

type ArtefactFn = fn(&'static str, &CellKeyNode) -> Option<ObjectParsed>;

struct TrieNode {
    segment: PathSegment,
    children: Vec<TrieNode>,
    outputs: Vec<ArtefactFn>,
}

impl TrieNode {
    fn lit(name: &'static str) -> Self {
        Self { segment: PathSegment::Literal(name), children: vec![], outputs: vec![] }
    }
    fn re(pattern: &str) -> Self {
        Self { segment: PathSegment::Pattern(Regex::new(pattern).unwrap()), children: vec![], outputs: vec![] }
    }
    fn any() -> Self {
        Self { segment: PathSegment::Any, children: vec![], outputs: vec![] }
    }
    fn emit(mut self, f: ArtefactFn) -> Self { self.outputs.push(f); self }
    fn sub(mut self, children: Vec<TrieNode>) -> Self { self.children = children; self }
}

fn parse_values<F, T, O>(cell: &CellKeyNode, format: F) -> T
where
    F: Fn(&CellKeyValue) -> Option<O>,
    T: FromIterator<O>,
{
    cell.value_iter().filter_map(|v| format(&v)).collect()
}

fn parse_time(cell: &CellKeyNode) -> (i64, i64, String) {
    let filetime = cell.last_key_written_date_and_time();

    (filetime.timestamp(), filetime.timestamp_millis(), filetime.to_rfc3339())
}

use TrieNode as T;

static ARTEFACTS: LazyLock<TrieNode> = LazyLock::new(|| {
    T::lit("").sub(vec![
        // --- SOFTWARE ---
        T::lit("Microsoft").sub(vec![
            T::lit("Windows").sub(vec![
                T::lit("CurrentVersion").sub(vec![
                    T::lit("Run").emit(|parser, cell| {
                        let (ts_unix, ts_unix_ms, ts_rfc3339) = parse_time(cell);
                        
                        let programs: Vec<Value> = parse_values(cell, |value| {
                            Some(json!({
                                "program_name": value.get_pretty_name(),
                                "command": value.get_content().0.to_string(),
                            }))
                        });                      

                        Some(ObjectParsed {
                            parser: parser,
                            kind: "windows.hive.autorun.system",
                            text: format!(
                                "PERSISTENT PROGRAMS (AUTO RUN): {}",
                                programs.iter().map(|value| value["program_name"].as_str().unwrap_or(""))
                                .collect::<Vec<&str>>().join(", ")
                            ),
                            json: json!({
                                "registry_path": cell.path,
                                "last_write_timestamp": ts_rfc3339,
                                "last_write_timestamp_unix": ts_unix,
                                "last_write_timestamp_unix_ms": ts_unix_ms,
                                "system_run_programs": programs,
                            }),
                        })
                    }),
                    T::lit("RunOnce").emit(|parser, cell| {
                        let (ts_unix, ts_unix_ms, ts_rfc3339) = parse_time(cell);

                        let programs: Vec<Value> = parse_values(cell, |value| {
                            Some(json!({
                                "program_name": value.get_pretty_name(),
                                "command": value.get_content().0.to_string(),
                            }))
                        });

                        Some(ObjectParsed {
                            parser: parser,
                            kind: "windows.hive.autorun.system",
                            text: format!(
                                "PERSISTENT PROGRAMS (AUTO RUN ONCE): {}",
                                programs.iter().map(|value| value["program_name"].as_str().unwrap_or(""))
                                .collect::<Vec<&str>>().join(", ")
                            ),
                            json: json!({
                                "registry_path": cell.path,
                                "last_write_timestamp": ts_rfc3339,
                                "last_write_timestamp_unix": ts_unix,
                                "last_write_timestamp_unix_ms": ts_unix_ms,
                                "system_run_once_programs": programs,
                            }),
                        })
                    }),
                    T::lit("RunServices").emit(|parser, cell| {
                        let (ts_unix, ts_unix_ms, ts_rfc3339) = parse_time(cell);

                        let services: Vec<Value> = parse_values(cell, |value| {
                            Some(json!({
                                "services_name": value.get_pretty_name(),
                                "command": value.get_content().0.to_string(),
                            }))
                        });

                        Some(ObjectParsed {
                            parser: parser,
                            kind: "windows.hive.autorun.system",
                            text: format!(
                                "PERSISTENT SERVICES (AUTO RUN): {}",
                                services.iter().map(|value| value["program_name"].as_str().unwrap_or(""))
                                .collect::<Vec<&str>>().join(", ")
                            ),
                            json: json!({
                                "registry_path": cell.path,
                                "last_write_timestamp": ts_rfc3339,
                                "last_write_timestamp_unix": ts_unix,
                                "last_write_timestamp_unix_ms": ts_unix_ms,
                                "system_run_services": services,
                            }),
                        })
                    }),
                    T::lit("RunServicesOnce").emit(|parser, cell| {
                        let (ts_unix, ts_unix_ms, ts_rfc3339) = parse_time(cell);

                        let services: Vec<Value> = parse_values(cell, |value| {
                            Some(json!({
                                "service_name": value.get_pretty_name(),
                                "command": value.get_content().0.to_string(),
                            }))
                        });

                        Some(ObjectParsed {
                            parser: parser,
                            kind: "windows.hive.autorun.system",
                            text: format!(
                                "PERSISTENT SERVICES (AUTO RUN ONCE): {}",
                                services.iter().map(|value| value["program_name"].as_str().unwrap_or(""))
                                .collect::<Vec<&str>>().join(", ")
                            ),
                            json: json!({
                                "registry_path": cell.path,
                                "last_write_timestamp": ts_rfc3339,
                                "last_write_timestamp_unix": ts_unix,
                                "last_write_timestamp_unix_ms": ts_unix_ms,
                                "system_run_once_services": services,
                            }),
                        })
                    }),
                ]),
            ]),
        ]),

        
        // --- NTUSER.DAT ---
        T::lit("Software").sub(vec![
            T::lit("Microsoft").sub(vec![
                T::lit("Windows").sub(vec![
                    T::lit("CurrentVersion").sub(vec![
                        T::lit("Run").emit(|parser, cell| {
                            let (ts_unix, ts_unix_ms, ts_rfc3339) = parse_time(cell);
                            
                            let programs: Vec<Value> = parse_values(cell, |value| {
                                Some(json!({
                                    "program_name": value.get_pretty_name(),
                                    "command": value.get_content().0.to_string(),
                                }))
                            });                      

                            Some(ObjectParsed {
                                parser: parser,
                                kind: "windows.hive.autorun.user",
                                text: format!(
                                    "USER PERSISTENT PROGRAMS (USER AUTO RUN): {}",
                                    programs.iter().map(|value| value["program_name"].as_str().unwrap_or(""))
                                    .collect::<Vec<&str>>().join(", ")
                                ),
                                json: json!({
                                    "registry_path": cell.path,
                                    "last_write_timestamp": ts_rfc3339,
                                    "last_write_timestamp_unix": ts_unix,
                                    "last_write_timestamp_unix_ms": ts_unix_ms,
                                    "user_run_programs": programs,
                                }),
                            })
                        }),
                        T::lit("RunOnce").emit(|parser, cell| {
                            let (ts_unix, ts_unix_ms, ts_rfc3339) = parse_time(cell);

                            let programs: Vec<Value> = parse_values(cell, |value| {
                                Some(json!({
                                    "program_name": value.get_pretty_name(),
                                    "command": value.get_content().0.to_string(),
                                }))
                            });

                            Some(ObjectParsed {
                                parser: parser,
                                kind: "windows.hive.autorun.user",
                                text: format!(
                                    "USER PERSISTENT PROGRAMS (USER AUTO RUN ONCE): {}",
                                    programs.iter().map(|value| value["program_name"].as_str().unwrap_or(""))
                                    .collect::<Vec<&str>>().join(", ")
                                ),
                                json: json!({
                                    "registry_path": cell.path,
                                    "last_write_timestamp": ts_rfc3339,
                                    "last_write_timestamp_unix": ts_unix,
                                    "last_write_timestamp_unix_ms": ts_unix_ms,
                                    "user_run_once_programs": programs,
                                }),
                            })
                        }),
                    ]),
                ]),
            ]),
        ]),
    ])
});

/// Parser implementation for Windows Hive files.
///
/// This type wraps the `notatin` crate and adapts it to the crate's
/// `Parser` trait, emitting one [`ObjectParsed`] per hive key and key value.
#[derive(Default)]
pub struct WindowsHiveParser {
    //enable recovery of deleted cells
    recover_cells: bool,
    //only parse known keys with forensic value
    parse_all_keys: bool,
}

impl WindowsHiveParser {
    fn run_with_parser(
        &self,
        parser: &mut HiveParser,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {

        if self.parse_all_keys {
            for cell in ParserIterator::new(&parser) {
                self.parse_cell_full(cell, sink)?
            }
        }

        self.default_parse(parser, sink)
    }

    fn default_parse(
        &self,
        parser: &mut HiveParser,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>
    ) -> Result<()> {
        let Some(root_cell) = parser.get_root_key()? else { return Ok(()) };

        let mut seen = std::collections::HashSet::new();
        let mut candidates: Vec<(CellKeyNode, Vec<&'static TrieNode>)> = vec![(root_cell, vec![&*ARTEFACTS])];

        while let Some((mut parent, nodes)) = candidates.pop() {
            let mut children = parent.read_sub_keys(parser);
            children.append(&mut parent.deleted_keys);

            for cell in children {
                if !seen.insert(cell.file_offset_absolute) { continue; }

                let mut matched: Vec<&'static TrieNode> = Vec::new();

                for node in &nodes {
                    for child in &node.children {
                        if !child.segment.matches(&cell.key_name) { continue; }

                        for output in &child.outputs {
                            if let Some(obj) = output(self.name(), &cell) {
                                sink(obj)?;
                            }
                        }
                        if !child.children.is_empty() {
                            matched.push(child);
                        }
                    }
                }

                if !matched.is_empty() {
                    candidates.push((cell, matched));
                }
            }
        }

        Ok(())
    }

    fn parse_cell_full(
        &self,
        cell: CellKeyNode,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
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
                "last_write_timestamp": ts_rfc3339,
                "last_write_timestamp_unix": ts_unix,
                "last_write_timestamp_unix_ms": ts_unix_ms,
                "is_recovered": cell.has_or_is_recovered(),
                "key_state": key_state,
                "size": cell.detail.size().abs(),
                "subkeys_count": cell.detail.number_of_sub_keys(),
                "values_count": cell.detail.number_of_key_values(),
                "values": values,
                "slack": hex::encode(cell.detail.slack()),
            }),
        })
    }

    /// Enable recovery of deleted cells from slack
    /// or transaction logs
    pub fn recover_cells(mut self, v: bool) -> Self {
        self.recover_cells = v;
        self
    }
    
    /// Enable parse_all_keys to recover information
    /// about all keys in Hive files.
    /// Default behaviour searches for a collection
    /// of know important key values.
    pub fn parse_all_keys(mut self, v: bool) -> Self {
        self.parse_all_keys = v;
        self
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
                    &mut parser_builder
                        .build()
                        .context("Failed to open Hive from Path")?,
                    sink,
                )
            }
            ParserInput::Bytes(items) => {
                let mut parser_builder = ParserBuilder::from_file(Cursor::new(items));
                parser_builder.recover_deleted(self.recover_cells);

                self.run_with_parser(
                    &mut parser_builder
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
                    &mut parser_builder
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
                    &mut parser_builder
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
