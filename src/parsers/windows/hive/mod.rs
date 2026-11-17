use crate::core::{
    CompanionSpec, ObjectParsed, Parser, ParserContext, ParserInput, ParserInputError, ParserIssue,
};
use crate::{ParserOptionDefault, ParserOptionSpec, ParserOptionType, ParserOptionValue};
use anyhow::{Context, Ok, Result};
use notatin::cell::CellState;
use notatin::cell_key_node::CellKeyNode;
use notatin::cell_key_value::CellKeyValue;
use notatin::parser::Parser as HiveParser;
use notatin::parser_builder::ParserBuilder;
use serde_json::{json, Map, Value};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Seek, SeekFrom};
use std::path::PathBuf;

mod devices;
mod browser_activity;
mod file_operations;
mod network;
mod persistence;
mod program_execution;
mod security;
mod system;
mod user_behavior;

const HIVE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("hive_log", ".LOG"),
    CompanionSpec::optional_suffix("hive_log1", ".LOG1"),
    CompanionSpec::optional_suffix("hive_log2", ".LOG2"),
];

const HIVE_PARSER_OPTIONS: &'static [ParserOptionSpec] = &[
    ParserOptionSpec {
        name: "artefact",
        label: "Artefact",
        description: concat!(
            "Choose one artefact by name. Full artefact names are accepted e.g. 'windows.hive.group.artefact'\n",
            "Current artefact list:",
            "devices.usb",
            ", devices.usbstor",
            ", persistence.appinit",
            ", persistence.appcert_dlls",
            ", persistence.command_processor",
            ", persistence.image_file_execution_options",
            ", persistence.run",
            ", persistence.runonce_ex",
            ", persistence.service",
            ", persistence.session_manager",
            ", persistence.startup_approved",
            ", persistence.task_cache",
            ", persistence.winlogon",
            ", program_execution.amcache",
            ", program_execution.appcompat_cache",
            ", program_execution.bam",
            ", program_execution.dam",
            ", program_execution.syscache",
            ", browser_activity.typed_urls",
            ", file_operations.comdlg32",
            ", file_operations.recent_docs",
            ", file_operations.typed_paths",
            ", user_behavior.feature_usage",
            ", user_behavior.recent_apps",
            ", user_behavior.run_mru",
            ", user_behavior.userassist",
            ", system.computer_name",
            ", system.user_profiles",
            ", system.timezone",
            ", windows_version",
            ", network.network_list",
            ", network.port_proxy",
            ", network.persistent_routes",
            ", security.defender",
            ", security.lsa",
            ", security.uac",
        ),
        value_type: ParserOptionType::String,
        required: false,
        default: None,
    },
    ParserOptionSpec {
        name: "profile",
        label: "Profile",
        description: concat!(
            "Choose a profile (group of artefacts). Available:",
            "devices",
            ", persistence",
            ", program_execution",
            ", browser_activity",
            ", file_operations",
            ", user_behavior",
            ", system",
            ", network",
            ", security."
        ),
        value_type: ParserOptionType::String,
        required: false,
        default: None,
    },
    ParserOptionSpec {
        name: "recover-cells",
        label: "Deleted Cell Recovery",
        description: "Enable or disable the recovery of deleted hive cells (Enabled by default)",
        value_type: ParserOptionType::Boolean,
        required: false,
        default: Some(ParserOptionDefault::Boolean(true)),
    },
];

const HIVE_KIND_PREFIX: &'static str = "windows.hive.";
macro_rules! hive_kind_prefix {
    ($kind:literal) => {
        concat!("windows.hive.", $kind)
    };
}
pub(super) use hive_kind_prefix;

const OBJECT_JSON_DATA: &'static str = "data";
const OBJECT_JSON_METADATA: &'static str = "metadata";
const OBJECT_JSON_SOURCES: &'static str = "sources";
const FILETIME_TO_UNIX_OFFSET_100NS: i128 = 116_444_736_000_000_000;

// ---------------------------------------------------------------------------
// Path segment for trie construction
// ---------------------------------------------------------------------------
#[allow(dead_code)]
pub(crate) enum PathSegment {
    Literal(&'static str),
    Prefix(&'static str),
    Suffix(&'static str),
    Contains(&'static str),
    Any,
}

impl PathSegment {
    fn same(&self, other: &PathSegment) -> bool {
        match (self, other) {
            (Self::Literal(a), Self::Literal(b)) => a.eq_ignore_ascii_case(b),
            (Self::Prefix(a), Self::Prefix(b)) => a.eq_ignore_ascii_case(b),
            (Self::Suffix(a), Self::Suffix(b)) => a.eq_ignore_ascii_case(b),
            (Self::Contains(a), Self::Contains(b)) => a.eq_ignore_ascii_case(b),
            (Self::Any, Self::Any) => true,
            _ => false,
        }
    }

    pub fn matches(&self, name: &str) -> bool {
        match self {
            Self::Literal(string) => string.eq_ignore_ascii_case(name),
            Self::Prefix(prefix) => name
                .get(..prefix.len())
                .map_or(false, |segment| segment.eq_ignore_ascii_case(prefix)),
            Self::Suffix(suffix) => name
                .get(name.len().saturating_sub(suffix.len())..)
                .map_or(false, |segment| segment.eq_ignore_ascii_case(suffix)),
            Self::Contains(string) => {
                string.is_empty()
                    || name
                        .as_bytes()
                        .windows(string.len())
                        .any(|segment| segment.eq_ignore_ascii_case(string.as_bytes()))
            }
            Self::Any => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Output mapping
// ---------------------------------------------------------------------------

pub(super) struct ObjectOutput {
    kind: &'static str,
    metadata: Map<String, Value>,
    sources: Vec<Value>,
    pub text: String,
    pub data: Map<String, Value>,
}

impl ObjectOutput {
    pub(super) fn new(kind: &'static str, cell: &CellKeyNode) -> Self {
        let (ts_unix, ts_unix_ms, ts_rfc3339) = parse_time(cell);
        let mut metadata = Map::new();
        metadata.insert("key_name".into(), json!(cell.key_name));
        metadata.insert("registry_path".into(), json!(cell.get_pretty_path()));
        metadata.insert("last_write_timestamp_rfc3339".into(), json!(ts_rfc3339));
        metadata.insert("last_write_timestamp_unix".into(), json!(ts_unix));
        metadata.insert("last_write_timestamp_unix_ms".into(), json!(ts_unix_ms));
        metadata.insert("key_state".into(), json!(Self::parse_key_state(cell)));
        metadata.insert(
            "raw_value_sources".into(),
            Value::Array(vec![Self::raw_value_source(cell)]),
        );

        Self {
            kind,
            metadata,
            sources: Vec::new(),
            text: String::new(),
            data: Map::new(),
        }
    }

    fn parse_key_state(cell: &CellKeyNode) -> &'static str {
        match cell.cell_state {
            CellState::Allocated => "live",
            CellState::ModifiedTransactionLog => "live_modified_by_log",
            CellState::DeletedPrimaryFile => "deleted_recovered",
            CellState::DeletedPrimaryFileSlack => "deleted_slack",
            CellState::DeletedTransactionLog => "deleted_in_log",
        }
    }

    /// Record a child key that contributed data (combine only).
    pub(super) fn add_source(&mut self, cell: &CellKeyNode) {
        let (_, _, ts_rfc3339) = parse_time(cell);
        self.sources.push(json!({
            "registry_path": cell.get_pretty_path(),
            "last_write_timestamp_rfc3339": ts_rfc3339,
            "key_state": Self::parse_key_state(cell),
        }));
        if let Some(raw_value_sources) = self
            .metadata
            .get_mut("raw_value_sources")
            .and_then(Value::as_array_mut)
        {
            raw_value_sources.push(Self::raw_value_source(cell));
        }
    }

    fn raw_value_source(cell: &CellKeyNode) -> Value {
        json!({
            "registry_path": cell.get_pretty_path(),
            "raw_registry_values": cell.value_iter().map(|value| json!({
                "value_name": value.get_pretty_name(),
                "data_type": format!("{:?}", value.data_type),
                "raw_hex": hex::encode(value.detail.value_bytes().unwrap_or_default()),
            })).collect::<Vec<_>>(),
        })
    }

    pub(super) fn into_output(mut self, parser_name: &'static str) -> ObjectParsed {
        if !self.sources.is_empty() {
            self.metadata
                .insert(OBJECT_JSON_SOURCES.into(), Value::Array(self.sources));
        }
        ObjectParsed {
            parser: parser_name,
            kind: self.kind,
            text: self.text,
            json: json!({
                OBJECT_JSON_DATA: self.data,
                OBJECT_JSON_METADATA: self.metadata,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Trie for path traversal search
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome {
    Keep,
    Skip,
}

type OutputFn = fn(&mut ObjectOutput, &CellKeyNode) -> Outcome;
/// TrieOutput decides what happens to the current output:
/// Emit is used for artefacts that do not require more data
/// Combine is for artefacts that require information from child keys
struct TrieOutput {
    func: OutputFn,
    kind: &'static str,
    output_type: OutputType,
}

enum OutputType {
    Emit,
    Combine,
}

pub(super) struct TrieNode {
    segment: PathSegment,
    children: Vec<TrieNode>,
    outputs: Vec<TrieOutput>,
}

impl TrieNode {
    fn new_internal(segment: PathSegment) -> Self {
        Self {
            segment,
            children: vec![],
            outputs: vec![],
        }
    }

    #[allow(dead_code)]
    pub(super) fn lit(path_literal: &'static str) -> Self {
        Self::new_internal(PathSegment::Literal(path_literal))
    }
    #[allow(dead_code)]
    pub(super) fn pre(path_prefix: &'static str) -> Self {
        Self::new_internal(PathSegment::Prefix(path_prefix))
    }
    #[allow(dead_code)]
    pub(super) fn suf(path_suffix: &'static str) -> Self {
        Self::new_internal(PathSegment::Suffix(path_suffix))
    }
    #[allow(dead_code)]
    pub(super) fn con(path_contains: &'static str) -> Self {
        Self::new_internal(PathSegment::Contains(path_contains))
    }
    #[allow(dead_code)]
    pub(super) fn any() -> Self {
        Self::new_internal(PathSegment::Any)
    }
    ///add subkeys to the current path
    pub(super) fn sub(mut self, children: Vec<TrieNode>) -> Self {
        self.children = children;
        self
    }
    /// create an output from a singular key
    pub(super) fn emit(mut self, kind: &'static str, func: OutputFn) -> Self {
        self.outputs.push(TrieOutput {
            func,
            kind,
            output_type: OutputType::Emit,
        });
        self
    }
    /// create a combined output from a key and its children
    pub(super) fn combine(mut self, kind: &'static str, func: OutputFn) -> Self {
        self.outputs.push(TrieOutput {
            func,
            kind,
            output_type: OutputType::Combine,
        });
        self
    }

    fn add_children(&mut self, children: Vec<TrieNode>) {
        for child in children {
            self.add_child(child);
        }
    }

    fn add_child(&mut self, child: TrieNode) {
        match self
            .children
            .iter_mut()
            .find(|c| c.segment.same(&child.segment))
        {
            Some(existing) => existing.merge(child),
            None => self.children.push(child),
        }
    }

    fn merge(&mut self, other: TrieNode) {
        self.outputs.extend(other.outputs);
        for child in other.children {
            self.add_child(child);
        }
    }
}

struct HivePath<'a> {
    pub cell: CellKeyNode,
    pub node: &'a TrieNode,
    pub roots: Vec<(&'static str, usize)>,
}

// ---------------------------------------------------------------------------
// Artefacts
// ---------------------------------------------------------------------------
#[derive(Clone, Copy)]
pub(super) struct Artefact {
    pub kind: &'static str,
    pub build: fn() -> Vec<TrieNode>,
}

impl Artefact {
    fn all_artefacts() -> Vec<Artefact> {
        Self::profiles()
            .into_iter()
            .flat_map(|(_, artefacts)| artefacts)
            .collect()
    }

    fn str_to_artefact(string: &str) -> Option<Artefact> {
        Self::all_artefacts().into_iter().find(|artefact| {
            if artefact.kind.eq_ignore_ascii_case(string) {
                return true
            }

            artefact.kind
                .strip_prefix(HIVE_KIND_PREFIX)
                .unwrap_or(artefact.kind)
                .eq_ignore_ascii_case(string)
        })
    }

    fn str_to_profile(string: &str) -> Option<Vec<Artefact>> {
        let normalized = string.trim()
            .to_ascii_lowercase()
            .replace('-', "_")
            .replace(' ', "_");

        Self::profiles()
            .into_iter()
            .find(|(name, _)| *name == normalized.as_str())
            .map(|(_, artefacts)| artefacts)
    }

    fn profiles() -> Vec<(&'static str, Vec<Artefact>)> {
        vec![
            ("devices", devices::profile()),
            ("persistence", persistence::profile()),
            ("program_execution", program_execution::profile()),
            ("browser_activity", browser_activity::profile()),
            ("file_operations", file_operations::profile()),
            ("user_behavior", user_behavior::profile()),
            ("system", system::profile()),
            ("network", network::profile()),
            ("security", security::profile()),
        ]
    }
}

// ---------------------------------------------------------------------------
// Shared data parsers (used by the profile files)
// ---------------------------------------------------------------------------

pub(crate) fn parse_values<F, T, O>(cell: &CellKeyNode, format: F) -> T
where
    F: Fn(&CellKeyValue) -> Option<O>,
    T: FromIterator<O>,
{
    cell.value_iter().filter_map(|v| format(&v)).collect()
}

pub(crate) fn value_text(value: &CellKeyValue) -> String {
    let (content, _) = value.get_content();
    if content.get_type() == "Binary" {
        format!(
            "<binary data: {} bytes>",
            value.detail.value_bytes().unwrap_or_default().len()
        )
    } else {
        content.to_string()
    }
}

pub(crate) fn parse_time(cell: &CellKeyNode) -> (i64, i64, String) {
    let filetime = cell.last_key_written_date_and_time();

    (
        filetime.timestamp(),
        filetime.timestamp_millis(),
        filetime.to_rfc3339(),
    )
}

pub(crate) fn filetime_to_rfc3339(filetime: u64) -> Value {
    let unix_100ns = i128::from(filetime) - FILETIME_TO_UNIX_OFFSET_100NS;

    let seconds = unix_100ns.div_euclid(10_000_000);
    let nanos = (unix_100ns.rem_euclid(10_000_000) * 100) as u32;

    let timestamp = i64::try_from(seconds)
        .ok()
        .and_then(|seconds| chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, nanos));

    json!({
        "timestamp_rfc3339": timestamp.map_or(Value::Null, |time| json!(time.to_rfc3339())),
        "timestamp_unix": timestamp.map_or(Value::Null, |time| json!(time.timestamp())),
        "timestamp_unix_ms": timestamp.map_or(Value::Null, |time| json!(time.timestamp_millis())),
    })
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parser implementation for Windows Hive files.
///
/// This type wraps the `notatin` crate and adapts it to the crate's
/// `Parser` trait, emitting one [`ObjectParsed`] per hive artefact found.
pub struct WindowsHiveParser {
    recover_cells: bool,
    artefacts: Vec<Artefact>,
}

impl Default for WindowsHiveParser {
    fn default() -> Self {
        Self {
            recover_cells: true,
            artefacts: Vec::new(),
        }
    }
}

impl WindowsHiveParser {
    fn run_with_parser(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        match input {
            ParserInput::Path(path_buf) => {
                let companion_paths: Vec<PathBuf> = HIVE_COMPANIONS
                    .iter()
                    .filter_map(|companion| {
                        hive_suffix_for_role(companion.role)
                            .map(|suffix| hive_path_with_suffix(&path_buf, suffix))
                    })
                    .collect();
                let mut parser_builder = ParserBuilder::from_path(path_buf);
                parser_builder.recover_deleted(self.recover_cells);
                for companion_path in companion_paths {
                    if companion_path.exists() {
                        parser_builder.with_transaction_log(companion_path);
                    }
                }

                let mut parser = parser_builder
                    .build()
                    .context("Failed to open Hive from given path")?;

                self.default_parse(&mut parser, sink)
            }
            ParserInput::Bytes(items) => {
                let mut parser_builder = ParserBuilder::from_file(Cursor::new(items));
                parser_builder.recover_deleted(self.recover_cells);

                let mut parser = parser_builder
                        .build()
                        .context("Failed to open Hive from byte stream")?;

                self.default_parse(&mut parser, sink)
            }
            ParserInput::ReadSeek(mut read_seek) => {
                let mut hive_file =
                    tempfile::tempfile().context("Failed to create a temporary Hive file")?;
                std::io::copy(&mut read_seek, &mut hive_file)
                    .context("Failed to copy Hive stream to temporary file")?;
                hive_file.seek(SeekFrom::Start(0))?;

                let mut parser_builder = ParserBuilder::from_file(hive_file);
                parser_builder.recover_deleted(self.recover_cells);

                let mut parser = parser_builder
                    .build()
                    .context("Failed to open Hive from read-seek input")?;

                self.default_parse(&mut parser, sink)
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

                let mut parser = parser_builder
                    .build()
                    .context("Failed to open Hive from compound context")?;

                self.default_parse(&mut parser, sink)
            }
        }
    }

    fn default_parse(
        &self,
        parser: &mut HiveParser,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let Some(root_cell) = parser.get_root_key()? else {
            return Ok(());
        };

        let root_trie = self.build_trie();

        let mut seen = HashSet::new();
        let mut combined_objects: HashMap<(usize, &'static str), ObjectOutput> = HashMap::new();

        let mut stack = vec![HivePath {
            cell: root_cell,
            node: &root_trie,
            roots: Vec::new(),
        }];

        while let Some(mut path) = stack.pop() {
            let node = path.node;
            for output in &node.outputs {
                match output.output_type {
                    OutputType::Emit => {
                        let mut object = ObjectOutput::new(output.kind, &path.cell);
                        if (output.func)(&mut object, &path.cell) == Outcome::Keep {
                            sink(object.into_output(self.name()))?;
                        }
                    }
                    OutputType::Combine => {
                        let found = path
                            .roots
                            .iter()
                            .find(|(kind, _)| *kind == output.kind)
                            .map(|(_, offset)| *offset);
                        let root = match found {
                            Some(offset) => offset,
                            None => {
                                let offset = path.cell.file_offset_absolute;
                                path.roots.push((output.kind, offset));
                                offset
                            }
                        };
                        match combined_objects.entry((root, output.kind)) {
                            Entry::Occupied(mut entry) => {
                                let object = entry.get_mut();
                                if (output.func)(object, &path.cell) == Outcome::Keep {
                                    object.add_source(&path.cell);
                                }
                            }
                            Entry::Vacant(entry) => {
                                if found.is_none() {
                                    let mut object = ObjectOutput::new(output.kind, &path.cell);
                                    if (output.func)(&mut object, &path.cell) == Outcome::Keep {
                                        entry.insert(object);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let mut sub_keys = path.cell.read_sub_keys(parser);
            sub_keys.append(&mut path.cell.deleted_keys);

            for sub_key in sub_keys {
                if !seen.insert(sub_key.file_offset_absolute) {
                    continue;
                }
                for trie_node in &node.children {
                    if trie_node.segment.matches(&sub_key.key_name) {
                        stack.push(HivePath {
                            cell: sub_key.clone(),
                            node: trie_node,
                            roots: path.roots.clone(),
                        });
                    }
                }
            }
        }

        for (_, object) in combined_objects {
            sink(object.into_output(self.name()))?
        }

        Ok(())
    }

    fn build_trie(&self) -> TrieNode {
        let mut root = TrieNode::any();
        let artefacts = if self.artefacts.is_empty() {
            Artefact::all_artefacts()
        } else {
            self.artefacts.clone()
        };
        artefacts.into_iter().for_each(|artefact| {
            root.add_children((artefact.build)());
        });
        root
    }

    /// Enable recovery of deleted cells from slack
    /// or transaction logs
    pub fn recover_cells(mut self, v: bool) -> Self {
        self.recover_cells = v;
        self
    }
}

impl Parser for WindowsHiveParser {
    fn name(&self) -> &'static str {
        "windows_hive"
    }

    fn description(&self) -> &'static str {
        "Parse Windows Hive files and emit one JSON object for each selected Artefact"
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        HIVE_COMPANIONS
    }

    fn option_specs(&self) -> &'static [ParserOptionSpec] {
        HIVE_PARSER_OPTIONS
    }

    fn run_into_with_context(
        &self,
        input: ParserInput,
        context: &ParserContext,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
        _diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
    ) -> Result<()> {
        if context.parser_name() != self.name() {
            return Err(
                ParserInputError::invalid("context", "context belongs to a different parser")
                    .into(),
            );
        }

        let artefact_name = match context.option("artefact") {
            Some(ParserOptionValue::String(value)) => value.as_str(),
            None => "",
            _ => {
                return Err(ParserInputError::invalid(
                    "artefact",
                    "expected a string",
                )
                .into());
            }
        };
        let profile_name = match context.option("profile") {
            Some(ParserOptionValue::String(value)) => value.as_str(),
            None => "",
            _ => {
                return Err(ParserInputError::invalid("profile", "expected a string").into());
            }
        };

        let mut artefacts = if profile_name.is_empty() {
            Vec::new()
        } else {
            Artefact::str_to_profile(profile_name).ok_or_else(|| {
                ParserInputError::invalid(
                    "profile",
                    format!(
                        "unknown profile '{profile_name}'; see the profile option description for available profiles"
                    ),
                )
            })?
        };
        
        if !artefact_name.is_empty() {
            let artefact = Artefact::str_to_artefact(artefact_name).ok_or_else(|| {
                ParserInputError::invalid(
                    "artefact",
                    format!(
                        "unknown artefact '{artefact_name}'; see the artefact option description for available artefacts"
                    ),
                )
            })?;
            if !artefacts
                .iter()
                .any(|selected| selected.kind == artefact.kind)
            {
                artefacts.push(artefact);
            }
        }

        let recover_cells = match context.option("recover-cells") {
            Some(ParserOptionValue::Boolean(value)) => *value,
            None => self.recover_cells,
            _ => {
                return Err(
                    ParserInputError::invalid("recover-cells", "expected a boolean").into(),
                );
            }
        };

        let parser = Self {
            recover_cells,
            artefacts,
        };
        parser.run_with_parser(input, sink)
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        self.run_with_parser(input, sink)
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

fn hive_path_with_suffix(path: &PathBuf, suffix: &str) -> PathBuf {
    let mut path = path.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}
