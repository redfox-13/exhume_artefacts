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
use serde_json::{Map, Value, json};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Seek, SeekFrom};
use std::path::PathBuf;

mod browser_activity;
mod devices;
mod file_operations;
mod network;
mod persistence;
mod program_execution;
mod profiles;
mod security;
mod sysinfo;
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
            "Choose one artefact by name. Full artefact names are accepted e.g. 'windows.hive.group.artefact'. Available:",
            "devices.usb",
            ", devices.usbstor",
            ", devices.volume_mappings",
            ", devices.readyboost_history",
            ", devices.audio_endpoints",
            ", devices.portable_devices",
            ", devices.printers",
            ", persistence.appinit",
            ", persistence.appcert_dlls",
            ", persistence.command_processor",
            ", persistence.com_registration",
            ", persistence.image_file_execution_options",
            ", persistence.print_components",
            ", persistence.run",
            ", persistence.runonce_ex",
            ", persistence.service",
            ", persistence.session_manager",
            ", persistence.startup_approved",
            ", persistence.task_cache",
            ", persistence.winlogon",
            ", persistence.netsh_helpers",
            ", persistence.shell_overlay_handlers",
            ", persistence.wsh_settings",
            ", persistence.windows_address_book",
            ", persistence.file_type_commands",
            ", persistence.exefile_associations",
            ", program_execution.amcache",
            ", program_execution.app_paths",
            ", program_execution.appcompat_cache",
            ", program_execution.appcompat_flags",
            ", program_execution.bam",
            ", program_execution.dam",
            ", program_execution.mui_cache",
            ", program_execution.syscache",
            ", program_execution.uninstall",
            ", program_execution.heap_leak_detection",
            ", program_execution.msi_products",
            ", program_execution.drivers32",
            ", browser_activity.typed_urls",
            ", browser_activity.security_zones",
            ", browser_activity.outlook_webview",
            ", file_operations.comdlg32",
            ", file_operations.recent_docs",
            ", file_operations.shellbags",
            ", file_operations.typed_paths",
            ", file_operations.recent_document_controls",
            ", user_behavior.feature_usage",
            ", user_behavior.recent_apps",
            ", user_behavior.run_mru",
            ", user_behavior.userassist",
            ", user_behavior.wordwheel_query",
            ", user_behavior.last_logged_on",
            ", user_behavior.app_keys",
            ", user_behavior.this_pc_policy",
            ", sysinfo.computer_name",
            ", sysinfo.user_profiles",
            ", sysinfo.timezone",
            ", sysinfo.windows_version",
            ", sysinfo.wbem",
            ", sysinfo.spp_clients",
            ", sysinfo.scheduling_agent",
            ", sysinfo.wow64_configuration",
            ", sysinfo.windows_update_client",
            ", sysinfo.display_calibration",
            ", network.network_list",
            ", network.interfaces",
            ", network.mapped_drives",
            ", network.port_proxy",
            ", network.proxy_settings",
            ", network.persistent_routes",
            ", network.group_policy_settings",
            ", security.defender",
            ", security.lsa",
            ", security.sam_accounts",
            ", security.sam_aliases",
            ", security.uac",
            ", security.security_center",
            ", security.powershell_execution_policy",
            ", security.file_handler_overrides",
        ),
        value_type: ParserOptionType::String,
        required: false,
        default: None,
    },
    ParserOptionSpec {
        name: "profile",
        label: "Profile",
        description: concat!(
            "Choose a profile (group of artefacts). Available: ",
            "system",
            ", software",
            ", sam",
            ", ntuser",
            ", default",
            ", usrclass",
            ", amcache",
            ", syscache",
            ", devices",
            ", persistence",
            ", program_execution",
            ", browser_activity",
            ", file_operations",
            ", user_behavior",
            ", sysinfo",
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

// ---------------------------------------------------------------------------
// Path segment for trie construction
// ---------------------------------------------------------------------------
#[allow(dead_code)]
#[derive(PartialEq, Eq, Hash)]
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
    include_raw_value_sources: bool,
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
            include_raw_value_sources: true,
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
        if self.include_raw_value_sources {
            if let Some(raw_value_sources) = self
                .metadata
                .get_mut("raw_value_sources")
                .and_then(Value::as_array_mut)
            {
                raw_value_sources.push(Self::raw_value_source(cell));
            }
        }
    }

    pub(super) fn omit_raw_value_sources(&mut self) {
        self.include_raw_value_sources = false;
        self.metadata.remove("raw_value_sources");
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
        profiles::all_artefacts()
    }

    fn str_to_artefact(string: &str) -> Option<Artefact> {
        Self::all_artefacts().into_iter().find(|artefact| {
            if artefact.kind.eq_ignore_ascii_case(string) {
                return true;
            }

            let kind = artefact
                .kind
                .strip_prefix(HIVE_KIND_PREFIX)
                .unwrap_or(artefact.kind)
                .to_owned();
            
            kind.eq_ignore_ascii_case(string)
        })
    }

    fn str_to_profile(string: &str) -> Option<Vec<Artefact>> {
        profiles::profile(string)
    }
}

// ---------------------------------------------------------------------------
// Shared data parsers (used by the profile files)
// ---------------------------------------------------------------------------

pub(crate) fn parse_value_map<F>(cell: &CellKeyNode, format: F) -> Map<String, Value>
where
    F: Fn(&CellKeyValue) -> Option<(String, Value)>,
{
    let mut values: HashMap<String, Vec<Value>> = HashMap::new();
    for value in cell.value_iter() {
        if let Some((name, data)) = format(&value) {
            values.entry(name).or_default().push(data);
        }
    }

    values
        .into_iter()
        .map(|(name, mut data)| {
            let value = if data.len() == 1 {
                data.remove(0)
            } else {
                Value::Array(data)
            };
            (name, value)
        })
        .collect()
}

pub(crate) fn registry_value_map(cell: &CellKeyNode) -> Map<String, Value> {
    parse_value_map(cell, |value| {
        Some((value.get_pretty_name(), json!(value_text(value))))
    })
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
                for trie_node in &node.children {
                    if trie_node.segment.matches(&sub_key.key_name) {
                        let visit = (
                            sub_key.file_offset_absolute,
                            std::ptr::from_ref(trie_node),
                        );
                        if !seen.insert(visit) {
                            continue;
                        }
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
            return Err(ParserInputError::invalid(
                "context",
                "context belongs to a different parser",
            )
            .into());
        }

        let artefact_name = match context.option("artefact") {
            Some(ParserOptionValue::String(value)) => value.as_str(),
            None => "",
            _ => {
                return Err(ParserInputError::invalid("artefact", "expected a string").into());
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
