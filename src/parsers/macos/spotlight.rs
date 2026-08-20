//! macOS Spotlight Store-V2 (`store.db`) parser.
//!
//! Spotlight stores are page-oriented databases.  The current volume-store
//! format (`8tsd`) keeps its metadata schema either in property pages inside
//! the store, or (as modern BootVolume stores do) in sibling `dbStr-*.map`
//! files.  Data pages contain size-prefixed metadata records and are normally
//! compressed as a chain of Apple's `bv41` LZ4 blocks.
//!
//! This parser deliberately treats `store.db` as the primary generation.  Its
//! sibling `.store.db` is a second database generation and should not be fed as
//! a companion; cataloguing both as primaries would duplicate most records.

use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::parsers::macos::common::input::{FileEvidence, FileRef};
use crate::parsers::macos::common::timestamps::{apple_absolute_to_json, firefox_prtime_to_json};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

const PARSER_NAME: &str = "macos_spotlight";
const SCHEMA_VARIANT: &str = "macos_spotlight_store_v2_v1";

const PAGE_ALIGNMENT: usize = 0x1000;
const MAX_BLOCK_SIZE: usize = 16 * 1024 * 1024;
const MAX_DECOMPRESSED_BLOCK: usize = 64 * 1024 * 1024;
const MAX_BLOCK_INDEXES: usize = 1_000_000;
const MAX_PROPERTIES_PER_ITEM: usize = 16_384;

const PROPERTY: u32 = 0x11;
const CATEGORY: u32 = 0x21;
const UNKNOWN_41: u32 = 0x41;
const INDEX: u32 = 0x81;
const METADATA: u32 = 0x09;

const COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_sibling("dbstr1_header", "dbStr-1.map.header"),
    CompanionSpec::optional_sibling("dbstr1_offsets", "dbStr-1.map.offsets"),
    CompanionSpec::optional_sibling("dbstr1_data", "dbStr-1.map.data"),
    CompanionSpec::optional_sibling("dbstr2_header", "dbStr-2.map.header"),
    CompanionSpec::optional_sibling("dbstr2_offsets", "dbStr-2.map.offsets"),
    CompanionSpec::optional_sibling("dbstr2_data", "dbStr-2.map.data"),
    CompanionSpec::optional_sibling("dbstr4_header", "dbStr-4.map.header"),
    CompanionSpec::optional_sibling("dbstr4_offsets", "dbStr-4.map.offsets"),
    CompanionSpec::optional_sibling("dbstr4_data", "dbStr-4.map.data"),
    CompanionSpec::optional_sibling("dbstr5_header", "dbStr-5.map.header"),
    CompanionSpec::optional_sibling("dbstr5_offsets", "dbStr-5.map.offsets"),
    CompanionSpec::optional_sibling("dbstr5_data", "dbStr-5.map.data"),
];

#[derive(Default)]
pub struct MacosSpotlightParser;

impl Parser for MacosSpotlightParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse macOS Spotlight Store-V2 metadata, including modern external dbStr maps and LZ4-compressed item pages."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        COMPANIONS
    }

    fn requires_source_metadata(&self) -> bool {
        true
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        if obj.kind != "macos.spotlight.item" {
            return Vec::new();
        }
        let Some(ts_unix_ms) = obj.json["timestamps"]["updated"]["unix_ms"].as_i64() else {
            return Vec::new();
        };
        let description = obj.json["item"]["path"]
            .as_str()
            .or_else(|| obj.json["item"]["name"].as_str())
            .map(|s| format!("Spotlight indexed {s}"));
        vec![TimelineEvent {
            ts_unix_ms,
            event_type: "macos.spotlight.item_updated",
            description,
            actor: None,
        }]
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = SpotlightEvidence::read(input)?;
        let store = Store::parse(&evidence.primary.bytes, &evidence.companions)?;
        let boot_volume = evidence.primary.source_label.contains("/BootVolume/");
        let mut items = store.parse_items(&evidence.primary.bytes, boot_volume)?;
        populate_paths(&mut items);

        for (index, item) in items.into_iter().enumerate() {
            let name = item.name();
            let text = item
                .path
                .clone()
                .or_else(|| name.clone())
                .unwrap_or_else(|| format!("Spotlight item {}", item.id));
            let json = json!({
                "platform": "macos",
                "app": "spotlight",
                "record_type": "spotlight_item",
                "source": evidence.primary.source_json("metadata_item", index as i64, SCHEMA_VARIANT),
                "store": {
                    "version": store.header.version,
                    "flags": store.header.flags,
                    "original_path": store.header.original_path,
                    "external_definition_maps": store.header.external_maps,
                },
                "timestamps": {
                    // Spotlight stores this as microseconds since the Unix epoch.
                    "updated": firefox_prtime_to_json(i64::try_from(item.date_updated).ok()),
                },
                "item": {
                    "id": item.id,
                    "parent_id": item.parent_id,
                    "item_id": item.item_id,
                    "flags": item.flags,
                    "name": name,
                    "path": item.path,
                },
                "attributes": Value::Object(item.attributes),
            });
            sink(ObjectParsed {
                parser: PARSER_NAME,
                kind: "macos.spotlight.item",
                text,
                json,
            })?;
        }
        Ok(())
    }
}

struct SpotlightEvidence {
    primary: FileEvidence,
    companions: HashMap<String, Vec<u8>>,
}

impl SpotlightEvidence {
    fn read(input: ParserInput) -> Result<Self> {
        match input {
            ParserInput::Path(path) => Self::from_path(&path),
            ParserInput::Compound(mut compound) => {
                let mut primary_bytes = Vec::new();
                compound
                    .provider
                    .copy_to(&compound.primary, &mut primary_bytes)
                    .context("failed to read Spotlight primary")?;
                let mut source_files = vec![FileRef {
                    role: compound.primary.role.clone(),
                    path: compound.primary.original_path.clone(),
                    artifact_id: compound.primary.artifact_id,
                    system_file_id: compound.primary.system_file_id,
                    fs_identifier: compound.primary.fs_identifier,
                }];
                let mut companions = HashMap::new();
                for source in &compound.companions {
                    let mut bytes = Vec::new();
                    compound
                        .provider
                        .copy_to(source, &mut bytes)
                        .with_context(|| {
                            format!("failed to read Spotlight companion {}", source.role)
                        })?;
                    companions.insert(source.role.clone(), bytes);
                    source_files.push(FileRef {
                        role: source.role.clone(),
                        path: source.original_path.clone(),
                        artifact_id: source.artifact_id,
                        system_file_id: source.system_file_id,
                        fs_identifier: source.fs_identifier,
                    });
                }
                Ok(Self {
                    primary: FileEvidence {
                        bytes: primary_bytes,
                        source_label: compound.primary.original_path.clone(),
                        source_files,
                    },
                    companions,
                })
            }
            other => Ok(Self {
                primary: FileEvidence::read_primary(other)?,
                companions: HashMap::new(),
            }),
        }
    }

    fn from_path(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let label = path.display().to_string();
        let mut source_files = vec![FileRef {
            role: "primary".to_string(),
            path: label.clone(),
            artifact_id: None,
            system_file_id: None,
            fs_identifier: None,
        }];
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut companions = HashMap::new();
        for spec in COMPANIONS {
            let crate::core::CompanionPathRule::Sibling(name) = spec.path_rule else {
                continue;
            };
            let sibling = parent.join(name);
            if sibling.is_file() {
                let companion = fs::read(&sibling)
                    .with_context(|| format!("failed to read {}", sibling.display()))?;
                companions.insert(spec.role.to_string(), companion);
                source_files.push(FileRef {
                    role: spec.role.to_string(),
                    path: sibling.display().to_string(),
                    artifact_id: None,
                    system_file_id: None,
                    fs_identifier: None,
                });
            }
        }
        Ok(Self {
            primary: FileEvidence {
                bytes,
                source_label: label,
                source_files,
            },
            companions,
        })
    }
}

#[derive(Debug)]
struct StoreHeader {
    version: u8,
    flags: u32,
    header_size: usize,
    block0_size: usize,
    block_size: usize,
    definition_blocks: [u32; 5],
    original_path: String,
    external_maps: bool,
}

impl StoreHeader {
    fn parse(data: &[u8]) -> Result<Self> {
        ensure!(data.len() >= 0x244, "truncated Spotlight store header");
        let version = match &data[..4] {
            b"8tsd" => 2,
            b"7tsd" => 1,
            _ => bail!("not a Spotlight store.db (expected 7tsd/8tsd signature)"),
        };
        ensure!(
            version == 2,
            "Spotlight Store-V1 is not supported by this parser"
        );
        let flags = le_u32(data, 4)?;
        let header_size = usize::try_from(le_u32(data, 36)?)?;
        let block0_size = usize::try_from(le_u32(data, 40)?)?;
        let block_size = usize::try_from(le_u32(data, 44)?)?;
        ensure!(
            header_size >= 0x244 && header_size <= data.len(),
            "invalid Spotlight header size {header_size}"
        );
        ensure!(
            block0_size >= 20 && block0_size <= MAX_BLOCK_SIZE,
            "invalid Spotlight map size {block0_size}"
        );
        ensure!(
            block_size >= 32 && block_size <= MAX_BLOCK_SIZE,
            "invalid Spotlight page size {block_size}"
        );
        let definition_blocks = [
            le_u32(data, 48)?,
            le_u32(data, 52)?,
            le_u32(data, 56)?,
            le_u32(data, 60)?,
            le_u32(data, 64)?,
        ];
        let original_path = nul_string(&data[0x144..0x244]);
        Ok(Self {
            version,
            flags,
            header_size,
            block0_size,
            block_size,
            definition_blocks,
            original_path,
            external_maps: definition_blocks[0] == 0,
        })
    }
}

#[derive(Debug, Clone)]
struct Property {
    name: String,
    property_type: u8,
    value_type: u8,
}

#[derive(Debug)]
struct Store {
    header: StoreHeader,
    metadata_blocks: Vec<u32>,
    properties: HashMap<u32, Property>,
    categories: HashMap<u32, String>,
    indexes_1: HashMap<u32, Vec<i32>>,
    indexes_2: HashMap<u32, Vec<i32>>,
}

impl Store {
    fn parse(data: &[u8], companions: &HashMap<String, Vec<u8>>) -> Result<Self> {
        let header = StoreHeader::parse(data)?;
        let metadata_blocks = parse_block_map(data, &header)?;
        let mut store = Self {
            header,
            metadata_blocks,
            properties: HashMap::new(),
            categories: HashMap::new(),
            indexes_1: HashMap::new(),
            indexes_2: HashMap::new(),
        };
        if store.header.external_maps {
            store.parse_external_maps(companions)?;
        } else {
            store.parse_internal_definitions(data)?;
        }
        ensure!(
            !store.properties.is_empty(),
            "Spotlight store has no decoded property definitions"
        );
        Ok(store)
    }

    fn parse_external_maps(&mut self, files: &HashMap<String, Vec<u8>>) -> Result<()> {
        self.properties = parse_external_properties(
            required(files, "dbstr1_data")?,
            required(files, "dbstr1_offsets")?,
            required(files, "dbstr1_header")?,
        )?;
        self.categories = parse_external_categories(
            required(files, "dbstr2_data")?,
            required(files, "dbstr2_offsets")?,
            required(files, "dbstr2_header")?,
        )?;
        // Index maps are useful for list/category references but not required
        // to recover scalar strings, IDs, dates, and sizes.  Modern stores
        // normally provide both; tolerate their absence and preserve numeric
        // references instead of dropping the whole store.
        if let (Some(data), Some(offsets), Some(header)) = (
            files.get("dbstr4_data"),
            files.get("dbstr4_offsets"),
            files.get("dbstr4_header"),
        ) {
            self.indexes_1 = parse_external_indexes(data, offsets, header, false)?;
        }
        if let (Some(data), Some(offsets), Some(header)) = (
            files.get("dbstr5_data"),
            files.get("dbstr5_offsets"),
            files.get("dbstr5_header"),
        ) {
            self.indexes_2 = parse_external_indexes(data, offsets, header, true)?;
        }
        Ok(())
    }

    fn parse_internal_definitions(&mut self, data: &[u8]) -> Result<()> {
        let defs = self.header.definition_blocks;
        parse_definition_chain(data, self.header.block_size, defs[0], PROPERTY, |page| {
            parse_property_page(page, &mut self.properties)
        })?;
        parse_definition_chain(data, self.header.block_size, defs[1], CATEGORY, |page| {
            parse_category_page(page, &mut self.categories)
        })?;
        if defs[3] != 0 {
            parse_definition_chain(data, self.header.block_size, defs[3], INDEX, |page| {
                parse_index_page(page, &mut self.indexes_1)
            })?;
        }
        if defs[4] != 0 {
            parse_definition_chain(data, self.header.block_size, defs[4], INDEX, |page| {
                parse_index_page(page, &mut self.indexes_2)
            })?;
        }
        if defs[2] != 0 {
            parse_definition_chain(
                data,
                self.header.block_size,
                defs[2],
                UNKNOWN_41,
                |_| Ok(()),
            )?;
        }
        Ok(())
    }

    fn parse_items(&self, data: &[u8], boot_volume: bool) -> Result<Vec<Item>> {
        let mut items = Vec::new();
        for &block_index in &self.metadata_blocks {
            let Some(page) = page_at(data, block_index, self.header.block_size) else {
                continue;
            };
            let Ok(block) = StoreBlock::parse(page) else {
                continue;
            };
            if block.block_type & 0xff != METADATA {
                continue;
            }
            let Ok(uncompressed) = decompress_metadata_page(page, &block) else {
                // Best effort: one damaged/unsupported page must not discard
                // records recovered from the other hundreds of pages.
                continue;
            };
            let mut pos = 0usize;
            while pos + 4 <= uncompressed.len() {
                let size = usize::try_from(le_u32(&uncompressed, pos)?)?;
                pos += 4;
                if size == 0 || size == u32::MAX as usize {
                    break;
                }
                let Some(record) = uncompressed.get(pos..pos.saturating_add(size)) else {
                    break;
                };
                if let Ok(mut item) = self.parse_item(record) {
                    if boot_volume && item.id != 1 {
                        item.id = item.id.swap_bytes();
                        item.parent_id = item.parent_id.swap_bytes();
                    }
                    items.push(item);
                }
                pos += size;
            }
        }
        Ok(items)
    }

    fn parse_item(&self, record: &[u8]) -> Result<Item> {
        let mut cursor = Cursor::new(record);
        let id = cursor.var()?;
        let flags = cursor.u8()?;
        let item_id = cursor.var()?;
        let parent_id = cursor.var()?;
        let date_updated = cursor.var()?;
        let mut property_index = 0u32;
        let mut attributes = Map::new();

        for _ in 0..MAX_PROPERTIES_PER_ITEM {
            if cursor.remaining() == 0 {
                break;
            }
            let skip = cursor.var()?;
            if skip == 0 || skip == u32::MAX as u64 {
                break;
            }
            let skip = u32::try_from(skip).context("Spotlight property index overflow")?;
            property_index = property_index
                .checked_add(skip)
                .context("Spotlight property index overflow")?;
            let property = self
                .properties
                .get(&property_index)
                .with_context(|| format!("unknown Spotlight property index {property_index}"))?;
            let value = self.decode_value(&mut cursor, property)?;
            attributes.insert(property.name.clone(), value);
        }
        Ok(Item {
            id,
            flags,
            item_id,
            parent_id,
            date_updated,
            attributes,
            path: None,
        })
    }

    fn decode_value(&self, cursor: &mut Cursor<'_>, property: &Property) -> Result<Value> {
        let multi = property.property_type & 2 != 0;
        Ok(match property.value_type {
            0 | 2 | 6 => json!(cursor.var()?),
            7 => {
                if multi {
                    let descriptor = signed_var(cursor.var()?);
                    ensure!(descriptor >= 0, "negative Spotlight array descriptor");
                    let count = usize::try_from(descriptor >> 3)?;
                    ensure!(
                        count <= MAX_PROPERTIES_PER_ITEM,
                        "oversized Spotlight integer list"
                    );
                    Value::Array(
                        (0..count)
                            .map(|_| cursor.var().map(|v| json!(signed_var(v))))
                            .collect::<Result<Vec<_>>>()?,
                    )
                } else {
                    json!(signed_var(cursor.var()?))
                }
            }
            8 => {
                if multi {
                    Value::Array(
                        (0..4)
                            .map(|_| cursor.var().map(|v| json!(v)))
                            .collect::<Result<Vec<_>>>()?,
                    )
                } else {
                    json!(cursor.var()?)
                }
            }
            9 => decode_fixed_array(cursor, multi, 4, |c| c.f32().map(|v| json!(v)))?,
            10 => decode_fixed_array(cursor, multi, 8, |c| c.f64().map(|v| json!(v)))?,
            11 => {
                let strings = cursor.strings()?;
                if multi || strings.len() != 1 {
                    json!(strings)
                } else {
                    json!(strings.into_iter().next().unwrap_or_default())
                }
            }
            12 => {
                if multi {
                    let bytes = usize::try_from(cursor.var()?)?;
                    ensure!(bytes % 8 == 0, "invalid Spotlight date-array size");
                    let count = bytes / 8;
                    ensure!(
                        count <= MAX_PROPERTIES_PER_ITEM,
                        "oversized Spotlight date list"
                    );
                    Value::Array(
                        (0..count)
                            .map(|_| cursor.f64().map(|v| apple_absolute_to_json(Some(v))))
                            .collect::<Result<Vec<_>>>()?,
                    )
                } else {
                    apple_absolute_to_json(Some(cursor.f64()?))
                }
            }
            14 => {
                let length = usize::try_from(cursor.var()?)?;
                let bytes = cursor.take(length)?;
                if property.name == "kMDStoreUUID" {
                    json!(hex::encode(bytes))
                } else if let Ok(text) = std::str::from_utf8(bytes) {
                    json!(trim_localization(text.trim_end_matches('\0')))
                } else {
                    json!({ "hex": hex::encode(bytes), "len": bytes.len() })
                }
            }
            15 => {
                let reference = signed_var(cursor.var()?);
                self.resolve_reference(reference, property.property_type)
            }
            other => bail!(
                "unsupported Spotlight value type 0x{other:02x} for {}",
                property.name
            ),
        })
    }

    fn resolve_reference(&self, reference: i64, property_type: u8) -> Value {
        if reference < 0 {
            return Value::Null;
        }
        let reference = reference as u32;
        if property_type & 3 == 3 {
            let Some(indexes) = self.indexes_2.get(&reference) else {
                return json!({ "unresolved_category_list": reference });
            };
            for &index in indexes {
                if index >= 0 {
                    if let Some(value) = self.categories.get(&(index as u32)) {
                        return json!(trim_localization(value));
                    }
                }
            }
            Value::Null
        } else if property_type & 2 != 0 {
            let Some(indexes) = self.indexes_1.get(&reference) else {
                return json!({ "unresolved_category_list": reference });
            };
            Value::Array(
                indexes
                    .iter()
                    .filter_map(|&index| {
                        (index >= 0)
                            .then(|| self.categories.get(&(index as u32)))
                            .flatten()
                            .map(|s| json!(trim_localization(s)))
                    })
                    .collect(),
            )
        } else {
            self.categories
                .get(&reference)
                .map(|s| json!(trim_localization(s)))
                .unwrap_or_else(|| json!({ "unresolved_category": reference }))
        }
    }
}

#[derive(Debug)]
struct Item {
    id: u64,
    flags: u8,
    item_id: u64,
    parent_id: u64,
    date_updated: u64,
    attributes: Map<String, Value>,
    path: Option<String>,
}

impl Item {
    fn name(&self) -> Option<String> {
        for key in ["_kMDItemFileName", "kMDItemDisplayName", "kMDItemTitle"] {
            match self.attributes.get(key) {
                Some(Value::String(value)) if !value.is_empty() => return Some(value.clone()),
                Some(Value::Array(values)) => {
                    if let Some(value) = values.iter().find_map(Value::as_str) {
                        return Some(value.to_string());
                    }
                }
                _ => {}
            }
        }
        None
    }
}

fn populate_paths(items: &mut [Item]) {
    let parents: HashMap<u64, (u64, Option<String>)> = items
        .iter()
        .map(|item| (item.id, (item.parent_id, item.name())))
        .collect();
    for item in items {
        item.path = resolve_path(item.id, &parents);
    }
}

fn resolve_path(id: u64, items: &HashMap<u64, (u64, Option<String>)>) -> Option<String> {
    if id == 1 {
        return Some("plist".to_string());
    }
    let mut current = id;
    let mut parts = Vec::new();
    let mut seen = HashSet::new();
    for _ in 0..256 {
        if current == 2 {
            break;
        }
        if !seen.insert(current) {
            return None;
        }
        let (parent, name) = items.get(&current)?;
        if let Some(name) = name {
            if !name.is_empty() && name != "/" {
                parts.push(name.clone());
            }
        }
        current = if *parent == 0 { 2 } else { *parent };
    }
    if current != 2 {
        return None;
    }
    parts.reverse();
    Some(format!("/{}", parts.join("/")))
}

fn parse_block_map(data: &[u8], header: &StoreHeader) -> Result<Vec<u32>> {
    let end = header
        .header_size
        .checked_add(header.block0_size)
        .context("Spotlight map range overflow")?;
    let map = data
        .get(header.header_size..end)
        .context("truncated Spotlight block map")?;
    ensure!(
        map.starts_with(b"1mbd") || map.starts_with(b"2mbd"),
        "invalid Spotlight block-map signature"
    );
    let count = usize::try_from(le_u32(map, 8)?)?;
    ensure!(count <= MAX_BLOCK_INDEXES, "oversized Spotlight block map");
    ensure!(
        20 + count * 16 <= map.len(),
        "truncated Spotlight block indexes"
    );
    let mut indexes = Vec::with_capacity(count);
    for index in 0..count {
        let offset = 20 + index * 16;
        let block = le_u32(map, offset + 8)?;
        let file_offset = usize::try_from(block)?
            .checked_mul(PAGE_ALIGNMENT)
            .context("Spotlight page offset overflow")?;
        if file_offset < data.len() {
            indexes.push(block);
        }
    }
    Ok(indexes)
}

#[derive(Debug)]
struct StoreBlock {
    logical_size: usize,
    block_type: u32,
    uncompressed_size: usize,
    next_block: u32,
}

impl StoreBlock {
    fn parse(page: &[u8]) -> Result<Self> {
        ensure!(
            page.len() >= 32 && page.starts_with(b"2pbd"),
            "invalid Spotlight page"
        );
        let physical_size = usize::try_from(le_u32(page, 4)?)?;
        let logical_size = usize::try_from(le_u32(page, 8)?)?;
        ensure!(physical_size >= 32, "invalid Spotlight physical page size");
        ensure!(
            logical_size >= 20 && logical_size <= page.len(),
            "invalid Spotlight logical page size"
        );
        Ok(Self {
            logical_size,
            block_type: le_u32(page, 12)?,
            uncompressed_size: usize::try_from(le_u32(page, 16)?)?,
            next_block: le_u32(page, 20)?,
        })
    }
}

fn parse_definition_chain(
    data: &[u8],
    block_size: usize,
    initial: u32,
    expected_type: u32,
    mut parse: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    ensure!(
        initial != 0,
        "missing Spotlight definition page type 0x{expected_type:x}"
    );
    let mut current = initial;
    let mut visited = HashSet::new();
    while current != 0 {
        ensure!(
            visited.insert(current),
            "cycle in Spotlight definition pages"
        );
        ensure!(
            visited.len() <= MAX_BLOCK_INDEXES,
            "oversized Spotlight definition chain"
        );
        let page =
            page_at(data, current, block_size).context("truncated Spotlight definition page")?;
        let block = StoreBlock::parse(page)?;
        ensure!(
            block.block_type == expected_type,
            "unexpected Spotlight definition page type"
        );
        parse(&page[..block.logical_size])?;
        current = block.next_block;
    }
    Ok(())
}

fn parse_property_page(page: &[u8], properties: &mut HashMap<u32, Property>) -> Result<()> {
    let mut pos = 32usize;
    while pos + 6 <= page.len() {
        let index = le_u32(page, pos)?;
        let value_type = page[pos + 4];
        let property_type = page[pos + 5];
        pos += 6;
        let (name, consumed) = read_nul_string(&page[pos..])?;
        pos += consumed;
        if index == 0 || name.is_empty() {
            break;
        }
        properties.insert(
            index,
            Property {
                name,
                property_type,
                value_type,
            },
        );
    }
    Ok(())
}

fn parse_category_page(page: &[u8], categories: &mut HashMap<u32, String>) -> Result<()> {
    let mut pos = 32usize;
    while pos + 4 <= page.len() {
        let index = le_u32(page, pos)?;
        pos += 4;
        let (name, consumed) = read_nul_string(&page[pos..])?;
        pos += consumed;
        if index == 0 || name.is_empty() {
            break;
        }
        categories.insert(index, name);
    }
    Ok(())
}

fn parse_index_page(page: &[u8], indexes: &mut HashMap<u32, Vec<i32>>) -> Result<()> {
    let mut cursor = Cursor::at(page, 32)?;
    while cursor.remaining() >= 4 {
        let index = cursor.u32()?;
        if index == 0 {
            break;
        }
        let byte_count = usize::try_from(cursor.var()?)?;
        let padding = byte_count % 4;
        cursor.take(padding)?;
        let aligned = byte_count - padding;
        ensure!(
            aligned / 4 <= MAX_PROPERTIES_PER_ITEM,
            "oversized Spotlight index"
        );
        let mut values = Vec::with_capacity(aligned / 4);
        for _ in 0..aligned / 4 {
            values.push(cursor.i32()?);
        }
        indexes.insert(index, values);
    }
    Ok(())
}

fn parse_external_properties(
    data: &[u8],
    offsets: &[u8],
    header: &[u8],
) -> Result<HashMap<u32, Property>> {
    validate_map_header(header)?;
    let mut properties = HashMap::new();
    for (index, offset) in map_offsets(offsets)? {
        let mut cursor = Cursor::at(data, offset)?;
        let entry_size = usize::try_from(cursor.var()?)?;
        let entry_end = cursor
            .pos
            .checked_add(entry_size)
            .context("Spotlight map entry overflow")?
            .min(data.len());
        let value_type = cursor.u8()?;
        let property_type = cursor.u8()?;
        let name = nul_string(cursor.data.get(cursor.pos..entry_end).unwrap_or_default());
        if !name.is_empty() {
            properties.insert(
                index,
                Property {
                    name,
                    property_type,
                    value_type,
                },
            );
        }
    }
    Ok(properties)
}

fn parse_external_categories(
    data: &[u8],
    offsets: &[u8],
    header: &[u8],
) -> Result<HashMap<u32, String>> {
    validate_map_header(header)?;
    let mut categories = HashMap::new();
    for (index, offset) in map_offsets(offsets)? {
        let mut cursor = Cursor::at(data, offset)?;
        let entry_size = usize::try_from(cursor.var()?)?;
        let bytes = cursor.take(entry_size)?;
        let name = nul_string(bytes);
        if !name.is_empty() {
            categories.insert(index, name);
        }
    }
    Ok(categories)
}

fn parse_external_indexes(
    data: &[u8],
    offsets: &[u8],
    header: &[u8],
    extra_byte: bool,
) -> Result<HashMap<u32, Vec<i32>>> {
    validate_map_header(header)?;
    let mut indexes = HashMap::new();
    for (index, offset) in map_offsets(offsets)? {
        let mut cursor = Cursor::at(data, offset)?;
        let _entry_size = cursor.leb128()?;
        let byte_count = usize::try_from(cursor.var()?)?;
        if extra_byte {
            cursor.u8()?;
        }
        let count = byte_count / 4;
        ensure!(
            count <= MAX_PROPERTIES_PER_ITEM,
            "oversized external Spotlight index"
        );
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(cursor.i32()?);
        }
        indexes.insert(index, values);
    }
    Ok(indexes)
}

fn validate_map_header(header: &[u8]) -> Result<()> {
    ensure!(header.len() >= 56, "truncated dbStr map header");
    ensure!(
        &header[..8] == b"\0PataD\0\0",
        "invalid dbStr map header signature"
    );
    Ok(())
}

fn map_offsets(data: &[u8]) -> Result<Vec<(u32, usize)>> {
    ensure!(data.len() >= 4, "truncated dbStr offsets file");
    let mut result = Vec::new();
    let mut index = 1u32;
    let mut pos = 4usize;
    while pos + 4 <= data.len() {
        let offset = le_u32(data, pos)?;
        if offset == 0 {
            break;
        }
        if offset != 1 {
            result.push((index, usize::try_from(offset)?));
        }
        index = index.checked_add(1).context("dbStr index overflow")?;
        pos += 4;
    }
    Ok(result)
}

fn required<'a>(files: &'a HashMap<String, Vec<u8>>, role: &str) -> Result<&'a [u8]> {
    files
        .get(role)
        .map(Vec::as_slice)
        .with_context(|| format!("modern Spotlight store requires companion role {role}"))
}

fn page_at(data: &[u8], block: u32, block_size: usize) -> Option<&[u8]> {
    let offset = usize::try_from(block).ok()?.checked_mul(PAGE_ALIGNMENT)?;
    data.get(offset..offset.checked_add(block_size)?)
}

fn decompress_metadata_page(page: &[u8], block: &StoreBlock) -> Result<Vec<u8>> {
    let payload = page
        .get(20..block.logical_size)
        .context("truncated Spotlight metadata page")?;
    if block.block_type & 0x1000 != 0 {
        if payload.starts_with(b"bv41") || payload.starts_with(b"bv4-") {
            decode_lz4_chunks(payload)
        } else {
            let expected = block.uncompressed_size.saturating_sub(20);
            decode_lz4_block(payload, expected, &[])
        }
    } else if block.block_type & 0x2000 != 0 {
        if payload.starts_with(b"bvx-") {
            let size = usize::try_from(le_u32(payload, 4)?)?;
            Ok(payload
                .get(8..8 + size)
                .context("truncated bvx- block")?
                .to_vec())
        } else {
            let expected = payload
                .get(4..8)
                .map(|_| le_u32(payload, 4))
                .transpose()?
                .unwrap_or(0);
            decode_apple_compression(
                payload,
                usize::try_from(expected)?,
                CompressionAlgorithm::Lzfse,
            )
        }
    } else {
        decode_apple_compression(
            payload,
            block.uncompressed_size.saturating_sub(20),
            CompressionAlgorithm::Zlib,
        )
    }
}

fn decode_lz4_chunks(data: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0usize;
    let mut output = Vec::new();
    let mut dictionary = Vec::new();
    while pos + 4 <= data.len() {
        match &data[pos..pos + 4] {
            b"bv41" => {
                ensure!(pos + 12 <= data.len(), "truncated bv41 header");
                let uncompressed = usize::try_from(le_u32(data, pos + 4)?)?;
                let compressed = usize::try_from(le_u32(data, pos + 8)?)?;
                ensure!(
                    uncompressed <= MAX_DECOMPRESSED_BLOCK,
                    "oversized bv41 block"
                );
                let payload = data
                    .get(pos + 12..pos + 12 + compressed)
                    .context("truncated bv41 payload")?;
                let decoded = decode_lz4_block(payload, uncompressed, &dictionary)?;
                dictionary = decoded[decoded.len().saturating_sub(65_535)..].to_vec();
                output.extend_from_slice(&decoded);
                ensure!(
                    output.len() <= MAX_DECOMPRESSED_BLOCK,
                    "oversized Spotlight metadata page"
                );
                pos += 12 + compressed;
            }
            b"bv4-" => {
                ensure!(pos + 8 <= data.len(), "truncated bv4- header");
                let size = usize::try_from(le_u32(data, pos + 4)?)?;
                let payload = data
                    .get(pos + 8..pos + 8 + size)
                    .context("truncated bv4- payload")?;
                output.extend_from_slice(payload);
                dictionary = payload[payload.len().saturating_sub(65_535)..].to_vec();
                ensure!(
                    output.len() <= MAX_DECOMPRESSED_BLOCK,
                    "oversized Spotlight metadata page"
                );
                pos += 8 + size;
            }
            b"bv4$" | b"\0\0\0\0" => break,
            marker => bail!("unknown Spotlight LZ4 marker {:02x?}", marker),
        }
    }
    Ok(output)
}

/// Decode a raw LZ4 block. `dictionary` is the preceding bv41 chunk (up to
/// 64 KiB), which Apple uses for dependent chunks.
fn decode_lz4_block(data: &[u8], expected: usize, dictionary: &[u8]) -> Result<Vec<u8>> {
    ensure!(expected <= MAX_DECOMPRESSED_BLOCK, "oversized LZ4 output");
    let mut input = 0usize;
    let mut output = Vec::with_capacity(expected);
    while input < data.len() {
        let token = data[input];
        input += 1;
        let literal_length = extended_lz4_length(data, &mut input, usize::from(token >> 4))?;
        let literals = data
            .get(input..input + literal_length)
            .context("truncated LZ4 literals")?;
        output.extend_from_slice(literals);
        input += literal_length;
        if input == data.len() {
            break;
        }
        ensure!(input + 2 <= data.len(), "truncated LZ4 match offset");
        let offset = usize::from(u16::from_le_bytes([data[input], data[input + 1]]));
        input += 2;
        ensure!(
            offset != 0 && offset <= dictionary.len() + output.len(),
            "invalid LZ4 match offset"
        );
        let match_length = extended_lz4_length(data, &mut input, usize::from(token & 0x0f))? + 4;
        ensure!(
            output.len() + match_length <= MAX_DECOMPRESSED_BLOCK,
            "oversized LZ4 match"
        );
        for _ in 0..match_length {
            let source = dictionary.len() + output.len() - offset;
            let byte = if source < dictionary.len() {
                dictionary[source]
            } else {
                output[source - dictionary.len()]
            };
            output.push(byte);
        }
    }
    ensure!(
        expected == 0 || output.len() == expected,
        "LZ4 size mismatch: got {}, expected {expected}",
        output.len()
    );
    Ok(output)
}

fn extended_lz4_length(data: &[u8], input: &mut usize, initial: usize) -> Result<usize> {
    let mut length = initial;
    if initial == 15 {
        loop {
            let byte = *data.get(*input).context("truncated LZ4 length")?;
            *input += 1;
            length = length
                .checked_add(usize::from(byte))
                .context("LZ4 length overflow")?;
            if byte != 255 {
                break;
            }
        }
    }
    Ok(length)
}

enum CompressionAlgorithm {
    Zlib,
    Lzfse,
}

#[cfg(target_os = "macos")]
fn decode_apple_compression(
    data: &[u8],
    expected: usize,
    algorithm: CompressionAlgorithm,
) -> Result<Vec<u8>> {
    const COMPRESSION_ZLIB: u32 = 0x205;
    const COMPRESSION_LZFSE: u32 = 0x801;
    #[link(name = "compression")]
    unsafe extern "C" {
        fn compression_decode_buffer(
            dst: *mut u8,
            dst_size: usize,
            src: *const u8,
            src_size: usize,
            scratch: *mut std::ffi::c_void,
            algorithm: u32,
        ) -> usize;
    }
    let algorithm = match algorithm {
        CompressionAlgorithm::Zlib => COMPRESSION_ZLIB,
        CompressionAlgorithm::Lzfse => COMPRESSION_LZFSE,
    };
    let mut capacity = expected.max(64 * 1024).min(MAX_DECOMPRESSED_BLOCK);
    loop {
        let mut output = vec![0u8; capacity];
        // SAFETY: both buffers are valid for their advertised sizes and the
        // Compression framework writes only to `output`.
        let written = unsafe {
            compression_decode_buffer(
                output.as_mut_ptr(),
                output.len(),
                data.as_ptr(),
                data.len(),
                std::ptr::null_mut(),
                algorithm,
            )
        };
        if written > 0 && (written < capacity || written == expected) {
            output.truncate(written);
            return Ok(output);
        }
        if capacity == MAX_DECOMPRESSED_BLOCK {
            bail!("Apple Compression framework could not decode Spotlight page");
        }
        capacity = (capacity * 2).min(MAX_DECOMPRESSED_BLOCK);
    }
}

#[cfg(not(target_os = "macos"))]
fn decode_apple_compression(
    _data: &[u8],
    _expected: usize,
    algorithm: CompressionAlgorithm,
) -> Result<Vec<u8>> {
    let name = match algorithm {
        CompressionAlgorithm::Zlib => "zlib",
        CompressionAlgorithm::Lzfse => "LZFSE",
    };
    bail!("Spotlight {name} decoding currently requires Apple's Compression framework")
}

fn decode_fixed_array(
    cursor: &mut Cursor<'_>,
    multi: bool,
    element_size: usize,
    mut read: impl FnMut(&mut Cursor<'_>) -> Result<Value>,
) -> Result<Value> {
    if !multi {
        return read(cursor);
    }
    let bytes = usize::try_from(cursor.var()?)?;
    ensure!(
        bytes % element_size == 0,
        "invalid Spotlight fixed-array size"
    );
    let count = bytes / element_size;
    ensure!(
        count <= MAX_PROPERTIES_PER_ITEM,
        "oversized Spotlight fixed array"
    );
    Ok(Value::Array(
        (0..count)
            .map(|_| read(cursor))
            .collect::<Result<Vec<_>>>()?,
    ))
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn at(data: &'a [u8], pos: usize) -> Result<Self> {
        ensure!(pos <= data.len(), "cursor outside Spotlight data");
        Ok(Self { data, pos })
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(size)
            .context("Spotlight cursor overflow")?;
        let bytes = self
            .data
            .get(self.pos..end)
            .context("truncated Spotlight value")?;
        self.pos = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    fn f32(&mut self) -> Result<f32> {
        Ok(f32::from_bits(self.u32()?))
    }

    fn f64(&mut self) -> Result<f64> {
        let b = self.take(8)?;
        Ok(f64::from_le_bytes(b.try_into().expect("8-byte slice")))
    }

    fn var(&mut self) -> Result<u64> {
        let first = self.u8()?;
        if first == 0 {
            return Ok(0);
        }
        let (extra, lower_nibble, adjusted) = if first & 0xf0 == 0xf0 {
            if first & 0x0f == 0x0f {
                (8, false, first)
            } else if first & 0x0e == 0x0e {
                (7, false, first)
            } else if first & 0x0c == 0x0c {
                (6, false, first)
            } else if first & 0x08 == 0x08 {
                (5, false, first)
            } else {
                (4, true, first - 0xf0)
            }
        } else if first & 0xe0 == 0xe0 {
            (3, true, first - 0xe0)
        } else if first & 0xc0 == 0xc0 {
            (2, true, first - 0xc0)
        } else if first & 0x80 == 0x80 {
            (1, true, first - 0x80)
        } else {
            return Ok(u64::from(first));
        };
        let bytes = self.take(extra)?;
        let mut value = if lower_nibble {
            u64::from(adjusted) << (extra * 8)
        } else {
            0
        };
        for (index, byte) in bytes.iter().enumerate() {
            value |= u64::from(*byte) << ((extra - index - 1) * 8);
        }
        Ok(value)
    }

    fn leb128(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..=63).step_by(7) {
            let byte = self.u8()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        bail!("oversized Spotlight LEB128 value")
    }

    fn strings(&mut self) -> Result<Vec<String>> {
        let size = usize::try_from(self.var()?)?;
        let bytes = self.take(size)?;
        Ok(bytes
            .split(|b| *b == 0)
            .filter(|part| !part.is_empty())
            .map(|part| trim_localization(&String::from_utf8_lossy(part)).to_string())
            .collect())
    }
}

fn signed_var(value: u64) -> i64 {
    (value as u32 as i32) as i64
}

fn le_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .context("truncated little-endian u32")?;
    Ok(u32::from_le_bytes(bytes.try_into().expect("4-byte slice")))
}

fn read_nul_string(data: &[u8]) -> Result<(String, usize)> {
    let end = data
        .iter()
        .position(|b| *b == 0)
        .context("unterminated Spotlight string")?;
    Ok((String::from_utf8_lossy(&data[..end]).into_owned(), end + 1))
}

fn nul_string(data: &[u8]) -> String {
    let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

fn trim_localization(value: &str) -> &str {
    value.split('\u{16}').next().unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_spotlight_variable_integers() -> Result<()> {
        for value in [0, 1, 0x7f, 0x80, 0x1234, 0x12_3456, 1_700_000_000_000_000] {
            let encoded = encode_var(value);
            let mut cursor = Cursor::new(&encoded);
            assert_eq!(cursor.var()?, value);
            assert_eq!(cursor.remaining(), 0);
        }
        Ok(())
    }

    #[test]
    fn decodes_lz4_literals_and_overlap() -> Result<()> {
        // "abc" as literals, followed by a 6-byte match at offset 3 -> abcabcabc.
        let compressed = [0x32, b'a', b'b', b'c', 0x03, 0x00];
        assert_eq!(decode_lz4_block(&compressed, 9, &[])?, b"abcabcabc");
        Ok(())
    }

    #[test]
    fn parses_synthetic_store_v2() -> Result<()> {
        let bytes = synthetic_store();
        let parser = MacosSpotlightParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Bytes(bytes), &mut |object| {
            objects.push(object);
            Ok(())
        })?;
        assert_eq!(objects.len(), 1);
        let item = &objects[0];
        assert_eq!(item.kind, "macos.spotlight.item");
        assert_eq!(item.json["item"]["id"], 42);
        assert_eq!(item.json["item"]["path"], "/report.txt");
        assert_eq!(item.json["attributes"]["_kMDItemFileName"], "report.txt");
        assert_eq!(item.json["attributes"]["kMDItemContentType"], "public.text");
        assert!(item.json["attributes"]["kMDItemContentModificationDate"]["unix_ms"].is_i64());
        assert_eq!(parser.extract_timeline_events(item).len(), 1);
        Ok(())
    }

    fn synthetic_store() -> Vec<u8> {
        let block_size = 0x1000usize;
        let mut data = vec![0u8; block_size * 7];
        data[..4].copy_from_slice(b"8tsd");
        put_u32(&mut data, 4, 1);
        put_u32(&mut data, 36, block_size as u32);
        put_u32(&mut data, 40, block_size as u32);
        put_u32(&mut data, 44, block_size as u32);
        for (offset, block) in [(48, 2), (52, 3), (56, 0), (60, 4), (64, 5)] {
            put_u32(&mut data, offset, block);
        }
        data[0x144..0x14a].copy_from_slice(b"/test\0");

        let map = block_size;
        data[map..map + 4].copy_from_slice(b"2mbd");
        put_u32(&mut data, map + 4, block_size as u32);
        put_u32(&mut data, map + 8, 1);
        put_u32(&mut data, map + 20 + 8, 6);
        put_u32(&mut data, map + 20 + 12, block_size as u32);

        let mut properties = Vec::new();
        property(&mut properties, 1, 11, 0, "_kMDItemFileName");
        property(&mut properties, 2, 15, 0, "kMDItemContentType");
        property(&mut properties, 3, 12, 0, "kMDItemContentModificationDate");
        definition_page(&mut data, 2, PROPERTY, &properties);

        let mut categories = Vec::new();
        categories.extend_from_slice(&1u32.to_le_bytes());
        categories.extend_from_slice(b"public.text\0");
        definition_page(&mut data, 3, CATEGORY, &categories);
        definition_page(&mut data, 4, INDEX, &[]);
        definition_page(&mut data, 5, INDEX, &[]);

        let mut record = Vec::new();
        record.extend_from_slice(&encode_var(42));
        record.push(0x10);
        record.extend_from_slice(&encode_var(7));
        record.extend_from_slice(&encode_var(2));
        record.extend_from_slice(&encode_var(1_700_000_000_000_000));
        record.extend_from_slice(&encode_var(1));
        record.extend_from_slice(&encode_var(11));
        record.extend_from_slice(b"report.txt\0");
        record.extend_from_slice(&encode_var(1));
        record.extend_from_slice(&encode_var(1));
        record.extend_from_slice(&encode_var(1));
        record.extend_from_slice(&700_000_000f64.to_le_bytes());
        let mut records = Vec::new();
        records.extend_from_slice(&(record.len() as u32).to_le_bytes());
        records.extend_from_slice(&record);

        let page = block_size * 6;
        data[page..page + 4].copy_from_slice(b"2pbd");
        put_u32(&mut data, page + 4, block_size as u32);
        put_u32(&mut data, page + 12, 0x1000 | METADATA);
        let mut payload = Vec::new();
        payload.extend_from_slice(b"bv4-");
        payload.extend_from_slice(&(records.len() as u32).to_le_bytes());
        payload.extend_from_slice(&records);
        payload.extend_from_slice(b"bv4$");
        put_u32(&mut data, page + 8, (20 + payload.len()) as u32);
        put_u32(&mut data, page + 16, (20 + records.len()) as u32);
        data[page + 20..page + 20 + payload.len()].copy_from_slice(&payload);
        data
    }

    fn property(output: &mut Vec<u8>, index: u32, value_type: u8, property_type: u8, name: &str) {
        output.extend_from_slice(&index.to_le_bytes());
        output.push(value_type);
        output.push(property_type);
        output.extend_from_slice(name.as_bytes());
        output.push(0);
    }

    fn definition_page(data: &mut [u8], block: usize, block_type: u32, payload: &[u8]) {
        let offset = block * PAGE_ALIGNMENT;
        data[offset..offset + 4].copy_from_slice(b"2pbd");
        put_u32(data, offset + 4, PAGE_ALIGNMENT as u32);
        put_u32(data, offset + 8, (32 + payload.len()) as u32);
        put_u32(data, offset + 12, block_type);
        data[offset + 32..offset + 32 + payload.len()].copy_from_slice(payload);
    }

    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn encode_var(value: u64) -> Vec<u8> {
        if value < 0x80 {
            return vec![value as u8];
        }
        let bytes = ((64 - value.leading_zeros() as usize) + 7) / 8;
        match bytes {
            1 => vec![0x80, value as u8],
            2 => vec![0xc0, (value >> 8) as u8, value as u8],
            3 => vec![0xe0, (value >> 16) as u8, (value >> 8) as u8, value as u8],
            4 => {
                let mut out = vec![0xf0];
                out.extend_from_slice(&(value as u32).to_be_bytes());
                out
            }
            5 => {
                let mut out = vec![0xf8];
                out.extend_from_slice(&value.to_be_bytes()[3..]);
                out
            }
            6 => {
                let mut out = vec![0xfc];
                out.extend_from_slice(&value.to_be_bytes()[2..]);
                out
            }
            7 => {
                let mut out = vec![0xfe];
                out.extend_from_slice(&value.to_be_bytes()[1..]);
                out
            }
            _ => {
                let mut out = vec![0xff];
                out.extend_from_slice(&value.to_be_bytes());
                out
            }
        }
    }
}
