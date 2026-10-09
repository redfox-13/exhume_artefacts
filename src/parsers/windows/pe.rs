//! Windows Portable Executable (PE) Parser
//!
//! This module provides functionality for parsing and analyzing Windows PE files,
//! extracting metadata, sections, imports, exports, rich headers, and more.

use crate::core::{ObjectParsed, Parser, ParserInput};
use anyhow::{Context, Result};
use goblin::pe::PE;
use md5;
use scroll::Pread;
use serde_json::json;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek}; // <- add Read because you call read_to_end

/// A parser for Windows Portable Executable (PE) files.
///
/// This parser uses the `goblin` crate to extract detailed information useful for
/// malware analysis and forensic investigations.
#[derive(Default)]
pub struct WindowsPeParser;

impl WindowsPeParser {
    /// Calculates the Shannon entropy of a byte slice.
    ///
    /// Entropy is used to detect packed or encrypted sections in PE files.
    /// Returns a value between 0.0 (no entropy) and 8.0 (max entropy).
    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut counts = [0usize; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        let mut entropy = 0.0;
        let len = data.len() as f64;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Calculates the "imphash" (Import Hash) of a PE file.
    ///
    /// The imphash is a MD5 hash of the lowercased, comma-separated list of imported
    /// functions and their respective DLLs (without extensions). It is commonly used
    /// to cluster related malware samples based on their import patterns.
    fn calculate_imphash(pe: &PE) -> String {
        let mut imphash_data = Vec::new();
        for import in &pe.imports {
            let dll = import.dll.to_lowercase();
            let dll = if dll.ends_with(".dll") || dll.ends_with(".sys") || dll.ends_with(".ocx") {
                &dll[..dll.len() - 4]
            } else {
                &dll
            };
            let func = import.name.to_lowercase();
            imphash_data.push(format!("{}.{}", dll, func));
        }
        let imphash_str = imphash_data.join(",");
        let digest = md5::compute(imphash_str.as_bytes());
        format!("{:x}", digest)
    }

    /// Parses the "Rich Header" from a PE file if present.
    ///
    /// The Rich Header is an undocumented header found in PE files compiled with
    /// Microsoft Visual Studio. It contains information about the build tools and
    /// versions used to create the binary.
    fn parse_rich_header(data: &[u8], pe: &PE) -> Option<serde_json::Value> {
        // In this goblin version, DOS header field is typically `pe_pointer` (not `lfanew`)
        let nt_offset = pe.header.dos_header.pe_pointer as usize;
        if nt_offset == 0 || nt_offset > data.len() {
            return None;
        }

        let search_range = &data[..nt_offset];

        let rich_index = search_range.windows(4).position(|w| w == b"Rich")?;
        if rich_index + 8 > search_range.len() {
            return None;
        }

        let xor_key_bytes = &search_range[rich_index + 4..rich_index + 8];
        let xor_key = u32::from_le_bytes(xor_key_bytes.try_into().ok()?);

        let dans_signature = 0x536e6144 ^ xor_key; // "DanS" ^ key
        let mut entries = Vec::new();

        let mut current_offset = rich_index;
        while current_offset >= 8 {
            current_offset -= 8;

            let entry_xor: u32 = search_range.pread_with(current_offset, scroll::LE).ok()?;
            let count_xor: u32 = search_range
                .pread_with(current_offset + 4, scroll::LE)
                .ok()?;

            if entry_xor == dans_signature {
                break;
            }

            let entry = entry_xor ^ xor_key;
            let count = count_xor ^ xor_key;

            let product_id = (entry >> 16) as u16;
            let build_id = (entry & 0xFFFF) as u16;

            entries.push(json!({
                "product_id": product_id,
                "build_id": build_id,
                "count": count
            }));
        }

        Some(json!({
            "xor_key": format!("0x{:08x}", xor_key),
            "entries": entries
        }))
    }
}

impl Parser for WindowsPeParser {
    /// Returns the unique name of the parser.
    fn name(&self) -> &'static str {
        "windows_pe"
    }

    /// Returns a brief description of what this parser does.
    fn description(&self) -> &'static str {
        "Extract comprehensive information from Windows PE files for malware analysis."
    }

    /// Executes the parser on the provided input and sends results to the sink.
    ///
    /// Supported input types:
    /// - `ParserInput::Path`: Reads from a file on disk.
    /// - `ParserInput::Bytes`: Parses from an in-memory byte slice.
    /// - `ParserInput::ReadSeek`: Reads and seeks from a generic stream.
    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let data = match input {
            ParserInput::Path(p) => std::fs::read(p)?,
            ParserInput::Bytes(b) => b,
            ParserInput::ReadSeek(mut rs) => {
                let mut b = Vec::new();
                rs.seek(std::io::SeekFrom::Start(0))?;
                rs.read_to_end(&mut b)?;
                b
            }
            ParserInput::Compound(_) => {
                anyhow::bail!("windows_pe does not support compound parser input")
            }
        };

        let pe = PE::parse(&data).context("failed to parse PE file")?;

        let md5_hash = format!("{:x}", md5::compute(&data));

        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(&data);
        let sha256_hash = hex::encode(sha256_hasher.finalize());

        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(&data);
        let sha1_hash = hex::encode(sha1_hasher.finalize());

        let imphash = Self::calculate_imphash(&pe);
        let rich_header = Self::parse_rich_header(&data, &pe);

        let sections: Vec<serde_json::Value> = pe
            .sections
            .iter()
            .map(|s| {
                let name = s.name().unwrap_or("");

                let start = s.pointer_to_raw_data as usize;
                let end = ((s.pointer_to_raw_data + s.size_of_raw_data) as usize).min(data.len());
                let section_data = if start < end { &data[start..end] } else { &[] };

                let entropy = Self::calculate_entropy(section_data);

                json!({
                    "name": name,
                    "virtual_address": format!("0x{:x}", s.virtual_address),
                    "virtual_size": format!("0x{:x}", s.virtual_size),
                    "raw_size": format!("0x{:x}", s.size_of_raw_data),
                    "raw_pointer": format!("0x{:x}", s.pointer_to_raw_data),
                    "characteristics": format!("0x{:08x}", s.characteristics),
                    "entropy": entropy
                })
            })
            .collect();

        let imports: Vec<serde_json::Value> = pe
            .imports
            .iter()
            .map(|i| {
                json!({
                    "dll": i.dll,
                    "name": i.name.to_string(),
                    "offset": i.offset,
                    "rva": i.rva
                })
            })
            .collect();

        let exports: Vec<serde_json::Value> = pe
            .exports
            .iter()
            .map(|e| {
                let reexport = e.reexport.as_ref().map(|re| match re {
                    goblin::pe::export::Reexport::DLLName { lib, export } => {
                        format!("{}.{}", lib, export)
                    }
                    goblin::pe::export::Reexport::DLLOrdinal { lib, ordinal } => {
                        format!("{}.#{}", lib, ordinal)
                    }
                });

                json!({
                    "name": e.name.as_ref().map(|s| s.to_string()).unwrap_or_default(),
                    "rva": e.rva,
                    "offset": e.offset,
                    "reexport": reexport
                })
            })
            .collect();

        let debug_data: Vec<serde_json::Value> = pe
            .debug_data
            .iter()
            .map(|d| {
                // PDB 2.0 (NB10)
                let pdb20 = d.codeview_pdb20_debug_info.as_ref().map(|cv| {
                    serde_json::json!({
                        "kind": "codeview_pdb20",
                        "codeview_signature": format!("0x{:08x}", cv.codeview_signature),
                        "codeview_offset": cv.codeview_offset,
                        "signature": format!("0x{:08x}", cv.signature),
                        "age": cv.age,
                        "filename": String::from_utf8_lossy(cv.filename).to_string(),
                    })
                });

                // PDB 7.0 (RSDS) — field layout can vary; safest is Debug string
                let pdb70 = d.codeview_pdb70_debug_info.as_ref().map(|cv| {
                    serde_json::json!({
                        "kind": "codeview_pdb70",
                        "debug": format!("{:?}", cv),
                    })
                });

                let vcfeature = d.vcfeature_info.as_ref().map(|v| {
                    serde_json::json!({
                        "kind": "vcfeature",
                        "pre_vc_plusplus_count": v.pre_vc_plusplus_count,
                        "c_and_cplusplus_count": v.c_and_cplusplus_count,
                        "guard_stack_count": v.guard_stack_count,
                        "sdl_count": v.sdl_count,
                        "guard_count": v.guard_count,
                    })
                });

                let ex_dll = d.ex_dll_characteristics_info.as_ref().map(|x| {
                    serde_json::json!({
                        "kind": "ex_dll_characteristics",
                        "characteristics_ex": format!("0x{:08x}", x.characteristics_ex),
                    })
                });

                let repro = d.repro_info.as_ref().map(|r| match r {
                    goblin::pe::debug::ReproInfo::TimeDateStamp(ts) => serde_json::json!({
                        "kind": "repro",
                        "time_date_stamp": ts,
                    }),
                    goblin::pe::debug::ReproInfo::Buffer { length, buffer } => serde_json::json!({
                        "kind": "repro",
                        "length": length,
                        "buffer_hex": hex::encode(buffer),
                    }),
                });

                let pogo = d.pogo_info.as_ref().map(|p| {
                    // You can go deeper (iterate entries) later; for now keep it robust:
                    serde_json::json!({
                        "kind": "pogo",
                        "debug": format!("{:?}", p),
                    })
                });

                serde_json::json!({
                    "pdb20": pdb20,
                    "pdb70": pdb70,
                    "vcfeature": vcfeature,
                    "ex_dll_characteristics": ex_dll,
                    "repro": repro,
                    "pogo": pogo,
                })
            })
            .collect();

        let resources = pe.resource_data.as_ref().map(|r| {
            // Manifest is commonly UTF-8 XML, but be defensive.
            let manifest = r
                .manifest_data
                .as_ref()
                .map(|m| match str::from_utf8(m.data) {
                    Ok(s) => serde_json::Value::String(s.to_string()),
                    Err(_) => json!({
                        "encoding": "non-utf8",
                        "size": m.data.len(),
                        "sha256": hex::encode(Sha256::digest(m.data)),
                    }),
                });

            let version_info = r.version_info.as_ref().map(|v| {
                json!({
                    "fixed_info": format!("{:?}", v.fixed_info),

                    // string_info already exposes typed getters (company_name, product_name, etc.)
                    "strings": {
                        "company_name": v.string_info.company_name(),
                        "file_description": v.string_info.file_description(),
                        "file_version": v.string_info.file_version(),
                        "internal_name": v.string_info.internal_name(),
                        "legal_copyright": v.string_info.legal_copyright(),
                        "legal_trademarks": v.string_info.legal_trademarks(),
                        "original_filename": v.string_info.original_filename(),
                        "private_build": v.string_info.private_build(),
                        "product_name": v.string_info.product_name(),
                        "product_version": v.string_info.product_version(),
                        "special_build": v.string_info.special_build(),
                        "comments": v.string_info.comments(),
                    }
                })
            });

            // Enumerate top-level resource entries (type layer).
            let mut top_level = Vec::new();
            for e in r.entries().take(256).flatten() {
                top_level.push(json!({
                    "id": e.id(),                         // Some(u16) if ID-based; None if name-based
                    "name_is_string": e.name_is_string(), // if true, id() is None
                    "name_offset": format!("0x{:x}", e.name_offset()),
                    "data_is_directory": e.data_is_directory(),
                    "offset_to_directory": format!("0x{:x}", e.offset_to_directory()),
                    "offset_to_data": e.offset_to_data().map(|x| format!("0x{:x}", x)),
                }));
            }

            json!({
                "directory": {
                    "time_date_stamp": r.image_resource_directory.time_date_stamp,
                    "major_version": r.image_resource_directory.major_version,
                    "minor_version": r.image_resource_directory.minor_version,
                    "number_of_named_entries": r.image_resource_directory.number_of_named_entries,
                    "number_of_id_entries": r.image_resource_directory.number_of_id_entries,
                    "count": r.image_resource_directory.count(),
                },
                "top_level_entries": top_level,
                "version_info": version_info,
                "manifest": manifest,
            })
        });

        sink(ObjectParsed {
            parser: self.name(),
            kind: "windows.pe.analysis",
            text: format!("PE File: size={} bytes", data.len()),
            json: json!({
                "hashes": {
                    "md5": md5_hash,
                    "sha1": sha1_hash,
                    "sha256": sha256_hash,
                    "imphash": imphash
                },
                "headers": {
                    "machine": format!("0x{:x}", pe.header.coff_header.machine),
                    "entry_point": format!("0x{:x}", pe.entry),
                    "image_base": format!("0x{:x}", pe.image_base),
                    "subsystem": format!(
                        "0x{:x}",
                        pe.header.optional_header
                            .map(|o| o.windows_fields.subsystem)
                            .unwrap_or(0)
                    ),
                },
                "rich_header": rich_header,
                "sections": sections,
                "imports": imports,
                "exports": exports,
                "debug": debug_data,
                "resources": resources,
                "is_64bit": pe.is_64,
                "is_lib": pe.is_lib
            }),
        })?;

        Ok(())
    }
}
