//! Procmon PML parser for Windows event streams.
//!
//! This module decodes PML records into normalized JSON events for investigation workflows.

use crate::core::{ObjectParsed, Parser, ParserInput, ReadSeek, TimelineEvent};
use anyhow::{Result, anyhow};
use scroll::{LE, Pread};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Parser implementation for Windows Procmon `.PML` files.
pub struct WindowsPmlParser;

impl Default for WindowsPmlParser {
    fn default() -> Self {
        Self
    }
}

/// In-memory PML string table.
pub struct StringTable {
    pub strings: Vec<String>,
}

impl StringTable {
    /// Parses a string table from `table_offset`.
    pub fn parse(reader: &mut dyn ReadSeek, table_offset: u64) -> Result<Self> {
        reader.seek(SeekFrom::Start(table_offset))?;
        let mut count_buf = [0u8; 4];
        reader.read_exact(&mut count_buf)?;
        let count = u32::from_le_bytes(count_buf) as usize;

        if count > 100000 {
            return Err(anyhow!("StringTable count too large: {}", count));
        }

        let mut offsets = Vec::with_capacity(count);
        for _ in 0..count {
            let mut off_buf = [0u8; 4];
            reader.read_exact(&mut off_buf)?;
            offsets.push(u32::from_le_bytes(off_buf));
        }

        let mut strings = Vec::with_capacity(count);
        for off in offsets.iter().take(count) {
            let pos = table_offset + *off as u64;
            reader.seek(SeekFrom::Start(pos))?;

            let mut len_buf = [0u8; 4];
            if reader.read_exact(&mut len_buf).is_err() {
                strings.push(String::new());
                continue;
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            if len == 0 || len > 8192 {
                strings.push(String::new());
                continue;
            }

            let mut utf16_buf = vec![0u8; len];
            if reader.read_exact(&mut utf16_buf).is_err() {
                strings.push(String::new());
                continue;
            }

            let utf16_data: Vec<u16> = utf16_buf
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();

            let s = String::from_utf16_lossy(&utf16_data)
                .trim_matches('\0')
                .to_string();
            strings.push(s);
        }

        Ok(Self { strings })
    }

    /// Returns a string by index if present.
    pub fn get(&self, index: u32) -> Option<&String> {
        self.strings.get(index as usize)
    }
}

/// Process metadata entry resolved from the process table.
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub user: String,
    pub integrity: String,
    pub image_path: String,
    pub command_line: String,
    pub company: String,
    pub version: String,
    pub description: String,
}

/// In-memory process table keyed by process index.
pub struct ProcessTable {
    pub processes: HashMap<u32, ProcessInfo>,
}

impl ProcessTable {
    /// Parses a process table from `table_offset` and resolves string indices.
    pub fn parse(
        reader: &mut dyn ReadSeek,
        table_offset: u64,
        string_table: &StringTable,
    ) -> Result<Self> {
        reader.seek(SeekFrom::Start(table_offset))?;
        let count = {
            let mut b = [0u8; 4];
            reader.read_exact(&mut b)?;
            u32::from_le_bytes(b) as usize
        };

        reader.seek(SeekFrom::Current((count as i64) * 4))?;

        let mut offsets = Vec::with_capacity(count);
        for _ in 0..count {
            let mut b = [0u8; 4];
            reader.read_exact(&mut b)?;
            offsets.push(u32::from_le_bytes(b));
        }

        let mut processes = HashMap::new();

        for rel_off in offsets {
            let pos = table_offset + rel_off as u64;
            reader.seek(SeekFrom::Start(pos))?;

            let mut buf = [0u8; 0x70];
            if reader.read_exact(&mut buf).is_err() {
                continue;
            }

            let process_index: u32 = buf.pread_with(0x00, LE)?;
            let pid: u32 = buf.pread_with(0x04, LE)?;

            let integrity_idx: u32 = buf.pread_with(0x38, LE)?;
            let user_idx: u32 = buf.pread_with(0x3C, LE)?;
            let name_idx: u32 = buf.pread_with(0x40, LE)?;
            let image_idx: u32 = buf.pread_with(0x44, LE)?;
            let cmd_idx: u32 = buf.pread_with(0x48, LE)?;
            let company_idx: u32 = buf.pread_with(0x4C, LE)?;
            let version_idx: u32 = buf.pread_with(0x50, LE)?;
            let desc_idx: u32 = buf.pread_with(0x54, LE)?;

            let get = |idx: u32| string_table.get(idx).cloned().unwrap_or_default();

            processes.insert(
                process_index,
                ProcessInfo {
                    pid,
                    name: get(name_idx),
                    user: get(user_idx),
                    integrity: get(integrity_idx),
                    image_path: get(image_idx),
                    command_line: get(cmd_idx),
                    company: get(company_idx),
                    version: get(version_idx),
                    description: get(desc_idx),
                },
            );
        }

        Ok(Self { processes })
    }
}

fn get_operation_name(event_class: u32, op: u16) -> &'static str {
    match event_class {
        1 => match op {
            0 => "Process Defined",
            1 => "Process Create",
            2 => "Process Exit",
            3 => "Thread Create",
            4 => "Thread Exit",
            5 => "Load Image",
            6 => "Thread Profile",
            7 => "Process Start",
            8 => "Process Statistics",
            9 => "System Statistics",
            _ => "Process Other",
        },
        2 => match op {
            0 => "RegOpenKey",
            1 => "RegCreateKey",
            2 => "RegCloseKey",
            3 => "RegQueryKey",
            4 => "RegSetValue",
            5 => "RegQueryValue",
            6 => "RegEnumValue",
            7 => "RegEnumKey",
            8 => "RegSetInfoKey",
            9 => "RegDeleteKey",
            10 => "RegDeleteValue",
            11 => "RegFlushKey",
            12 => "RegLoadKey",
            13 => "RegUnloadKey",
            14 => "RegRenameKey",
            15 => "RegQueryMultipleValueKey",
            16 => "RegSetKeySecurity",
            17 => "RegQueryKeySecurity",
            _ => "Registry Other",
        },
        3 => match op {
            0 => "VolumeDismount",
            1 => "VolumeMount",
            2 => "FASTIO_MDL_WRITE_COMPLETE",
            3 => "WriteFile2",
            4 => "FASTIO_MDL_READ_COMPLETE",
            5 => "ReadFile2",
            6 => "QueryOpen",
            7 => "FASTIO_CHECK_IF_POSSIBLE",
            8 => "IRP_MJ_12",
            9 => "IRP_MJ_11",
            10 => "IRP_MJ_10",
            11 => "IRP_MJ_9",
            12 => "IRP_MJ_8",
            13 => "FASTIO_NOTIFY_STREAM_FO_CREATION",
            14 => "FASTIO_RELEASE_FOR_CC_FLUSH",
            15 => "FASTIO_ACQUIRE_FOR_CC_FLUSH",
            16 => "FASTIO_RELEASE_FOR_MOD_WRITE",
            17 => "FASTIO_ACQUIRE_FOR_MOD_WRITE",
            18 => "FASTIO_RELEASE_FOR_SECTION_SYNCHRONIZATION",
            19 => "CreateFileMapping",
            20 => "CreateFile",
            21 => "CreatePipe",
            22 => "IRP_MJ_CLOSE",
            23 => "ReadFile",
            24 => "WriteFile",
            25 => "QueryInformationFile",
            26 => "SetInformationFile",
            27 => "QueryEAFile",
            28 => "SetEAFile",
            29 => "FlushBuffersFile",
            30 => "QueryVolumeInformation",
            31 => "SetVolumeInformation",
            32 => "DirectoryControl",
            33 => "FileSystemControl",
            34 => "DeviceIoControl",
            35 => "InternalDeviceIoControl",
            36 => "Shutdown",
            37 => "LockUnlockFile",
            38 => "CloseFile",
            39 => "CreateMailSlot",
            40 => "QuerySecurityFile",
            41 => "SetSecurityFile",
            42 => "Power",
            43 => "SystemControl",
            44 => "DeviceChange",
            45 => "QueryFileQuota",
            46 => "SetFileQuota",
            47 => "PlugAndPlay",
            _ => "FileSystem Other",
        },
        4 => match op {
            0 => "Thread Profiling",
            1 => "Process Profiling",
            2 => "Debug Output Profiling",
            _ => "Profiling Other",
        },
        5 => match op {
            0 => "Unknown",
            1 => "Other",
            2 => "Send",
            3 => "Receive",
            4 => "Accept",
            5 => "Connect",
            6 => "Disconnect",
            7 => "Reconnect",
            8 => "Retransmit",
            9 => "TCPCopy",
            _ => "Network Other",
        },
        _ => "Other",
    }
}

fn read_u8(cursor: &mut Cursor<&[u8]>) -> Option<u8> {
    let mut b = [0u8; 1];
    cursor.read_exact(&mut b).ok()?;
    Some(b[0])
}

fn read_u16(cursor: &mut Cursor<&[u8]>) -> Option<u16> {
    let mut b = [0u8; 2];
    cursor.read_exact(&mut b).ok()?;
    Some(u16::from_le_bytes(b))
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Option<u32> {
    let mut b = [0u8; 4];
    cursor.read_exact(&mut b).ok()?;
    Some(u32::from_le_bytes(b))
}

fn read_u64(cursor: &mut Cursor<&[u8]>) -> Option<u64> {
    let mut b = [0u8; 8];
    cursor.read_exact(&mut b).ok()?;
    Some(u64::from_le_bytes(b))
}

fn skip(cursor: &mut Cursor<&[u8]>, bytes: usize) -> bool {
    let pos = cursor.position() as usize;
    let next = pos.saturating_add(bytes);
    if next > cursor.get_ref().len() {
        return false;
    }
    cursor.set_position(next as u64);
    true
}

fn read_detail_string_info(cursor: &mut Cursor<&[u8]>) -> Option<(bool, usize)> {
    let flags = read_u16(cursor)?;
    let is_ascii = (flags >> 15) == 1;
    let char_count = (flags & 0x7FFF) as usize;
    Some((is_ascii, char_count))
}

fn read_detail_string(cursor: &mut Cursor<&[u8]>, info: (bool, usize)) -> Option<String> {
    let (is_ascii, char_count) = info;
    if char_count == 0 || char_count > 65535 {
        return Some(String::new());
    }

    if is_ascii {
        let mut bytes = vec![0u8; char_count];
        cursor.read_exact(&mut bytes).ok()?;
        Some(
            String::from_utf8_lossy(&bytes)
                .trim_matches('\0')
                .to_string(),
        )
    } else {
        let byte_len = char_count.checked_mul(2)?;
        let mut bytes = vec![0u8; byte_len];
        cursor.read_exact(&mut bytes).ok()?;
        let utf16: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(
            String::from_utf16_lossy(&utf16)
                .trim_matches('\0')
                .to_string(),
        )
    }
}

fn read_utf16_multisz(cursor: &mut Cursor<&[u8]>) -> String {
    let pos = cursor.position() as usize;
    let remaining = &cursor.get_ref()[pos..];
    if remaining.is_empty() {
        return String::new();
    }
    let utf16: Vec<u16> = remaining
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let parts: Vec<String> = String::from_utf16_lossy(&utf16)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    parts.join(" | ")
}

fn reg_type_label(reg_type: u32) -> String {
    match reg_type {
        0 => "REG_NONE".to_string(),
        1 => "REG_SZ".to_string(),
        2 => "REG_EXPAND_SZ".to_string(),
        3 => "REG_BINARY".to_string(),
        4 => "REG_DWORD".to_string(),
        5 => "REG_DWORD_BIG_ENDIAN".to_string(),
        6 => "REG_LINK".to_string(),
        7 => "REG_MULTI_SZ".to_string(),
        8 => "REG_RESOURCE_LIST".to_string(),
        9 => "REG_FULL_RESOURCE_DESCRIPTOR".to_string(),
        10 => "REG_RESOURCE_REQUIREMENTS_LIST".to_string(),
        11 => "REG_QWORD".to_string(),
        _ => format!("<Unknown: {}>", reg_type),
    }
}

fn read_exact_vec(cursor: &mut Cursor<&[u8]>, len: usize) -> Option<Vec<u8>> {
    let mut v = vec![0u8; len];
    cursor.read_exact(&mut v).ok()?;
    Some(v)
}

fn decode_registry_data(cursor: &mut Cursor<&[u8]>, reg_type: u32, length: usize) -> Option<Value> {
    let available = cursor
        .get_ref()
        .len()
        .saturating_sub(cursor.position() as usize);
    let n = length.min(available);
    if n == 0 {
        return None;
    }

    match reg_type {
        4 if n >= 4 => Some(json!(read_u32(cursor)?)),
        11 if n >= 8 => Some(json!(read_u64(cursor)?)),
        1 | 2 => {
            let bytes = read_exact_vec(cursor, n)?;
            let utf16: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Some(json!(
                String::from_utf16_lossy(&utf16)
                    .trim_matches('\0')
                    .to_string()
            ))
        }
        7 => {
            let bytes = read_exact_vec(cursor, n)?;
            let mut c = Cursor::new(bytes.as_slice());
            let s = read_utf16_multisz(&mut c);
            if s.is_empty() { None } else { Some(json!(s)) }
        }
        _ => {
            let bytes = read_exact_vec(cursor, n)?;
            let hex = bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join("");
            Some(json!(hex))
        }
    }
}

fn decode_mask_string(mut mask: u32, mapping: &[(u32, &str)], sep: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for (value, name) in mapping {
        if mask & *value == *value {
            parts.push(*name);
            mask &= !*value;
        }
    }
    parts.join(sep)
}

fn filesystem_access_mask_string(mut access_mask: u32) -> String {
    let generic_mappings = [0x120089u32, 0x120116u32, 0x1200a0u32, 0x1f01ffu32];
    if access_mask & 0x80000000 != 0 {
        access_mask |= generic_mappings[0];
    }
    if access_mask & 0x40000000 != 0 {
        access_mask |= generic_mappings[1];
    }
    if access_mask & 0x20000000 != 0 {
        access_mask |= generic_mappings[2];
    }
    if access_mask & 0x10000000 != 0 {
        access_mask |= generic_mappings[3];
    }

    const ACCESS: &[(u32, &str)] = &[
        (0x1f01ff, "All Access"),
        (0x1201bf, "Generic Read/Write/Execute"),
        (0x12019f, "Generic Read/Write"),
        (0x1200a9, "Generic Read/Execute"),
        (0x1201b6, "Generic Write/Execute"),
        (0x120089, "Generic Read"),
        (0x120116, "Generic Write"),
        (0x1200a0, "Generic Execute"),
        (0x1, "Read Data/List Directory"),
        (0x2, "Write Data/Add File"),
        (0x4, "Append Data/Add Subdirectory/Create Pipe Instance"),
        (0x8, "Read EA"),
        (0x10, "Write EA"),
        (0x20, "Execute/Traverse"),
        (0x40, "Delete Child"),
        (0x80, "Read Attributes"),
        (0x100, "Write Attributes"),
        (0x10000, "Delete"),
        (0x20000, "Read Control"),
        (0x40000, "Write DAC"),
        (0x80000, "Write Owner"),
        (0x100000, "Synchronize"),
        (0x1000000, "Access System Security"),
        (0x2000000, "Maximum Allowed"),
    ];

    let s = decode_mask_string(access_mask, ACCESS, ", ");
    if s.is_empty() {
        format!("None 0x{:x}", access_mask)
    } else {
        s
    }
}

fn filesystem_disposition_string(disposition: u32) -> &'static str {
    match disposition {
        0 => "Supersede",
        1 => "Open",
        2 => "Create",
        3 => "OpenIf",
        4 => "Overwrite",
        5 => "OverwriteIf",
        _ => "<unknown>",
    }
}

fn filesystem_options_string(options_mask: u32) -> String {
    const OPTIONS: &[(u32, &str)] = &[
        (0x1, "Directory"),
        (0x2, "Write Through"),
        (0x4, "Sequential Access"),
        (0x8, "No Buffering"),
        (0x10, "Synchronous IO Alert"),
        (0x20, "Synchronous IO Non-Alert"),
        (0x40, "Non-Directory File"),
        (0x80, "Create Tree Connection"),
        (0x100, "Complete If Oplocked"),
        (0x200, "No EA Knowledge"),
        (0x400, "Open for Recovery"),
        (0x800, "Random Access"),
        (0x1000, "Delete On Close"),
        (0x2000, "Open By ID"),
        (0x4000, "Open For Backup"),
        (0x8000, "No Compression"),
        (0x10000, "Open Requiring Oplock"),
        (0x20000, "Disallow Exclusive"),
        (0x100000, "Reserve OpFilter"),
        (0x200000, "Open Reparse Point"),
        (0x400000, "Open No Recall"),
        (0x800000, "Open For Free Space Query"),
    ];
    decode_mask_string(options_mask, OPTIONS, ", ")
}

fn filesystem_attributes_string(attributes_mask: u32) -> String {
    if attributes_mask == 0 {
        return "n/a".to_string();
    }
    const ATTRS: &[(u32, &str)] = &[
        (0x1, "R"),
        (0x2, "H"),
        (0x4, "S"),
        (0x10, "D"),
        (0x20, "A"),
        (0x40, "D"),
        (0x80, "N"),
        (0x100, "T"),
        (0x200, "SF"),
        (0x400, "RP"),
        (0x800, "C"),
        (0x1000, "O"),
        (0x2000, "NCI"),
        (0x4000, "E"),
        (0x10000, "V"),
    ];
    decode_mask_string(attributes_mask, ATTRS, "")
}

fn filesystem_share_mode_string(share_mask: u32) -> String {
    if share_mask == 0 {
        return "None".to_string();
    }
    const SHARE: &[(u32, &str)] = &[(0x1, "Read"), (0x2, "Write"), (0x4, "Delete")];
    decode_mask_string(share_mask, SHARE, ", ")
}

fn filesystem_open_result_string(v: u32) -> &'static str {
    match v {
        0 => "Superseded",
        1 => "Opened",
        2 => "Created",
        3 => "Overwritten",
        4 => "Exists",
        5 => "DoesNotExist",
        _ => "<unknown>",
    }
}

fn registry_access_mask_string(mut access_mask: u32) -> String {
    let generic_mappings = [0x20019u32, 0x20006u32, 0x20019u32, 0xf003fu32];
    if access_mask & 0x80000000 != 0 {
        access_mask |= generic_mappings[0];
    }
    if access_mask & 0x40000000 != 0 {
        access_mask |= generic_mappings[1];
    }
    if access_mask & 0x20000000 != 0 {
        access_mask |= generic_mappings[2];
    }
    if access_mask & 0x10000000 != 0 {
        access_mask |= generic_mappings[3];
    }

    const MASKS: &[(u32, &str)] = &[
        (0xf003f, "All Access"),
        (0x2001f, "Read/Write"),
        (0x20019, "Read"),
        (0x20006, "Write"),
        (0x1, "Query Value"),
        (0x2, "Set Value"),
        (0x4, "Create Sub Key"),
        (0x8, "Enumerate Sub Keys"),
        (0x10, "Notify"),
        (0x20, "Create Link"),
        (0x300, "WOW64_Res"),
        (0x200, "WOW64_32Key"),
        (0x100, "WOW64_64Key"),
        (0x10000, "Delete"),
        (0x20000, "Read Control"),
        (0x40000, "Write DAC"),
        (0x80000, "Write Owner"),
        (0x100000, "Synchronize"),
        (0x1000000, "Access System Security"),
        (0x2000000, "Maximum Allowed"),
    ];

    let s = decode_mask_string(access_mask, MASKS, ", ");
    if s.is_empty() {
        format!("None 0x{:x}", access_mask)
    } else {
        s
    }
}

fn parse_registry_details(
    details_blob: &[u8],
    op_name: &str,
    extra_blob: Option<&[u8]>,
) -> Option<Map<String, Value>> {
    let mut io = Cursor::new(details_blob);
    let path_info = read_detail_string_info(&mut io)?;

    let mut new_path_info: Option<(bool, usize)> = None;
    let mut desired_access: Option<u32> = None;
    let mut length_hint: Option<u32> = None;
    let mut information_class: Option<u32> = None;
    let mut enum_index: Option<u32> = None;
    let mut reg_type_hint: Option<u32> = None;
    let mut data_length_hint: Option<u32> = None;

    match op_name {
        "RegLoadKey" | "RegRenameKey" => {
            new_path_info = read_detail_string_info(&mut io);
        }
        "RegOpenKey" | "RegCreateKey" => {
            if !skip(&mut io, 2) {
                return None;
            }
            desired_access = read_u32(&mut io);
        }
        "RegQueryKey" | "RegQueryValue" => {
            if !skip(&mut io, 2) {
                return None;
            }
            length_hint = read_u32(&mut io);
            information_class = read_u32(&mut io);
        }
        "RegEnumValue" | "RegEnumKey" => {
            if !skip(&mut io, 2) {
                return None;
            }
            length_hint = read_u32(&mut io);
            enum_index = read_u32(&mut io);
            information_class = read_u32(&mut io);
        }
        "RegSetInfoKey" => {
            if !skip(&mut io, 2 + 4 + 4) {
                return None;
            }
            length_hint = read_u16(&mut io).map(|v| v as u32);
            if !skip(&mut io, 2) {
                return None;
            }
        }
        "RegSetValue" => {
            if !skip(&mut io, 2) {
                return None;
            }
            reg_type_hint = read_u32(&mut io);
            length_hint = read_u32(&mut io);
            data_length_hint = read_u32(&mut io);
        }
        _ => {}
    }

    let path = read_detail_string(&mut io, path_info)?;
    let mut out = Map::new();
    if !path.is_empty() {
        out.insert("path".to_string(), json!(path));
    }

    if let Some(info) = new_path_info
        && let Some(new_path) = read_detail_string(&mut io, info)
        && !new_path.is_empty()
    {
        out.insert("new_path".to_string(), json!(new_path));
    }

    if let Some(index) = enum_index {
        out.insert("index".to_string(), json!(index));
    }

    if let Some(len) = length_hint {
        out.insert("length".to_string(), json!(len));
    }

    if let Some(access) = desired_access {
        out.insert(
            "desired_access".to_string(),
            json!(registry_access_mask_string(access)),
        );
    }

    let mut extra_cursor = extra_blob.map(Cursor::new);

    if matches!(
        op_name,
        "RegSetValue" | "RegSetInfoKey" | "RegLoadKey" | "RegRenameKey"
    ) {
        let pos = io.position() as usize;
        if pos < details_blob.len() {
            extra_cursor = Some(Cursor::new(&details_blob[pos..]));
        }
    }

    match op_name {
        "RegOpenKey" | "RegCreateKey" => {
            if let Some(cur) = extra_cursor.as_mut() {
                let first = read_u32(cur);
                let second = read_u32(cur);

                if op_name == "RegOpenKey" {
                    if desired_access.unwrap_or(0) & 0x2000000 != 0
                        && let Some(granted) = first
                    {
                        out.insert(
                            "granted_access".to_string(),
                            json!(registry_access_mask_string(granted)),
                        );
                    }
                } else if let Some(disposition) = second {
                    let disposition_name = match disposition {
                        1 => Some("REG_CREATED_NEW_KEY"),
                        2 => Some("REG_OPENED_EXISTING_KEY"),
                        _ => None,
                    };
                    if let Some(name) = disposition_name {
                        out.insert("disposition".to_string(), json!(name));
                    }
                }
            }
        }
        "RegQueryValue" | "RegEnumValue" => {
            if let Some(cur) = extra_cursor.as_mut() {
                let _ = read_u32(cur);
                if let Some(reg_type) = read_u32(cur) {
                    out.insert("type".to_string(), json!(reg_type_label(reg_type)));

                    let info_class = information_class.unwrap_or_default();
                    let mut data_len = None;
                    if info_class == 1 {
                        let offset_to_data = read_u32(cur).unwrap_or_default() as usize;
                        data_len = read_u32(cur);
                        let name_size = read_u32(cur).unwrap_or_default() as usize;
                        if name_size > 0 {
                            let name_bytes = read_exact_vec(cur, name_size).unwrap_or_default();
                            let utf16: Vec<u16> = name_bytes
                                .chunks_exact(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect();
                            let name = String::from_utf16_lossy(&utf16)
                                .trim_matches('\0')
                                .to_string();
                            if !name.is_empty() {
                                out.insert("value_name".to_string(), json!(name));
                            }
                        }
                        if offset_to_data <= cur.get_ref().len() {
                            cur.set_position(offset_to_data as u64);
                        }
                    } else if info_class == 2 {
                        data_len = read_u32(cur);
                    }

                    if let Some(len) = data_len {
                        out.insert("length".to_string(), json!(len));
                        if let Some(data) = decode_registry_data(cur, reg_type, len as usize) {
                            out.insert("data".to_string(), data);
                        }
                    }
                }
            }
        }
        "RegSetValue" => {
            if let Some(reg_type) = reg_type_hint {
                out.insert("type".to_string(), json!(reg_type_label(reg_type)));
                let n = length_hint
                    .unwrap_or_default()
                    .min(data_length_hint.unwrap_or_default()) as usize;
                if let Some(cur) = extra_cursor.as_mut()
                    && let Some(data) = decode_registry_data(cur, reg_type, n)
                {
                    out.insert("data".to_string(), data);
                }
            }
        }
        _ => {}
    }

    Some(out)
}

fn try_parse_filesystem_details(
    details_blob: &[u8],
    op_name: &str,
    ptr_size: usize,
    extra_blob: Option<&[u8]>,
) -> Option<Map<String, Value>> {
    let mut io = Cursor::new(details_blob);
    let sub_operation = read_u8(&mut io)?;
    if !skip(&mut io, 3) {
        return None;
    }

    let details_io_size = ptr_size.checked_mul(5)?.checked_add(0x14)?;
    let details_io_start = io.position() as usize;
    if !skip(&mut io, details_io_size) {
        return None;
    }
    let details_io_end = io.position() as usize;
    let mut details_io = Cursor::new(&details_blob[details_io_start..details_io_end]);

    let path_info = read_detail_string_info(&mut io)?;
    if !skip(&mut io, 2) {
        return None;
    }

    let path = read_detail_string(&mut io, path_info)?;
    let mut out = Map::new();
    out.insert("sub_operation".to_string(), json!(sub_operation));
    if !path.is_empty() {
        out.insert("path".to_string(), json!(path));
    }

    if op_name == "CreateFile" {
        if let Some(desired_access) = read_u32(&mut io) {
            out.insert(
                "desired_access".to_string(),
                json!(filesystem_access_mask_string(desired_access)),
            );
        }
        let impersonating_sid_length = read_u8(&mut io).unwrap_or(0) as usize;
        let _ = skip(&mut io, 3);

        let _ = skip(&mut details_io, 0x10);
        if ptr_size == 8 {
            let _ = skip(&mut details_io, 4);
        }

        if let Some(disposition_and_options) = read_u32(&mut details_io) {
            let disposition = disposition_and_options >> 24;
            let options = disposition_and_options & 0x00ff_ffff;
            out.insert(
                "disposition".to_string(),
                json!(filesystem_disposition_string(disposition)),
            );
            let options_text = filesystem_options_string(options);
            if !options_text.is_empty() {
                out.insert("options".to_string(), json!(options_text));
            }
        }

        if ptr_size == 8 {
            let _ = skip(&mut details_io, 4);
        }

        let attributes = read_u16(&mut details_io).unwrap_or(0) as u32;
        let share_mode = read_u16(&mut details_io).unwrap_or(0) as u32;
        out.insert(
            "attributes".to_string(),
            json!(filesystem_attributes_string(attributes)),
        );
        out.insert(
            "share_mode".to_string(),
            json!(filesystem_share_mode_string(share_mode)),
        );

        let _ = skip(&mut details_io, 0x4 + ptr_size * 2);
        if let Some(allocation) = read_u32(&mut details_io) {
            if allocation == 0xFFFF_FFFF {
                out.insert("allocation_size".to_string(), json!("n/a"));
            } else {
                out.insert("allocation_size".to_string(), json!(allocation));
            }
        }

        if impersonating_sid_length > 0
            && let Some(sid_raw) = read_exact_vec(&mut io, impersonating_sid_length)
        {
            out.insert(
                "impersonating_sid_raw".to_string(),
                json!(format!("{:x?}", sid_raw)),
            );
        }

        if let Some(extra) = extra_blob {
            let mut extra_io = Cursor::new(extra);
            if let Some(open_result) = read_u32(&mut extra_io) {
                out.insert(
                    "open_result".to_string(),
                    json!(filesystem_open_result_string(open_result)),
                );
            }
        }
    } else if op_name == "SetDispositionInformationFile" || op_name == "SetDispositionInformationEx"
    {
        let _ = skip(&mut details_io, 4);
        if let Some(delete_flag) = read_u8(&mut details_io) {
            out.insert("delete".to_string(), json!(delete_flag != 0));
        }
    } else if op_name == "CreateFileMapping" {
        let _ = skip(&mut details_io, 0x0c);
        if let Some(sync_type) = read_u32(&mut details_io) {
            let sync_type_name = match sync_type {
                0 => "SyncTypeOther",
                1 => "SyncTypeCreateSection",
                _ => "Unknown",
            };
            out.insert("sync_type".to_string(), json!(sync_type_name));
        }
        if let Some(page_protection) = read_u32(&mut details_io) {
            let mut pp = match page_protection & 0xff {
                0x02 => "PAGE_READONLY".to_string(),
                0x04 => "PAGE_READWRITE".to_string(),
                0x08 => "PAGE_WRITECOPY".to_string(),
                0x10 => "PAGE_EXECUTE".to_string(),
                0x20 => "PAGE_EXECUTE_READ".to_string(),
                0x40 => "PAGE_EXECUTE_READWRITE".to_string(),
                _ => format!("0x{:x}", page_protection),
            };
            if page_protection & 0x200 != 0 {
                pp.push_str("|PAGE_NOCACHE");
            }
            out.insert("page_protection".to_string(), json!(pp));
        }
    } else if op_name == "DeviceIoControl" || op_name == "FileSystemControl" {
        let _ = skip(&mut details_io, 8);
        let write_length = read_u32(&mut details_io).unwrap_or(0);
        let read_length = read_u32(&mut details_io).unwrap_or(0);
        if ptr_size == 8 {
            let _ = skip(&mut details_io, 4);
        }
        let _ = skip(&mut details_io, 4);
        if ptr_size == 8 {
            let _ = skip(&mut details_io, 4);
        }
        let ioctl = read_u32(&mut details_io).unwrap_or(0);
        out.insert("control".to_string(), json!(format!("0x{:x}", ioctl)));
        out.insert("write_length".to_string(), json!(write_length));
        out.insert("read_length".to_string(), json!(read_length));
    } else if op_name == "ReadFile" || op_name == "WriteFile" {
        let _ = skip(&mut details_io, 4);
        let io_flags_priority = read_u32(&mut details_io).unwrap_or(0);
        let _ = skip(&mut details_io, 4);
        let mut length = read_u32(&mut details_io).unwrap_or(0);
        if ptr_size == 8 {
            let _ = skip(&mut details_io, 4);
        }
        let _ = skip(&mut details_io, 4);
        if ptr_size == 8 {
            let _ = skip(&mut details_io, 4);
        }
        let offset = read_u64(&mut details_io).unwrap_or(0);

        if let Some(extra) = extra_blob {
            let mut extra_io = Cursor::new(extra);
            if let Some(extra_len) = read_u32(&mut extra_io) {
                length = extra_len;
            }
        }

        out.insert("length".to_string(), json!(length));
        out.insert("offset".to_string(), json!(offset));
        out.insert(
            "io_flags_priority".to_string(),
            json!(format!("0x{:x}", io_flags_priority)),
        );
    } else if op_name == "QueryDirectory"
        && let Some(filter_info) = read_detail_string_info(&mut io)
        && let Some(filter) = read_detail_string(&mut io, filter_info)
        && !filter.is_empty()
    {
        out.insert("filter".to_string(), json!(filter.clone()));
        if let Some(current_path) = out.get("path").and_then(|v| v.as_str()) {
            let full = if current_path.ends_with('\\') {
                format!("{}{}", current_path, filter)
            } else {
                format!("{}\\{}", current_path, filter)
            };
            out.insert("path".to_string(), json!(full));
        }
    }

    Some(out)
}

fn try_parse_process_details(
    details_blob: &[u8],
    op_name: &str,
    ptr_size: usize,
) -> Option<Map<String, Value>> {
    let mut io = Cursor::new(details_blob);
    let mut out = Map::new();

    match op_name {
        "Thread Create" => {
            out.insert("thread_id".to_string(), json!(read_u32(&mut io)?));
        }
        "Load Image" => {
            if !skip(&mut io, ptr_size) {
                return None;
            }
            out.insert("image_size".to_string(), json!(read_u32(&mut io)?));
            let path_info = read_detail_string_info(&mut io)?;
            if !skip(&mut io, 2) {
                return None;
            }
            let path = read_detail_string(&mut io, path_info)?;
            if !path.is_empty() {
                out.insert("path".to_string(), json!(path));
            }
        }
        "Process Defined" | "Process Create" => {
            if !skip(&mut io, 4) {
                return None;
            }
            out.insert("child_pid".to_string(), json!(read_u32(&mut io)?));
            if !skip(&mut io, 0x24) {
                return None;
            }
            let unknown_size1 = read_u8(&mut io)? as usize;
            let unknown_size2 = read_u8(&mut io)? as usize;
            let path_info = read_detail_string_info(&mut io)?;
            let command_line_info = read_detail_string_info(&mut io)?;
            if !skip(&mut io, 2 + unknown_size1 + unknown_size2) {
                return None;
            }
            let path = read_detail_string(&mut io, path_info)?;
            if !path.is_empty() {
                out.insert("path".to_string(), json!(path));
            }
            let cmd = read_detail_string(&mut io, command_line_info)?;
            if !cmd.is_empty() {
                out.insert("command_line_detail".to_string(), json!(cmd));
            }
        }
        "Process Start" => {
            out.insert("parent_pid".to_string(), json!(read_u32(&mut io)?));
            let command_line_info = read_detail_string_info(&mut io)?;
            let current_directory_info = read_detail_string_info(&mut io)?;
            let env_char_count = read_u32(&mut io)? as usize;

            let cmd = read_detail_string(&mut io, command_line_info)?;
            if !cmd.is_empty() {
                out.insert("command_line_detail".to_string(), json!(cmd));
            }
            let cwd = read_detail_string(&mut io, current_directory_info)?;
            if !cwd.is_empty() {
                out.insert("current_directory".to_string(), json!(cwd));
            }

            let env_byte_count = env_char_count.saturating_mul(2);
            let pos = io.position() as usize;
            let end = pos.saturating_add(env_byte_count).min(details_blob.len());
            io.set_position(end as u64);
            let mut env_io = Cursor::new(&details_blob[pos..end]);
            let env = read_utf16_multisz(&mut env_io);
            if !env.is_empty() {
                out.insert("environment".to_string(), json!(env));
            }
        }
        _ => {}
    }

    Some(out)
}

fn ip_to_string(bytes: [u8; 16], is_ipv4: bool) -> String {
    if is_ipv4 {
        Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()
    } else {
        Ipv6Addr::from(bytes).to_string()
    }
}

fn try_parse_network_details(details_blob: &[u8], op_name: &str) -> Option<Map<String, Value>> {
    let mut io = Cursor::new(details_blob);
    let flags = read_u16(&mut io)?;
    let is_source_ipv4 = (flags & 1) != 0;
    let is_dest_ipv4 = (flags & 2) != 0;
    let is_tcp = (flags & 4) != 0;

    if !skip(&mut io, 2) {
        return None;
    }
    let length = read_u32(&mut io)?;

    let mut src = [0u8; 16];
    io.read_exact(&mut src).ok()?;
    let mut dst = [0u8; 16];
    io.read_exact(&mut dst).ok()?;

    let src_port = read_u16(&mut io)?;
    let dst_port = read_u16(&mut io)?;

    let proto_prefix = if is_tcp { "TCP" } else { "UDP" };
    let mut out = Map::new();
    out.insert(
        "operation_with_protocol".to_string(),
        json!(format!("{} {}", proto_prefix, op_name)),
    );
    out.insert("length".to_string(), json!(length));

    let path = format!(
        "{}:{} -> {}:{}",
        ip_to_string(src, is_source_ipv4),
        src_port,
        ip_to_string(dst, is_dest_ipv4),
        dst_port
    );
    out.insert("path".to_string(), json!(path));

    let extra = read_utf16_multisz(&mut io);
    if !extra.is_empty() {
        out.insert("extra_multisz".to_string(), json!(extra));
    }

    Some(out)
}

fn filesystem_sub_operation_name(base_op: &str, sub: u8) -> Option<&'static str> {
    match base_op {
        "DirectoryControl" => match sub {
            0x1 => Some("QueryDirectory"),
            0x2 => Some("NotifyChangeDirectory"),
            _ => None,
        },
        "QueryInformationFile" => match sub {
            0x4 => Some("QueryBasicInformationFile"),
            0x5 => Some("QueryStandardInformationFile"),
            0x6 => Some("QueryFileInternalInformationFile"),
            0x7 => Some("QueryEAInformationFile"),
            0x9 => Some("QueryNameInformationFile"),
            0xe => Some("QueryPositionInformationFile"),
            0x12 => Some("QueryAllInformationFile"),
            0x14 => Some("QueryEndOfFile"),
            0x16 => Some("QueryStreamInformationFile"),
            0x1c => Some("QueryCompressionInformationFile"),
            0x1d => Some("QueryId"),
            0x1f => Some("QueryMoveClusterInformationFile"),
            0x22 => Some("QueryNetworkOpenInformationFile"),
            0x23 => Some("QueryAttributeTagFile"),
            0x25 => Some("QueryIdBothDirectory"),
            0x27 => Some("QueryValidDataLength"),
            0x28 => Some("QueryShortNameInformationFile"),
            0x2e => Some("QueryLinks"),
            0x30 => Some("QueryNormalizedNameInformationFile"),
            0x31 => Some("QueryNetworkPhysicalNameInformationFile"),
            0x32 => Some("QueryIdGlobalTxDirectoryInformation"),
            0x33 => Some("QueryIsRemoteDeviceInformation"),
            0x34 => Some("QueryAttributeCacheInformation"),
            0x35 => Some("QueryNumaNodeInformation"),
            0x36 => Some("QueryStandardLinkInformation"),
            0x37 => Some("QueryRemoteProtocolInformation"),
            0x3a => Some("QueryVolumeNameInformation"),
            0x3b => Some("QueryIdInformation"),
            0x3c => Some("QueryIdExtdDirectoryInformation"),
            0x3e => Some("QueryHardLinkFullIdInformation"),
            0x3f => Some("QueryIdExtdBothDirectoryInformation"),
            0x43 => Some("QueryDesiredStorageClassInformation"),
            0x44 => Some("QueryStatInformation"),
            0x45 => Some("QueryMemoryPartitionInformation"),
            0x47 => Some("QueryCaseSensitiveInformation"),
            0x4a => Some("QueryStorageReservedIdInformation"),
            _ => None,
        },
        "SetInformationFile" => match sub {
            0x04 => Some("SetBasicInformationFile"),
            0x0a => Some("SetRenameInformationFile"),
            0x0b => Some("SetLinkInformationFile"),
            0x0d => Some("SetDispositionInformationFile"),
            0x0e => Some("SetPositionInformationFile"),
            0x13 => Some("SetAllocationInformationFile"),
            0x14 => Some("SetEndOfFileInformationFile"),
            0x16 => Some("SetFileStreamInformation"),
            0x17 => Some("SetPipeInformation"),
            0x27 => Some("SetValidDataLengthInformationFile"),
            0x28 => Some("SetShortNameInformation"),
            0x3d => Some("SetReplaceCompletionInformation"),
            0x40 => Some("SetDispositionInformationEx"),
            0x41 => Some("SetRenameInformationEx"),
            0x42 => Some("SetRenameInformationExBypassAccessCheck"),
            0x4a => Some("SetStorageReservedIdInformation"),
            _ => None,
        },
        "QueryVolumeInformation" => match sub {
            0x1 => Some("QueryInformationVolume"),
            0x2 => Some("QueryLabelInformationVolume"),
            0x3 => Some("QuerySizeInformationVolume"),
            0x4 => Some("QueryDeviceInformationVolume"),
            0x5 => Some("QueryAttributeInformationVolume"),
            0x6 => Some("QueryControlInformationVolume"),
            0x7 => Some("QueryFullSizeInformationVolume"),
            0x8 => Some("QueryObjectIdInformationVolume"),
            _ => None,
        },
        "SetVolumeInformation" => match sub {
            0x1 => Some("SetControlInformationVolume"),
            0x2 => Some("SetLabelInformationVolume"),
            0x8 => Some("SetObjectIdInformationVolume"),
            _ => None,
        },
        "LockUnlockFile" => match sub {
            0x1 => Some("LockFile"),
            0x2 => Some("UnlockFileSingle"),
            0x3 => Some("UnlockFileAll"),
            0x4 => Some("UnlockFileByKey"),
            _ => None,
        },
        _ => None,
    }
}

fn effective_operation_name(event_class: u32, op_name: &str, details_blob: &[u8]) -> String {
    if event_class != 3 || details_blob.is_empty() {
        return op_name.to_string();
    }

    let sub = details_blob[0];
    if sub == 0 {
        return op_name.to_string();
    }

    filesystem_sub_operation_name(op_name, sub)
        .unwrap_or(op_name)
        .to_string()
}

fn parse_event_details(
    details_blob: &[u8],
    extra_blob: Option<&[u8]>,
    event_class: u32,
    op_name: &str,
    ptr_size: usize,
) -> Map<String, Value> {
    let mut parsed = Map::new();

    let specific = match event_class {
        1 => try_parse_process_details(details_blob, op_name, ptr_size),
        2 => parse_registry_details(details_blob, op_name, extra_blob),
        3 => try_parse_filesystem_details(details_blob, op_name, ptr_size, extra_blob),
        5 => try_parse_network_details(details_blob, op_name),
        _ => None,
    };

    if let Some(map) = specific {
        for (k, v) in map {
            parsed.insert(k, v);
        }
    }

    parsed
}

fn filetime_to_unix_ms(filetime: u64) -> i64 {
    let unix_epoch_diff_100ns: i128 = 116_444_736_000_000_000;
    let ft = filetime as i128;
    ((ft - unix_epoch_diff_100ns) / 10_000) as i64
}

fn result_text(status: u32) -> &'static str {
    match status {
        0x00000000 => "SUCCESS",
        0x00000103 => "NO MORE DATA",
        0x00000104 => "REPARSE",
        0x00000105 => "MORE ENTRIES",
        0x0000012a => "FILE LOCKED WITH ONLY READERS",
        0x0000012b => "FILE LOCKED WITH WRITERS",
        0x00000216 => "OPLOCK HANDLE CLOSED",
        0x00000368 => "REPARSE GLOBAL",
        0x4000001a => "NO MORE FILES",
        0x80000005 => "BUFFER OVERFLOW",
        0x80000006 => "NO MORE FILES",
        0x8000001a => "NO MORE ENTRIES",
        0x8000002d => "STOPPED ON SYMLINK",
        0xc0000001 => "UNSUCCESSFUL",
        0xc0000002 => "NOT IMPLEMENTED",
        0xc0000005 => "ACCESS VIOLATION",
        0xc0000008 => "INVALID HANDLE",
        0xc000000d => "INVALID PARAMETER",
        0xc000000f => "NO SUCH FILE",
        0xc0000010 => "INVALID DEVICE REQUEST",
        0xc0000011 => "END OF FILE",
        0xc0000017 => "NO MEMORY",
        0xc0000018 => "CONFLICTING ADDRESSES",
        0xc0000022 => "ACCESS DENIED",
        0xc0000023 => "BUFFER TOO SMALL",
        0xc0000033 => "OBJECT NAME INVALID",
        0xc0000034 => "NAME NOT FOUND",
        0xc0000035 => "NAME COLLISION",
        0xc000003a => "PATH NOT FOUND",
        0xc0000043 => "SHARING VIOLATION",
        0xc0000045 => "INVALID PAGE PROTECTION",
        0xc000004f => "EAS NOT SUPPORTED",
        0xc0000052 => "NO EAS ON FILE",
        0xc0000054 => "FILE LOCK CONFLICT",
        0xc0000056 => "DELETE PENDING",
        0xc000005f => "NO SUCH FILE",
        0xc0000061 => "PRIVILEGE NOT HELD",
        0xc00000ba => "FILE IS A DIRECTORY",
        0xc00000bb => "NOT SUPPORTED",
        0xc00000cc => "BAD NETWORK PATH",
        0xc00000d4 => "NOT SAME DEVICE",
        0xc0000101 => "DIRECTORY NOT EMPTY",
        0xc0000103 => "NOT A DIRECTORY",
        0xc0000120 => "CANCELLED",
        0xc0000121 => "CANNOT DELETE",
        0xc0000123 => "INVALID IMAGE FORMAT",
        0xc0000181 => "FILE CLOSED",
        0xc0000275 => "NOT REPARSE POINT",
        0xc01c0004 => "FAST IO DISALLOWED",
        _ => "UNKNOWN",
    }
}

fn derive_category(event_class: u32, op_name: &str, details: &Map<String, Value>) -> &'static str {
    if event_class == 2 {
        if op_name.starts_with("RegSet")
            || op_name.starts_with("RegDelete")
            || op_name == "RegRenameKey"
            || op_name == "RegLoadKey"
        {
            return "Write";
        }
        if op_name.ends_with("Security") {
            if op_name.contains("Set") {
                return "Write Metadata";
            }
            return "Read Metadata";
        }
        return "Read";
    }

    if event_class == 3 {
        if op_name.starts_with("Query")
            || matches!(
                op_name,
                "ReadFile" | "ReadFile2" | "QueryEAFile" | "NotifyChangeDirectory" | "QueryOpen"
            )
        {
            return "Read";
        }
        if op_name.starts_with("Set")
            || matches!(
                op_name,
                "WriteFile"
                    | "WriteFile2"
                    | "SetEAFile"
                    | "SetSecurityFile"
                    | "SetFileQuota"
                    | "SetDispositionInformationFile"
                    | "SetDispositionInformationEx"
            )
        {
            return "Write";
        }
        if op_name == "DeviceIoControl" || op_name == "FileSystemControl" {
            return "Read/Write Metadata";
        }
        if op_name == "CreateFile" {
            if let Some(d) = details.get("disposition").and_then(|v| v.as_str())
                && matches!(
                    d,
                    "Create" | "OpenIf" | "Overwrite" | "OverwriteIf" | "Supersede"
                )
            {
                return "Write";
            }
            return "Read";
        }
        return "Other";
    }

    if event_class == 5 {
        return "Network";
    }

    "Other"
}

fn should_emit_raw(
    details_blob: &[u8],
    event_class: u32,
    op_name: &str,
    details_obj: &Map<String, Value>,
) -> bool {
    if details_obj.get("path").is_some() {
        return false;
    }

    if details_blob.len() < 12 {
        return false;
    }

    if event_class == 1
        && matches!(
            op_name,
            "Thread Create"
                | "Thread Exit"
                | "Process Exit"
                | "Process Statistics"
                | "System Statistics"
        )
    {
        return false;
    }

    true
}

fn is_useful_detail_char(c: char) -> bool {
    !c.is_control() || matches!(c, '\t' | '\n' | '\r')
}

fn score_detail_candidate(s: &str) -> usize {
    s.chars().filter(|c| is_useful_detail_char(*c)).count()
}

fn extract_raw_details(blob: &[u8]) -> Option<String> {
    if blob.is_empty() {
        return None;
    }

    let mut best: Option<String> = None;
    let mut best_score = 0usize;
    let max_off = blob.len().min(16);
    for off in 0..max_off {
        let mut io = Cursor::new(&blob[off..]);
        if let Some(info) = read_detail_string_info(&mut io)
            && let Some(candidate) = read_detail_string(&mut io, info)
        {
            let trimmed = candidate.trim_matches('\0').trim().to_string();
            if trimmed.is_empty() {
                continue;
            }
            let score = score_detail_candidate(&trimmed);
            if score > best_score {
                best_score = score;
                best = Some(trimmed);
            }
        }
    }
    if best.is_some() {
        return best;
    }

    if blob.len() >= 2 {
        let utf16: Vec<u16> = blob
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let utf16_text = String::from_utf16_lossy(&utf16)
            .trim_matches('\0')
            .trim()
            .to_string();
        if !utf16_text.is_empty() {
            return Some(utf16_text);
        }
    }

    let utf8_text = String::from_utf8_lossy(blob)
        .trim_matches('\0')
        .trim()
        .to_string();
    if utf8_text.is_empty() {
        None
    } else {
        Some(utf8_text)
    }
}

impl WindowsPmlParser {
    /// Parses events from a seekable reader and streams normalized records into `sink`.
    fn parse_reader(
        &self,
        mut reader: Box<dyn ReadSeek + '_>,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let mut header_buf = vec![0u8; 0x300];
        reader.read_exact(&mut header_buf)?;

        let signature: [u8; 4] = header_buf.pread(0)?;
        if &signature != b"PML_" {
            return Err(anyhow!("Invalid PML signature"));
        }

        let is_64bit: u32 = header_buf.pread_with(0x08, LE)?;
        let ptr_size: usize = if is_64bit != 0 { 8 } else { 4 };

        let total_events: u32 = header_buf.pread_with(0x234, LE)?;
        let event_index_offset: u64 = header_buf.pread_with(0x248, LE)?;
        let processes_offset: u64 = header_buf.pread_with(0x250, LE)?;
        let strings_offset: u64 = header_buf.pread_with(0x258, LE)?;

        let string_table = StringTable::parse(reader.as_mut(), strings_offset)?;
        let process_table = ProcessTable::parse(reader.as_mut(), processes_offset, &string_table)?;

        for i in 0..total_events {
            let index_pos = event_index_offset + (i as u64 * 5);
            reader.seek(SeekFrom::Start(index_pos))?;

            let mut off4 = [0u8; 4];
            if reader.read_exact(&mut off4).is_err() {
                break;
            }
            let absolute_offset = u32::from_le_bytes(off4) as u64;

            let mut flag = [0u8; 1];
            let _ = reader.read_exact(&mut flag);

            if absolute_offset == 0 {
                continue;
            }

            reader.seek(SeekFrom::Start(absolute_offset))?;

            let mut eh = [0u8; 0x34];
            if reader.read_exact(&mut eh).is_err() {
                break;
            }

            let process_idx: u32 = eh.pread_with(0x00, LE)?;
            let thread_id: u32 = eh.pread_with(0x04, LE)?;
            let event_class: u32 = eh.pread_with(0x08, LE)?;
            let op_type: u16 = eh.pread_with(0x0C, LE)?;

            let duration: u64 = eh.pread_with(0x14, LE)?;
            let timestamp_filetime: u64 = eh.pread_with(0x1C, LE)?;
            let result: u32 = eh.pread_with(0x24, LE)?;
            let stack_depth: u16 = eh.pread_with(0x28, LE)?;
            let details_size: u32 = eh.pread_with(0x2C, LE)?;
            let extra_details_offset: u32 = eh.pread_with(0x30, LE)?;

            let stack_bytes_len = (stack_depth as usize) * ptr_size;
            let mut stacktrace = Vec::<u64>::with_capacity(stack_depth as usize);
            if stack_bytes_len > 0 {
                let mut sbuf = vec![0u8; stack_bytes_len];
                if reader.read_exact(&mut sbuf).is_ok() {
                    for chunk in sbuf.chunks_exact(ptr_size) {
                        let addr = if ptr_size == 8 {
                            u64::from_le_bytes(chunk.try_into().unwrap())
                        } else {
                            u32::from_le_bytes(chunk.try_into().unwrap()) as u64
                        };
                        stacktrace.push(addr);
                    }
                }
            }

            let details_size_usize = details_size as usize;
            let mut details_blob = Vec::<u8>::new();
            if details_size_usize > 0 && details_size_usize < 4 * 1024 * 1024 {
                details_blob.resize(details_size_usize, 0u8);
                let _ = reader.read_exact(&mut details_blob);
            }

            let mut extra_details_blob: Option<Vec<u8>> = None;
            if extra_details_offset > 0 {
                let consumed = (0x34usize)
                    .saturating_add(stack_bytes_len)
                    .saturating_add(details_size_usize) as u32;
                if extra_details_offset >= consumed {
                    let rel = (extra_details_offset - consumed) as i64;
                    if rel >= 0 {
                        let return_pos = reader.stream_position().unwrap_or(0);
                        if reader.seek(SeekFrom::Current(rel)).is_ok() {
                            let mut size_buf = [0u8; 2];
                            if reader.read_exact(&mut size_buf).is_ok() {
                                let extra_size = u16::from_le_bytes(size_buf) as usize;
                                if extra_size > 0 && extra_size < 4 * 1024 * 1024 {
                                    let mut eb = vec![0u8; extra_size];
                                    if reader.read_exact(&mut eb).is_ok() {
                                        extra_details_blob = Some(eb);
                                    }
                                }
                            }
                        }
                        let _ = reader.seek(SeekFrom::Start(return_pos));
                    }
                }
            }

            let base_op_name = get_operation_name(event_class, op_type);
            let mut op_name = effective_operation_name(event_class, base_op_name, &details_blob);

            let mut details = json!({
                "details_size": details_size,
                "extra_details_offset": extra_details_offset,
                "stack_depth": stack_depth,
            });

            if let Some(details_obj) = details.as_object_mut() {
                for (k, v) in parse_event_details(
                    &details_blob,
                    extra_details_blob.as_deref(),
                    event_class,
                    &op_name,
                    ptr_size,
                ) {
                    details_obj.insert(k, v);
                }

                if let Some(proto_op) = details_obj
                    .get("operation_with_protocol")
                    .and_then(|v| v.as_str())
                {
                    op_name = proto_op.to_string();
                }

                if should_emit_raw(&details_blob, event_class, &op_name, details_obj)
                    && let Some(raw) = extract_raw_details(&details_blob)
                {
                    details_obj.insert("raw".to_string(), json!(raw));
                }
            }

            if let Some(proc) = process_table.processes.get(&process_idx) {
                details["pid"] = json!(proc.pid);
                details["process_name"] = json!(proc.name);
                details["user"] = json!(proc.user);
                details["integrity"] = json!(proc.integrity);
                details["image_path"] = json!(proc.image_path);
                details["command_line"] = json!(proc.command_line);
                details["company"] = json!(proc.company);
                details["version"] = json!(proc.version);
                details["description"] = json!(proc.description);
            }

            let details_obj_ref = details.as_object();
            let category = details_obj_ref
                .map(|m| derive_category(event_class, &op_name, m))
                .unwrap_or("Other");
            let parse_quality = details_obj_ref
                .map(|m| {
                    if m.contains_key("path")
                        || m.contains_key("data")
                        || m.contains_key("desired_access")
                    {
                        "high"
                    } else if m.contains_key("raw") {
                        "medium"
                    } else {
                        "low"
                    }
                })
                .unwrap_or("low");
            let ts_unix_ms = filetime_to_unix_ms(timestamp_filetime);
            let ts_unix = ts_unix_ms / 1000;

            let obj = ObjectParsed {
                parser: self.name(),
                kind: "event",
                text: format!(
                    "[{}] PID={} {} -> {}",
                    op_name.as_str(),
                    details.get("pid").and_then(|v| v.as_u64()).unwrap_or(0),
                    details
                        .get("process_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    details
                        .get("path")
                        .and_then(|v| v.as_str())
                        .or_else(|| details.get("raw").and_then(|v| v.as_str()))
                        .unwrap_or("")
                ),
                json: json!({
                    "index": i,
                    "process_index": process_idx,
                    "thread_id": thread_id,
                    "event_class": event_class,
                    "operation": op_name,
                    "operation_raw": op_type,
                    "duration_100ns": duration,
                    "timestamp_filetime": timestamp_filetime,
                    "timestamp_unix": ts_unix,
                    "timestamp_unix_ms": ts_unix_ms,
                    "result": format!("0x{:x}", result),
                    "result_text": result_text(result),
                    "category": category,
                    "parse_quality": parse_quality,
                    "stacktrace": stacktrace,
                    "details": details,
                }),
            };

            sink(obj)?;
        }

        Ok(())
    }
}

impl Parser for WindowsPmlParser {
    fn name(&self) -> &'static str {
        "windows_pml"
    }

    fn description(&self) -> &'static str {
        "Parser for ProcMon PML files (v9)."
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        let Some(ts_unix_ms) = obj.json["timestamp_unix_ms"].as_i64() else {
            return Vec::new();
        };
        let operation = obj.json["operation"].as_str().unwrap_or("");
        let process = obj.json["details"]["process_name"].as_str().unwrap_or("");
        let path = obj.json["details"]["path"].as_str().unwrap_or("");
        let description = if path.is_empty() {
            format!("{operation} [{process}]")
        } else {
            format!("{operation} [{process}] {path}")
        };
        let actor = obj.json["details"]["user"].as_str().map(str::to_owned);
        vec![TimelineEvent {
            ts_unix_ms,
            event_type: "windows.pml.event",
            description: Some(description),
            actor,
        }]
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        match input {
            ParserInput::Path(path) => {
                let file = std::fs::File::open(path)?;
                self.parse_reader(Box::new(file), sink)
            }
            ParserInput::Bytes(bytes) => {
                let cursor = std::io::Cursor::new(bytes);
                self.parse_reader(Box::new(cursor), sink)
            }
            ParserInput::ReadSeek(reader) => self.parse_reader(reader, sink),
            ParserInput::Compound(_) => {
                anyhow::bail!("windows_pml does not support compound parser input")
            }
        }
    }
}
