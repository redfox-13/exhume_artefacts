//! Legacy `login.keychain-db` / `System.keychain` (CSSM `AppleDatabase`, magic
//! `kych`) metadata extraction.
//!
//! Layout (all integers big-endian), verified against `security dump-keychain`:
//! - Header: `kych`, version, header size, **schema offset** at byte 12.
//! - Schema (at schema offset): size, table count, then `table_count`
//!   `u32` table offsets relative to the schema offset.
//! - Table (at schema_off + rel): size, **table id** (record type), **record
//!   count**, then — from offset `0x1c` — an array of record offsets relative to
//!   the table start (`0` marks a freed slot).
//! - Record: header, then from offset `0x18` an attribute slot array. Each slot
//!   is `target_offset | low_bits`; `slot & !3` is the value offset within the
//!   record. String/blob attributes are `[u32 len][bytes]`; date attributes are
//!   a fixed 16-byte `YYYYMMDDhhmmssZ` string. A `0` slot means the attribute is
//!   absent. Secrets (`ssgp`-guarded `data`) are never decoded.

use super::{KEYCHAIN_ITEM_KIND, PARSER_NAME};
use crate::core::ObjectParsed;
use crate::parsers::macos::common::util::sqlite_source_json;
use crate::parsers::mobile::sqlite::SqliteEvidence;
use anyhow::{Result, bail};
use chrono::{TimeZone, Utc};
use serde_json::{Value, json};

const SCHEMA_VARIANT: &str = "macos_legacy_keychain_cssm_v1";

// CSSM record type (table id) constants.
const RECORD_GENERIC_PASSWORD: u32 = 0x8000_0000;
const RECORD_INTERNET_PASSWORD: u32 = 0x8000_0001;
const RECORD_APPLESHARE_PASSWORD: u32 = 0x8000_0002;
const RECORD_X509_CERTIFICATE: u32 = 0x8000_8000;
const RECORD_PUBLIC_KEY: u32 = 0x0000_000F;
const RECORD_PRIVATE_KEY: u32 = 0x0000_0010;
const RECORD_SYMMETRIC_KEY: u32 = 0x0000_0011;

pub(crate) fn parse(
    data: &[u8],
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    if data.len() < 24 || &data[0..4] != b"kych" {
        bail!("not a legacy CSSM keychain (bad magic)");
    }
    let schema_off = be(data, 12)? as usize;
    let table_count = be(data, schema_off + 4)? as usize;

    let mut index = 0i64;
    for t in 0..table_count {
        let rel = be(data, schema_off + 8 + 4 * t)? as usize;
        let base = schema_off + rel;
        let table_id = be(data, base + 4)?;
        let record_count = be(data, base + 8)? as usize;
        let record_offsets = collect_record_offsets(data, base, record_count);

        match table_id {
            RECORD_GENERIC_PASSWORD => {
                for &off in &record_offsets {
                    emit_password(
                        data,
                        base + off,
                        evidence,
                        "generic_password",
                        &GENERIC,
                        &mut index,
                        sink,
                    )?;
                }
            }
            RECORD_INTERNET_PASSWORD | RECORD_APPLESHARE_PASSWORD => {
                for &off in &record_offsets {
                    emit_password(
                        data,
                        base + off,
                        evidence,
                        "internet_password",
                        &INTERNET,
                        &mut index,
                        sink,
                    )?;
                }
            }
            RECORD_X509_CERTIFICATE if record_count > 0 => {
                emit_table_summary(evidence, "certificate", table_id, record_count, index, sink)?;
                index += 1;
            }
            RECORD_PUBLIC_KEY | RECORD_PRIVATE_KEY | RECORD_SYMMETRIC_KEY if record_count > 0 => {
                let class = key_class(table_id);
                emit_table_summary(evidence, class, table_id, record_count, index, sink)?;
                index += 1;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Attribute slot indices for a password record class (mirrors the modern
/// SQLite column order for the same class).
struct PasswordLayout {
    created: usize,
    modified: usize,
    description: usize,
    comment: usize,
    label: usize,
    account: usize,
    /// `svce` for generic passwords, `srvr` for internet passwords.
    service_or_server: usize,
    /// Internet-only extras; ignored when `usize::MAX`.
    protocol: usize,
    path: usize,
    port: usize,
}

const GENERIC: PasswordLayout = PasswordLayout {
    created: 0,
    modified: 1,
    description: 2,
    comment: 3,
    label: 7,
    account: 13,
    service_or_server: 14, // svce
    protocol: usize::MAX,
    path: usize::MAX,
    port: usize::MAX,
};

const INTERNET: PasswordLayout = PasswordLayout {
    created: 0,
    modified: 1,
    description: 2,
    comment: 3,
    label: 7,
    account: 13,
    service_or_server: 15, // srvr
    protocol: 16,
    path: 19,
    port: 18,
};

#[allow(clippy::too_many_arguments)]
fn emit_password(
    data: &[u8],
    rec: usize,
    evidence: &SqliteEvidence,
    class: &str,
    layout: &PasswordLayout,
    index: &mut i64,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let account = string_attr(data, rec, layout.account);
    let service = string_attr(data, rec, layout.service_or_server);
    let text = service
        .clone()
        .or_else(|| account.clone())
        .unwrap_or_default();

    let mut item = json!({
        "account": account,
        "label": string_attr(data, rec, layout.label),
        "description": string_attr(data, rec, layout.description),
        "comment": string_attr(data, rec, layout.comment),
    });
    let obj = item.as_object_mut().unwrap();
    if class == "internet_password" {
        obj.insert("server".to_string(), json_or_null(service.clone()));
        obj.insert(
            "protocol".to_string(),
            json_or_null(string_attr(data, rec, layout.protocol)),
        );
        obj.insert(
            "path".to_string(),
            json_or_null(string_attr(data, rec, layout.path)),
        );
        obj.insert("port".to_string(), int_attr(data, rec, layout.port));
    } else {
        obj.insert("service".to_string(), json_or_null(service));
    }

    let json = json!({
        "platform": "macos",
        "app": "keychain",
        "record_type": "keychain_item",
        "format": "keychain-db",
        "class": class,
        "source": sqlite_source_json(evidence, class, *index, SCHEMA_VARIANT),
        "timestamps": {
            "created": cssm_time_to_json(date_attr(data, rec, layout.created)),
            "modified": cssm_time_to_json(date_attr(data, rec, layout.modified)),
        },
        "item": item,
    });

    sink(ObjectParsed {
        parser: PARSER_NAME,
        kind: KEYCHAIN_ITEM_KIND,
        text,
        json,
    })?;
    *index += 1;
    Ok(())
}

/// Certificates and keys: emit one summary object (count) rather than fabricate
/// per-record attributes whose CSSM layout we have not verified.
fn emit_table_summary(
    evidence: &SqliteEvidence,
    class: &str,
    table_id: u32,
    record_count: usize,
    index: i64,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let json = json!({
        "platform": "macos",
        "app": "keychain",
        "record_type": "keychain_table_summary",
        "format": "keychain-db",
        "class": class,
        "source": sqlite_source_json(evidence, class, index, SCHEMA_VARIANT),
        "summary": {
            "table_id": format!("0x{table_id:08x}"),
            "record_count": record_count,
        },
    });
    sink(ObjectParsed {
        parser: PARSER_NAME,
        kind: KEYCHAIN_ITEM_KIND,
        text: format!("{class}: {record_count} record(s)"),
        json,
    })
}

/// Collect up to `record_count` non-zero record offsets (relative to the table
/// base) from the offset array beginning at `base + 0x1c`.
fn collect_record_offsets(data: &[u8], base: usize, record_count: usize) -> Vec<usize> {
    let mut offsets = Vec::with_capacity(record_count);
    let mut i = 0;
    // Bound the scan so a corrupt count cannot spin.
    let max_slots = record_count.saturating_mul(2) + 64;
    while offsets.len() < record_count && i < max_slots {
        match be(data, base + 0x1c + 4 * i) {
            Ok(v) if v != 0 => offsets.push(v as usize),
            Ok(_) => {}
            Err(_) => break,
        }
        i += 1;
    }
    offsets
}

/// Read a string/blob attribute (`[u32 len][bytes]` at `slot & !3`).
fn string_attr(data: &[u8], rec: usize, attr_index: usize) -> Option<String> {
    if attr_index == usize::MAX {
        return None;
    }
    let slot = be(data, rec + 0x18 + 4 * attr_index).ok()?;
    if slot == 0 {
        return None;
    }
    let off = rec + (slot & !3) as usize;
    let len = be(data, off).ok()? as usize;
    let bytes = data.get(off + 4..off + 4 + len)?;
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim_end_matches('\0');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Read a date attribute: a fixed 16-byte `YYYYMMDDhhmmssZ` string stored at
/// `slot & !3` with no length prefix.
fn date_attr(data: &[u8], rec: usize, attr_index: usize) -> Option<String> {
    let slot = be(data, rec + 0x18 + 4 * attr_index).ok()?;
    if slot == 0 {
        return None;
    }
    let off = rec + (slot & !3) as usize;
    let bytes = data.get(off..off + 16)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let text = String::from_utf8_lossy(&bytes[..end]);
    if text.is_empty() {
        None
    } else {
        Some(text.into_owned())
    }
}

/// Read an inline integer attribute (the slot value itself).
fn int_attr(data: &[u8], rec: usize, attr_index: usize) -> Value {
    if attr_index == usize::MAX {
        return Value::Null;
    }
    match be(data, rec + 0x18 + 4 * attr_index) {
        Ok(v) if v != 0 => json!(v),
        _ => Value::Null,
    }
}

/// Parse a CSSM `YYYYMMDDhhmmssZ` (Zulu/UTC) timestamp into the shared JSON
/// timestamp shape.
fn cssm_time_to_json(value: Option<String>) -> Value {
    let Some(text) = value else {
        return Value::Null;
    };
    let digits = text.trim_end_matches('Z');
    if digits.len() < 14 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Value::Null;
    }
    let parse = |a: usize, b: usize| digits[a..b].parse::<u32>().ok();
    let (Some(y), Some(mo), Some(da), Some(h), Some(mi), Some(s)) = (
        parse(0, 4),
        parse(4, 6),
        parse(6, 8),
        parse(8, 10),
        parse(10, 12),
        parse(12, 14),
    ) else {
        return Value::Null;
    };
    let Some(dt) = Utc.with_ymd_and_hms(y as i32, mo, da, h, mi, s).single() else {
        return Value::Null;
    };
    json!({
        "original": text,
        "original_epoch": "cssm_zulu",
        "unix_ms": dt.timestamp_millis(),
        "rfc3339": dt.to_rfc3339(),
    })
}

fn key_class(table_id: u32) -> &'static str {
    match table_id {
        RECORD_PUBLIC_KEY => "public_key",
        RECORD_PRIVATE_KEY => "private_key",
        RECORD_SYMMETRIC_KEY => "symmetric_key",
        _ => "key",
    }
}

fn json_or_null(value: Option<String>) -> Value {
    value.map(Value::String).unwrap_or(Value::Null)
}

fn be(data: &[u8], offset: usize) -> Result<u32> {
    let b = data
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow::anyhow!("truncated keychain at offset {offset}"))?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cssm_zulu_time() {
        let ts = cssm_time_to_json(Some("20240721061320Z".to_string()));
        assert_eq!(ts["rfc3339"], "2024-07-21T06:13:20+00:00");
        assert_eq!(ts["original_epoch"], "cssm_zulu");
    }

    #[test]
    fn rejects_bad_time() {
        assert!(cssm_time_to_json(Some("not-a-date".to_string())).is_null());
        assert!(cssm_time_to_json(None).is_null());
    }
}
