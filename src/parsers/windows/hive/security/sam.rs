use notatin::cell_key_node::CellKeyNode;
use serde_json::{Value, json};

use crate::formats::timestamps::windows_filetime_to_json;

pub(super) fn value_bytes(cell: &CellKeyNode, name: &str) -> Option<Vec<u8>> {
    cell.value_iter()
        .find(|value| value.get_pretty_name().eq_ignore_ascii_case(name))
        .map(|value| value.detail.value_bytes().unwrap_or_default())
}

pub(super) fn utf16_value(cell: &CellKeyNode, name: &str) -> Option<String> {
    let data = value_bytes(cell, name)?;
    if data.len() % 2 != 0 {
        return None;
    }

    Some(
        String::from_utf16_lossy(
            &data
                .chunks_exact(2)
                .map(|word| u16::from_le_bytes([word[0], word[1]]))
                .collect::<Vec<_>>(),
        )
        .trim_end_matches('\0')
        .to_owned(),
    )
}

pub(super) fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

pub(super) fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn utf16_field(data: &[u8], offset: usize, length: usize) -> Option<String> {
    let end = offset.checked_add(length)?;
    let bytes = data.get(offset..end)?;
    if bytes.len() % 2 != 0 {
        return None;
    }

    Some(String::from_utf16_lossy(
        &bytes
            .chunks_exact(2)
            .map(|word| u16::from_le_bytes([word[0], word[1]]))
            .collect::<Vec<_>>(),
    ))
}

fn relative_utf16_field(data: &[u8], offset: usize, length: usize) -> Option<String> {
    utf16_field(data, 0xCCusize.checked_add(offset)?, length)
}

pub(super) fn user_v(data: &[u8]) -> Option<Value> {
    let account_type = u32_at(data, 4)?;
    let username =
        relative_utf16_field(data, u32_at(data, 12)? as usize, u32_at(data, 16)? as usize)?;
    let full_name =
        relative_utf16_field(data, u32_at(data, 24)? as usize, u32_at(data, 28)? as usize);
    let comment =
        relative_utf16_field(data, u32_at(data, 36)? as usize, u32_at(data, 40)? as usize);
    let account_type_name = match account_type {
        0xBC => Some("default_admin"),
        0xD4 => Some("custom_limited_account"),
        0xB0 => Some("default_guest"),
        _ => None,
    };

    Some(json!({
        "username": username,
        "full_name": full_name,
        "comment": comment,
        "account_type": account_type_name,
        "account_type_code": account_type,
    }))
}

fn filetime_at(data: &[u8], offset: usize) -> Value {
    match u64_at(data, offset).filter(|time| *time != 0) {
        Some(filetime) => windows_filetime_to_json(filetime),
        None => Value::Null,
    }
}

pub(super) fn user_f(data: &[u8]) -> Option<Value> {
    if data.len() < 68 {
        return None;
    }

    let account_control_flags = u16_at(data, 56);
    let flag_names = account_control_flags
        .map(|flags| {
            [
                (0x0001, "account_disabled"),
                (0x0002, "home_directory_required"),
                (0x0004, "password_not_required"),
                (0x0008, "temporary_duplicate_account"),
                (0x0010, "normal_user_account"),
                (0x0020, "mns_logon_user_account"),
                (0x0040, "interdomain_trust_account"),
                (0x0080, "workstation_trust_account"),
                (0x0100, "server_trust_account"),
                (0x0200, "password_does_not_expire"),
                (0x0400, "account_auto_locked"),
            ]
            .into_iter()
            .filter_map(|(flag, name)| (flags & flag != 0).then_some(name))
            .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(json!({
        "last_logon": filetime_at(data, 8),
        "password_last_set": filetime_at(data, 24),
        "account_expires": filetime_at(data, 32),
        "last_failed_logon": filetime_at(data, 40),
        "rid": u32_at(data, 48),
        "account_control_flags": account_control_flags,
        "account_control_flag_names": flag_names,
        "failed_logon_count": u16_at(data, 64),
        "logon_count": u16_at(data, 66),
    }))
}

pub(super) fn domain_sid(cell: &CellKeyNode) -> Option<String> {
    let data = value_bytes(cell, "V")?;
    let offset = data.len().checked_sub(12)?;
    let first = u32_at(&data, offset)?;
    let second = u32_at(&data, offset + 4)?;
    let third = u32_at(&data, offset + 8)?;
    Some(format!("S-1-5-21-{first}-{second}-{third}"))
}

pub(super) fn alias_c(data: &[u8]) -> Option<(String, String, Vec<String>, u32)> {
    const HEADER_SIZE: usize = 0x34;

    if data.len() < HEADER_SIZE {
        return None;
    }
    let group_name = utf16_field(
        data,
        HEADER_SIZE.checked_add(u32_at(data, 16)? as usize)?,
        u32_at(data, 20)? as usize,
    )?;
    let comment = utf16_field(
        data,
        HEADER_SIZE.checked_add(u32_at(data, 28)? as usize)?,
        u32_at(data, 32)? as usize,
    )
    .unwrap_or_default();
    let member_list_offset = HEADER_SIZE.checked_add(u32_at(data, 40)? as usize)?;
    let member_count = u32_at(data, 48)?;
    let remaining = data.len().checked_sub(member_list_offset)?;
    if usize::try_from(member_count).ok()? > remaining / 8 {
        return None;
    }
    let mut members = Vec::new();
    let mut cursor = member_list_offset;

    for _ in 0..member_count {
        if data.get(cursor) == Some(&0) {
            cursor = cursor.checked_add(1)?;
        }
        let sid = data.get(cursor..)?;
        let sid_length = sid_length(sid)?;
        members.push(decode_sid(&sid[..sid_length])?);
        cursor = cursor.checked_add(sid_length)?;
    }

    Some((group_name, comment, members, member_count))
}

fn sid_length(data: &[u8]) -> Option<usize> {
    let sub_authority_count = usize::from(*data.get(1)?);
    8usize
        .checked_add(sub_authority_count.checked_mul(4)?)
        .filter(|length| *length <= data.len())
}

fn decode_sid(data: &[u8]) -> Option<String> {
    let length = sid_length(data)?;
    let revision = data[0];
    let authority = data[2..8]
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    let sub_authorities = data[8..length]
        .chunks_exact(4)
        .map(|part| u32::from_le_bytes([part[0], part[1], part[2], part[3]]))
        .map(|part| part.to_string())
        .collect::<Vec<_>>();

    Some(format!(
        "S-{revision}-{authority}-{}",
        sub_authorities.join("-")
    ))
}
