use crate::parsers::macos::common::input::FileEvidence;
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use plist::{Date, Dictionary, Value as Plist};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn parse_plist(evidence: &FileEvidence, label: &str) -> Result<Plist> {
    if evidence.bytes.is_empty() {
        bail!("{label} is empty");
    }
    if evidence.bytes.iter().all(|byte| *byte == 0) {
        bail!("{label} content is all zeroes (filesystem data unavailable)");
    }
    Plist::from_reader(Cursor::new(&evidence.bytes))
        .map_err(|err| anyhow::anyhow!("not a valid {label}: {err}"))
}

pub(super) fn string(dict: &Dictionary, key: &str) -> Option<String> {
    scalar_string(dict.get(key))
}

pub(super) fn string_any(dict: &Dictionary, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| string(dict, key))
}

fn scalar_string(value: Option<&Plist>) -> Option<String> {
    let value = match value? {
        Plist::String(value) => value.clone(),
        Plist::Integer(value) => value
            .as_signed()
            .map(|value| value.to_string())
            .or_else(|| value.as_unsigned().map(|value| value.to_string()))?,
        Plist::Real(value) if value.is_finite() => value.to_string(),
        _ => return None,
    };
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

pub(super) fn signed_integer(dict: &Dictionary, key: &str) -> Option<i64> {
    dict.get(key).and_then(Plist::as_signed_integer)
}

pub(super) fn boolean(dict: &Dictionary, key: &str) -> Option<bool> {
    match dict.get(key)? {
        Plist::Boolean(value) => Some(*value),
        Plist::Integer(value) => value.as_signed().map(|value| value != 0),
        Plist::String(value) if value.eq_ignore_ascii_case("true") || value == "1" => Some(true),
        Plist::String(value) if value.eq_ignore_ascii_case("false") || value == "0" => Some(false),
        _ => None,
    }
}

pub(super) fn string_array(value: Option<&Plist>) -> Vec<String> {
    match value {
        Some(Plist::Array(values)) => values
            .iter()
            .filter_map(|value| scalar_string(Some(value)))
            .collect(),
        Some(value) => scalar_string(Some(value)).into_iter().collect(),
        None => Vec::new(),
    }
}

pub(super) fn sorted_keys(dict: &Dictionary) -> Vec<String> {
    let mut keys = dict.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    keys
}

pub(super) fn plist_date_to_json(value: Option<&Plist>) -> Value {
    let date = match value {
        Some(Plist::Date(date)) => Some(*date),
        Some(Plist::String(value)) => Date::from_xml_format(value).ok(),
        _ => None,
    };
    let Some(date) = date else {
        return Value::Null;
    };

    let system_time = SystemTime::from(date);
    let unix_ms = match system_time.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).ok(),
        Err(error) => i64::try_from(error.duration().as_millis())
            .ok()
            .and_then(i64::checked_neg),
    };
    let rfc3339 = unix_ms
        .and_then(DateTime::<Utc>::from_timestamp_millis)
        .map(|date| date.to_rfc3339());

    json!({
        "original": date.to_xml_format(),
        "original_epoch": "plist_date",
        "unix_ms": unix_ms,
        "rfc3339": rfc3339,
    })
}

pub(super) fn timestamp_unix_ms(value: &Value) -> Option<i64> {
    value.get("unix_ms").and_then(Value::as_i64)
}

/// Return the path without Exhume's APFS `/volume_N` namespace while retaining
/// the exact evidence path elsewhere in every emitted record.
pub(super) fn logical_path(path: &str) -> &str {
    let Some(rest) = path.strip_prefix("/volume_") else {
        return path;
    };
    let Some(slash) = rest.find('/') else {
        return path;
    };
    let index = &rest[..slash];
    if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
        return path;
    }
    &rest[slash..]
}

pub(super) fn user_from_path(path: &str) -> Option<String> {
    let path = logical_path(path);
    let rest = path.strip_prefix("/Users/")?;
    let user = rest.split('/').next()?;
    (!user.is_empty() && user != "Shared").then(|| user.to_owned())
}

pub(super) fn scope_from_path(path: &str) -> &'static str {
    let path = logical_path(path);
    if path.starts_with("/Users/Shared/") {
        "shared"
    } else if path.starts_with("/Users/") {
        "user"
    } else if path.starts_with("/Applications/")
        || path.starts_with("/System/")
        || path.starts_with("/Library/")
        || path.starts_with("/private/var/")
    {
        "system"
    } else {
        "unknown"
    }
}

pub(super) fn data_summary(value: Option<&Plist>) -> Value {
    let Some(Plist::Data(bytes)) = value else {
        return Value::Null;
    };
    json!({
        "length": bytes.len(),
        "sha256": hex::encode(Sha256::digest(bytes)),
    })
}

pub(super) fn data_array_summaries(value: Option<&Plist>) -> Value {
    let Some(Plist::Array(values)) = value else {
        return Value::Null;
    };
    Value::Array(
        values
            .iter()
            .enumerate()
            .filter_map(|(index, value)| match value {
                Plist::Data(bytes) => Some(json!({
                    "index": index,
                    "length": bytes.len(),
                    "sha256": hex::encode(Sha256::digest(bytes)),
                })),
                _ => None,
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::{logical_path, plist_date_to_json};
    use plist::Value as Plist;

    #[test]
    fn strips_only_numeric_apfs_volume_namespaces() {
        assert_eq!(
            logical_path("/volume_12/Applications/App.app"),
            "/Applications/App.app"
        );
        assert_eq!(
            logical_path("/volume_x/Applications/App.app"),
            "/volume_x/Applications/App.app"
        );
        assert_eq!(
            logical_path("/Applications/App.app"),
            "/Applications/App.app"
        );
    }

    #[test]
    fn converts_plist_dates_without_guessing_numeric_epochs() {
        let date = plist::Date::from_xml_format("2024-07-21T06:24:38Z").unwrap();
        let converted = plist_date_to_json(Some(&Plist::Date(date)));
        assert_eq!(converted["unix_ms"], 1_721_543_078_000i64);
        assert_eq!(converted["original_epoch"], "plist_date");
        assert!(plist_date_to_json(Some(&Plist::Real(743_000_000.0))).is_null());
    }
}
