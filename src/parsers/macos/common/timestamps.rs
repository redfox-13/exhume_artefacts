//! Timestamp helpers specific to macOS desktop applications.
//!
//! Apple/Unix epoch helpers live in [`crate::parsers::mobile::common::timestamps`]
//! and are reused directly; this module only adds the browser-specific epochs
//! (Chrome/WebKit and Firefox PRTime) that the mobile parsers never needed.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

// Apple/Unix epoch helpers are shared with the mobile parsers; re-export the
// ones the macOS parsers use so they can import every timestamp helper from a
// single module.
pub(crate) use crate::parsers::mobile::common::timestamps::apple_absolute_to_json;

/// Microseconds between the Windows/WebKit epoch (1601-01-01) and the Unix
/// epoch (1970-01-01). Chrome, Edge, Brave and Safari's WebKit stack all count
/// microseconds since 1601-01-01 UTC.
const WEBKIT_TO_UNIX_MICROS: i64 = 11_644_473_600_000_000;

/// Chrome / Chromium / WebKit timestamp: microseconds since 1601-01-01 UTC.
pub(crate) fn chrome_webkit_to_json(value: Option<i64>) -> Value {
    match value {
        Some(micros) if micros > 0 => {
            let unix_micros = micros - WEBKIT_TO_UNIX_MICROS;
            micros_since_unix_to_json(value, "chrome_webkit_microseconds", unix_micros)
        }
        _ => Value::Null,
    }
}

/// Firefox PRTime: microseconds since 1970-01-01 UTC.
pub(crate) fn firefox_prtime_to_json(value: Option<i64>) -> Value {
    match value {
        Some(micros) if micros > 0 => {
            micros_since_unix_to_json(value, "firefox_prtime_microseconds", micros)
        }
        _ => Value::Null,
    }
}

fn micros_since_unix_to_json(
    original: Option<i64>,
    epoch: &'static str,
    unix_micros: i64,
) -> Value {
    let unix_ms = unix_micros.div_euclid(1_000);
    let seconds = unix_micros.div_euclid(1_000_000);
    let sub_micros = unix_micros.rem_euclid(1_000_000) as u32;
    let rfc3339 =
        DateTime::<Utc>::from_timestamp(seconds, sub_micros * 1_000).map(|dt| dt.to_rfc3339());

    json!({
        "original": original,
        "original_epoch": epoch,
        "unix_ms": unix_ms,
        "rfc3339": rfc3339,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_chrome_webkit_epoch() {
        // 13350000000000000 µs since 1601 → 2024-01-... . Use the epoch anchor.
        let ts = chrome_webkit_to_json(Some(WEBKIT_TO_UNIX_MICROS));
        assert_eq!(ts["unix_ms"], 0i64);
        assert_eq!(ts["rfc3339"], "1970-01-01T00:00:00+00:00");
    }

    #[test]
    fn converts_firefox_prtime() {
        let ts = firefox_prtime_to_json(Some(1_000_000));
        assert_eq!(ts["unix_ms"], 1_000i64);
        assert_eq!(ts["rfc3339"], "1970-01-01T00:00:01+00:00");
    }

    #[test]
    fn treats_non_positive_as_unset() {
        assert!(chrome_webkit_to_json(Some(0)).is_null());
        assert!(firefox_prtime_to_json(None).is_null());
    }
}
