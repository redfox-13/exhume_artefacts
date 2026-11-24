//! Epoch conversions shared by platform and application parsers.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

const APPLE_ABSOLUTE_TO_UNIX_SECONDS: f64 = 978_307_200.0;
const FILETIME_TO_UNIX_OFFSET_NS: i128 = 116_444_736_000_000_000;

pub(crate) fn apple_absolute_to_json(value: Option<f64>) -> Value {
    match value.and_then(apple_absolute_to_unix_ms) {
        Some(unix_ms) => {
            let seconds = unix_ms.div_euclid(1_000);
            let millis = unix_ms.rem_euclid(1_000) as u32;
            let nanos = millis * 1_000_000;
            let rfc3339 = DateTime::<Utc>::from_timestamp(seconds, nanos).map(|dt| dt.to_rfc3339());

            json!({
                "original": value,
                "original_epoch": "apple_absolute",
                "unix_ms": unix_ms,
                "rfc3339": rfc3339,
            })
        }
        None => Value::Null,
    }
}

pub(crate) fn apple_nanoseconds_to_json(value: Option<i64>) -> Value {
    match value.and_then(apple_nanoseconds_to_unix_ms) {
        Some(unix_ms) => {
            let seconds = unix_ms.div_euclid(1_000);
            let millis = unix_ms.rem_euclid(1_000) as u32;
            let nanos = millis * 1_000_000;
            let rfc3339 = DateTime::<Utc>::from_timestamp(seconds, nanos).map(|dt| dt.to_rfc3339());

            json!({
                "original": value,
                "original_epoch": "apple_absolute_nanoseconds",
                "unix_ms": unix_ms,
                "rfc3339": rfc3339,
            })
        }
        None => Value::Null,
    }
}

/// Epoch **milliseconds** (Android stores SMS/MMS dates this way).
pub(crate) fn unix_millis_to_json(value: Option<i64>) -> Value {
    match value {
        Some(unix_ms) if unix_ms > 0 => {
            let seconds = unix_ms.div_euclid(1_000);
            let millis = unix_ms.rem_euclid(1_000) as u32;
            let rfc3339 = DateTime::<Utc>::from_timestamp(seconds, millis * 1_000_000)
                .map(|dt| dt.to_rfc3339());

            json!({
                "original": value,
                "original_epoch": "unix_milliseconds",
                "unix_ms": unix_ms,
                "rfc3339": rfc3339,
            })
        }
        _ => Value::Null,
    }
}

pub(crate) fn unix_seconds_to_json(value: Option<i64>) -> Value {
    match value {
        Some(seconds) if seconds > 0 => {
            let rfc3339 = DateTime::<Utc>::from_timestamp(seconds, 0).map(|dt| dt.to_rfc3339());
            let unix_ms = seconds.checked_mul(1_000);

            json!({
                "original": value,
                "original_epoch": "unix_seconds",
                "unix_ms": unix_ms,
                "rfc3339": rfc3339,
            })
        }
        _ => Value::Null,
    }
}

pub(crate) fn windows_filetime_to_json(filetime: u64) -> Value {
    let unix_100ns = i128::from(filetime) - FILETIME_TO_UNIX_OFFSET_NS;

    let seconds = unix_100ns.div_euclid(10_000_000);
    let nanos = (unix_100ns.rem_euclid(10_000_000) * 100) as u32;

    let Ok(seconds) = i64::try_from(seconds) else {
        return Value::Null;
    };

    let Some(datetime) = DateTime::<Utc>::from_timestamp(seconds, nanos) else {
        return Value::Null;
    };

    json!({
        "original": filetime,
        "original_epoch": "windows_filetime",
        "unix_ms": datetime.timestamp_millis(),
        "rfc3339": datetime.to_rfc3339(),
    })
}


fn apple_absolute_to_unix_ms(value: f64) -> Option<i64> {
    if !value.is_finite() {
        return None;
    }

    let unix_seconds = value + APPLE_ABSOLUTE_TO_UNIX_SECONDS;
    let unix_ms = (unix_seconds * 1_000.0).round();
    if unix_ms < i64::MIN as f64 || unix_ms > i64::MAX as f64 {
        return None;
    }

    Some(unix_ms as i64)
}

fn apple_nanoseconds_to_unix_ms(value: i64) -> Option<i64> {
    if value <= 0 {
        return None;
    }

    let apple_ms = value.checked_div(1_000_000)?;
    apple_ms.checked_add(978_307_200_000)
}

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
    fn converts_apple_absolute_epoch() {
        let ts = apple_absolute_to_json(Some(0.0));
        assert_eq!(ts["unix_ms"], 978_307_200_000i64);
        assert_eq!(ts["rfc3339"], "2001-01-01T00:00:00+00:00");
    }

    #[test]
    fn converts_apple_absolute_nanoseconds() {
        let ts = super::apple_nanoseconds_to_json(Some(1_000_000_000));
        assert_eq!(ts["unix_ms"], 978_307_201_000i64);
        assert_eq!(ts["rfc3339"], "2001-01-01T00:00:01+00:00");
    }

    #[test]
    fn treats_zero_nanoseconds_as_unset() {
        assert!(super::apple_nanoseconds_to_json(Some(0)).is_null());
    }

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
