use chrono::{DateTime, Utc};
use serde_json::{Value, json};

const APPLE_ABSOLUTE_TO_UNIX_SECONDS: f64 = 978_307_200.0;

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

#[cfg(test)]
mod tests {
    use super::apple_absolute_to_json;

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
}
