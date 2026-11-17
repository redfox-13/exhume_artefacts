use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

use super::super::{Artefact, Outcome, TrieNode as T, filetime_to_rfc3339, parse_values};

const KIND: &str = "windows.hive.windows_version";

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Microsoft").sub(vec![T::lit("Windows NT").sub(vec![
                T::lit("CurrentVersion").emit(KIND, |object, cell| {
                    let values: Map<String, Value> = parse_values(cell, |value| {
                        Some((
                            value.get_pretty_name().to_ascii_lowercase(),
                            json!(super::super::value_text(value)),
                        ))
                    });
                    let text = |name: &str| {
                        values
                            .get(name)
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    };
                    let Some(product_name) = text("productname") else {
                        return Outcome::Skip;
                    };
                    let install_date = text("installdate")
                        .and_then(|value| value.parse::<i64>().ok())
                        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
                        .map(|date| date.to_rfc3339());
                    let install_time = text("installtime")
                        .and_then(|value| value.parse::<u64>().ok())
                        .map(filetime_to_rfc3339)
                        .and_then(|time| time.get("timestamp_rfc3339").cloned());

                    object.text = format!(
                        "Windows system information: {} (build {})",
                        product_name,
                        text("currentbuild").unwrap_or_else(|| "?".into())
                    );
                    object.data.insert("product_name".into(), json!(product_name));
                    object
                        .data
                        .insert("release_id".into(), json!(text("releaseid")));
                    object.data.insert(
                        "display_version".into(),
                        json!(text("displayversion")),
                    );
                    object
                        .data
                        .insert("csd_version".into(), json!(text("csdversion")));
                    object
                        .data
                        .insert("current_build".into(), json!(text("currentbuild")));
                    object.data.insert(
                        "ubr".into(),
                        json!(text("ubr").and_then(|value| value.parse::<u32>().ok())),
                    );
                    object
                        .data
                        .insert("build_lab".into(), json!(text("buildlab")));
                    object
                        .data
                        .insert("build_lab_ex".into(), json!(text("buildlabex")));
                    object.data.insert(
                        "edition_id".into(),
                        json!(text("compositioneditionid")),
                    );
                    object.data.insert(
                        "registered_organization".into(),
                        json!(text("registeredorganization")),
                    );
                    object.data.insert(
                        "registered_owner".into(),
                        json!(text("registeredowner")),
                    );
                    object.data.insert("install_date".into(), json!(install_date));
                    object.data.insert("install_time".into(), json!(install_time));
                    Outcome::Keep
                }),
            ])])]
        },
    }
}
