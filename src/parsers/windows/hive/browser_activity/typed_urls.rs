use serde_json::{json, Value};

use super::super::{
    filetime_to_rfc3339, hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T,
};

const KIND: &str = hive_kind_prefix!("browser_activity.typed_urls");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Software").sub(vec![
                T::lit("Microsoft").sub(vec![
                    T::lit("Internet Explorer").sub(vec![
                        T::lit("TypedURLs").emit(KIND, |object, cell| {
                            let entries: Vec<Value> = parse_values(cell, |value| {
                                Some(json!({
                                    "name": value.get_pretty_name(),
                                    "url": super::super::value_text(value),
                                }))
                            });
                            object.text = format!("Typed URLs: {} entries", entries.len());
                            object.data.insert("typed_urls".into(), json!(entries));
                            Outcome::Keep
                        }),
                        T::lit("TypedURLsTime").emit(KIND, |object, cell| {
                            let timestamps: Vec<Value> = parse_values(cell, |value| {
                                let bytes = value.detail.value_bytes().unwrap_or_default();
                                let timestamp = bytes
                                    .get(..8)
                                    .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                                    .map(u64::from_le_bytes)
                                    .map(filetime_to_rfc3339)
                                    .unwrap_or(Value::Null);
                                Some(json!({
                                    "url_name": value.get_pretty_name(),
                                    "timestamp": timestamp,
                                }))
                            });
                            object.text =
                                format!("Typed URL timestamps: {} entries", timestamps.len());
                            object
                                .data
                                .insert("typed_url_timestamps".into(), json!(timestamps));
                            Outcome::Keep
                        }),
                    ]),
                ]),
            ])]
        },
    }
}
