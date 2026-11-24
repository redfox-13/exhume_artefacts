use serde_json::{Value, json};

use crate::formats::timestamps::windows_filetime_to_json;

use super::super::{
    Artefact, Outcome, TrieNode as T, hive_kind_prefix, parse_value_map, value_text
};

pub const KIND: &str = hive_kind_prefix!("browser_activity.typed_urls");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Software").sub(vec![T::lit("Microsoft").sub(vec![
                T::lit("Internet Explorer").sub(vec![
                    T::lit("TypedURLs").emit(KIND, |object, cell| {
                        let entries = parse_value_map(cell, |value| {
                            Some((
                                value.get_pretty_name(),
                                json!(value_text(value)),
                            ))
                        });
                        object.text = format!("Typed URLs: {} entries", entries.len());
                        object.data.insert("typed_urls".into(), json!(entries));
                        Outcome::Keep
                    }),
                    T::lit("TypedURLsTime").emit(KIND, |object, cell| {
                        let timestamps = parse_value_map(cell, |value| {
                            let bytes = value.detail.value_bytes().unwrap_or_default();
                            let timestamp = bytes
                                .get(..8)
                                .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                                .map(u64::from_le_bytes)
                                .map(windows_filetime_to_json)
                                .unwrap_or(Value::Null);
                            Some((value.get_pretty_name(), timestamp))
                        });
                        object.text = format!("Typed URL timestamps: {} entries", timestamps.len());
                        object
                            .data
                            .insert("typed_url_timestamps".into(), json!(timestamps));
                        Outcome::Keep
                    }),
                ]),
            ])])]
        },
    }
}
