use serde_json::{json, Map, Value};

use super::super::{hive_kind_prefix, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("persistence.appinit");

/// Microsoft\Windows NT\CurrentVersion\Windows
pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![
                T::lit("Microsoft").sub(vec![
                    T::lit("Windows NT").sub(vec![
                        T::lit("CurrentVersion").sub(vec![
                            T::lit("Windows").emit(KIND, |object, cell| {
                                let values: Map<String, Value> =
                                    super::super::parse_values(cell, |value| {
                                        let data = super::super::value_text(value);
                                        match value.get_pretty_name().to_lowercase().as_str() {
                                            "appinit_dlls" => {
                                                Some(("appinit_dlls".into(), json!(data)))
                                            }
                                            "loadappinit_dlls" => {
                                                Some(("load_appinit_dlls".into(), json!(data)))
                                            }
                                            "load" => Some(("load".into(), json!(data))),
                                            "run" => Some(("run".into(), json!(data))),
                                            _ => None,
                                        }
                                    });
                                object.text = format!(
                                    "APPINIT: {}",
                                    values
                                        .get("appinit_dlls")
                                        .and_then(Value::as_str)
                                        .unwrap_or("Unknown"),
                                );
                                object.data = values;
                                Outcome::Keep
                            }),
                        ]),
                    ]),
                ]),
            ]
        },
    }
}
