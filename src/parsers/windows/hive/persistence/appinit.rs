use serde_json::{Value, json};

use super::super::{
    Artefact, Outcome, TrieNode as T, hive_kind_prefix, parse_value_map, value_text,
};

pub const KIND: &str = hive_kind_prefix!("persistence.appinit");

/// Microsoft\Windows NT\CurrentVersion\Windows
pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let appinit_key = || {
                T::lit("Windows").emit(KIND, |object, cell| {
                    let values = parse_value_map(cell, |value| {
                        let data = value_text(value);
                        match value.get_pretty_name().to_lowercase().as_str() {
                            "appinit_dlls" => Some(("appinit_dlls".into(), json!(data))),
                            "loadappinit_dlls" => Some(("load_appinit_dlls".into(), json!(data))),
                            "requiresignedappinit_dlls" => {
                                Some(("require_signed_appinit_dlls".into(), json!(data)))
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
                })
            };
            vec![
                T::lit("Microsoft")
                    .sub(vec![T::lit("Windows NT").sub(vec![
                        T::lit("CurrentVersion").sub(vec![appinit_key()]),
                    ])]),
                T::lit("Wow6432Node").sub(vec![T::lit("Microsoft").sub(vec![
                    T::lit("Windows NT").sub(vec![T::lit("CurrentVersion").sub(vec![
                        appinit_key(),
                    ])]),
                ])]),
            ]
        },
    }
}
