use serde_json::{json, Value};

use super::super::{hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("persistence.appcert_dlls");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::pre("ControlSet").sub(vec![T::lit("Control").sub(vec![
                T::lit("Session Manager").sub(vec![T::lit("AppCertDlls").emit(
                    KIND,
                    |object, cell| {
                        let entries: Vec<Value> = parse_values(cell, |value| {
                            Some(json!({
                                "name": value.get_pretty_name(),
                                "dll_path": super::super::value_text(value),
                            }))
                        });
                        object.text = format!("AppCertDlls persistence: {} entries", entries.len());
                        object
                            .data
                            .insert("appcert_dll_registrations".into(), json!(entries));
                        Outcome::Keep
                    },
                )]),
            ])])]
        },
    }
}
