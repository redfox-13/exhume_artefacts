use serde_json::json;

use super::super::{hive_kind_prefix, parse_value_map, value_text, Artefact, Outcome, TrieNode as T};

pub const KIND: &str = hive_kind_prefix!("persistence.appcert_dlls");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::pre("ControlSet").sub(vec![T::lit("Control").sub(vec![
                T::lit("Session Manager").sub(vec![T::lit("AppCertDlls").emit(
                    KIND,
                    |object, cell| {
                        let entries = parse_value_map(cell, |value| {
                            Some((
                                value.get_pretty_name(),
                                json!(value_text(value)),
                            ))
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
