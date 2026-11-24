use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, parse_value_map, value_text};

pub const KIND: &str = hive_kind_prefix!("persistence.runonce_ex");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let runonceex_path = || {
                T::lit("Windows").sub(vec![T::lit("CurrentVersion").sub(vec![
                    T::lit("RunOnceEx").sub(vec![T::any().emit(KIND, |object, cell| {
                        let values = parse_value_map(cell, |value| {
                            Some((
                                value.get_pretty_name(),
                                json!(value_text(value)),
                            ))
                        });
                        object.text = format!("RunOnceEx entry: {}", cell.key_name);
                        object.data.insert("entry_id".into(), json!(cell.key_name));
                        object
                            .data
                            .insert("runonceex_commands".into(), json!(values));
                        Outcome::Keep
                    })]),
                ])])
            };
            vec![
                T::lit("Microsoft").sub(vec![runonceex_path()]),
                T::lit("Software").sub(vec![T::lit("Microsoft").sub(vec![runonceex_path()])]),
            ]
        },
    }
}
