use serde_json::{json, Value};

use super::super::{TrieNode as T, hive_kind_prefix, Artefact, Outcome, parse_values};

const KIND: &str = hive_kind_prefix!("persistence.run");

/// Microsoft\Windows\CurrentVersion\Run*, and Policies\Explorer\Run
pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![
                T::lit("Microsoft").sub(vec![
                    T::lit("Windows").sub(vec![
                        T::lit("CurrentVersion").sub(vec![
                            T::pre("Run").emit(KIND, |object, cell| {
                                let entries: Vec<Value> =
                                    parse_values(cell, |value| {
                                        Some(json!({
                                            "name": value.get_pretty_name(),
                                            "command": super::super::value_text(value),
                                        }))
                                    });
                                object.text = format!(
                                    "RUN KEY {}: {} entries",
                                    cell.key_name,
                                    entries.len()
                                );
                                object.data.insert("run_commands".into(), json!(entries));
                                Outcome::Keep
                            }),
                            T::lit("Policies").sub(vec![
                                T::lit("Explorer").sub(vec![
                                    T::lit("Run").emit(KIND, |object, cell| {
                                        let entries: Vec<Value> =
                                            parse_values(cell, |value| {
                                                Some(json!({
                                                    "name": value.get_pretty_name(),
                                                    "command": super::super::value_text(value),
                                                }))
                                            });
                                        object.text = format!(
                                            "RUN KEY {}: {} entries",
                                            cell.key_name,
                                            entries.len()
                                        );
                                        object.data.insert("run_commands".into(), json!(entries));
                                        Outcome::Keep
                                    }),
                                ]),
                            ]),
                        ]),
                    ]),
                ]),
            ]
        },
    }
}
