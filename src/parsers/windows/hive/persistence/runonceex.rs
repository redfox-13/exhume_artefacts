use serde_json::{json, Value};

use super::super::{hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("persistence.runonce_ex");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Software").sub(vec![T::lit("Microsoft").sub(vec![
                T::lit("Windows").sub(vec![T::lit("CurrentVersion").sub(vec![
                    T::lit("RunOnceEx").sub(vec![T::any().emit(
                        KIND,
                        |object, cell| {
                            let values: Vec<Value> = parse_values(cell, |value| {
                                Some(json!({
                                    "name": value.get_pretty_name(),
                                    "command": super::super::value_text(value),
                                }))
                            });
                            object.text = format!("RunOnceEx entry: {}", cell.key_name);
                            object.data.insert("entry_id".into(), json!(cell.key_name));
                            object
                                .data
                                .insert("runonceex_commands".into(), json!(values));
                            Outcome::Keep
                        },
                    )]),
                ])]),
            ])])]
        },
    }
}
