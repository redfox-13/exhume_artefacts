use serde_json::{json, Value};

use super::super::{hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("system.computer_name");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::pre("ControlSet").sub(vec![T::lit("Control").sub(vec![
                T::lit("ComputerName").sub(vec![
                    T::lit("ComputerName").emit(KIND, |object, cell| {
                        let values: Vec<Value> = parse_values(cell, |value| {
                            Some(json!({
                                "name": value.get_pretty_name(),
                                "value": super::super::value_text(value),
                            }))
                        });
                        object.text = format!("Configured computer name: {}", cell.key_name);
                        object
                            .data
                            .insert("configured_computer_name_values".into(), json!(values));
                        Outcome::Keep
                    }),
                    T::lit("ActiveComputerName").emit(KIND, |object, cell| {
                        let values: Vec<Value> = parse_values(cell, |value| {
                            Some(json!({
                                "name": value.get_pretty_name(),
                                "value": super::super::value_text(value),
                            }))
                        });
                        object.text = format!("Active computer name: {}", cell.key_name);
                        object
                            .data
                            .insert("active_computer_name_values".into(), json!(values));
                        Outcome::Keep
                    }),
                ]),
            ])])]
        },
    }
}
