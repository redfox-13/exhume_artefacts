use serde_json::{json, Map, Value};

use super::super::{hive_kind_prefix, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("persistence.command_processor");

/// Microsoft\Command Processor
pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![
                T::lit("Microsoft").sub(vec![
                    T::lit("Command Processor").emit(KIND, |object, cell| {
                        let values: Map<String, Value> =
                            super::super::parse_values(cell, |value| {
                                match value.get_pretty_name().to_lowercase().as_str() {
                                    "autorun" => Some((
                                        "autorun".into(),
                                        json!(super::super::value_text(value)),
                                    )),
                                    _ => None,
                                }
                            });
                        object.text = format!(
                            "COMMAND PROCESSOR AUTORUN: {}",
                            values
                                .get("autorun")
                                .and_then(Value::as_str)
                                .unwrap_or("Not set"),
                        );
                        object.data = values;
                        Outcome::Keep
                    }),
                ]),
            ]
        },
    }
}
