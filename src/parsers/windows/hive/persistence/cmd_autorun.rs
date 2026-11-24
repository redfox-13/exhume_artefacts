use serde_json::{Value, json};

use super::super::{
    Artefact, Outcome, TrieNode as T, hive_kind_prefix, parse_value_map, value_text,
};

pub const KIND: &str = hive_kind_prefix!("persistence.command_processor");

/// Microsoft\Command Processor
pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let command_processor_key = || {
                T::lit("Command Processor").emit(KIND, |object, cell| {
                    let values = parse_value_map(cell, |value| {
                        match value.get_pretty_name().to_lowercase().as_str() {
                            "autorun" => {
                                Some(("autorun".into(), json!(value_text(value))))
                            }
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
                })
            };
            vec![
                T::lit("Microsoft").sub(vec![command_processor_key()]),
                T::lit("Software")
                    .sub(vec![T::lit("Microsoft").sub(vec![command_processor_key()])]),
            ]
        },
    }
}
