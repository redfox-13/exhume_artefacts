use serde_json::{json, Map, Value};

use super::super::{TrieNode as T, hive_kind_prefix, Artefact, Outcome, parse_values};

const KIND: &str = hive_kind_prefix!("persistence.session_manager");

/// ControlSet\Control\Session Manager
pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![
                T::pre("ControlSet").sub(vec![
                    T::lit("Control").sub(vec![
                        T::lit("Session Manager").emit(KIND, |object, cell| {
                            let values: Map<String, Value> =
                                parse_values(cell, |value| {
                                    let data = super::super::value_text(value);
                                    match value.get_pretty_name().to_lowercase().as_str() {
                                        "bootexecute" => Some(("boot_execute".into(), json!(data))),
                                        "setupexecute" => {
                                            Some(("setup_execute".into(), json!(data)))
                                        }
                                        "pendingfilerenameoperations" => Some((
                                            "pending_file_rename_operations".into(),
                                            json!(data),
                                        )),
                                        _ => None,
                                    }
                                });
                            object.text = format!(
                                "SESSION MANAGER: BootExecute: {}",
                                values
                                    .get("boot_execute")
                                    .and_then(Value::as_str)
                                    .unwrap_or("Unknown"),
                            );
                            object.data = values;
                            Outcome::Keep
                        }),
                    ]),
                ]),
            ]
        },
    }
}
