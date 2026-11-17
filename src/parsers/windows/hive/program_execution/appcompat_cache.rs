use serde_json::{json, Value};

use super::super::{hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("program_execution.appcompat_cache");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::pre("ControlSet").sub(vec![T::lit("Control").sub(vec![
                T::lit("Session Manager").sub(vec![
                    T::lit("AppCompatCache").emit(KIND, |object, cell| {
                        let values: Vec<Value> = parse_values(cell, |value| {
                            Some(json!({
                                "name": value.get_pretty_name(),
                                "value": super::super::value_text(value),
                            }))
                        });
                        object.text = "Application compatibility cache".into();
                        object
                            .data
                            .insert("appcompat_cache_properties".into(), json!(values));
                        Outcome::Keep
                    }),
                    T::lit("AppCompatibility").emit(KIND, |object, cell| {
                        let values: Vec<Value> = parse_values(cell, |value| {
                            Some(json!({
                                "name": value.get_pretty_name(),
                                "value": super::super::value_text(value),
                            }))
                        });
                        object.text = "Application compatibility data".into();
                        object
                            .data
                            .insert("application_compatibility_properties".into(), json!(values));
                        Outcome::Keep
                    }),
                ]),
            ])])]
        },
    }
}
