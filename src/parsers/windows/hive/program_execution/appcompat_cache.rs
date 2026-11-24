use serde_json::json;

use super::super::{hive_kind_prefix, registry_value_map, Artefact, Outcome, TrieNode as T};

pub const KIND: &str = hive_kind_prefix!("program_execution.appcompat_cache");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::pre("ControlSet").sub(vec![T::lit("Control").sub(vec![
                T::lit("Session Manager").sub(vec![
                    T::lit("AppCompatCache").emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "Application compatibility cache".into();
                        object
                            .data
                            .insert("appcompat_cache_properties".into(), json!(values));
                        Outcome::Keep
                    }),
                    T::lit("AppCompatibility").emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
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
