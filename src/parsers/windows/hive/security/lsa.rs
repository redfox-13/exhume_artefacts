use serde_json::{json, Value};

use super::super::{hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("security.lsa");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::pre("ControlSet").sub(vec![T::lit("Control").sub(vec![
                T::lit("Lsa").emit(KIND, |object, cell| {
                    let values: Vec<Value> = parse_values(cell, |value| {
                        Some(json!({
                            "name": value.get_pretty_name(),
                            "value": super::super::value_text(value),
                        }))
                    });
                    object.text = "LSA security configuration".into();
                    object
                        .data
                        .insert("lsa_configuration".into(), json!(values));
                    Outcome::Keep
                }),
            ])])]
        },
    }
}
