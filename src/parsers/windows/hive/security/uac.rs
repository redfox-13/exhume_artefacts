use serde_json::{json, Value};

use super::super::{hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("security.uac");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Software").sub(vec![T::lit("Microsoft").sub(vec![
                T::lit("Windows").sub(vec![T::lit("CurrentVersion").sub(vec![
                    T::lit("Policies").sub(vec![T::lit("System").emit(
                        KIND,
                        |object, cell| {
                            let values: Vec<Value> = parse_values(cell, |value| {
                                Some(json!({
                                    "name": value.get_pretty_name(),
                                    "value": super::super::value_text(value),
                                }))
                            });
                            object.text = "User Account Control policy".into();
                            object
                                .data
                                .insert("uac_policy_settings".into(), json!(values));
                            Outcome::Keep
                        },
                    )]),
                ])]),
            ])])]
        },
    }
}
