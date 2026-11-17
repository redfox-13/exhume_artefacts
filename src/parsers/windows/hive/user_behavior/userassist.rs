use serde_json::{json, Value};

use super::super::{hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("user_behavior.userassist");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Software").sub(vec![
                T::lit("Microsoft").sub(vec![
                    T::lit("Windows").sub(vec![
                        T::lit("CurrentVersion").sub(vec![
                            T::lit("Explorer").sub(vec![
                                T::lit("UserAssist").sub(vec![
                                    T::any().sub(vec![T::lit("Count").emit(
                                        KIND,
                                        |object, cell| {
                                            let entries: Vec<Value> =
                                                parse_values(cell, |value| {
                                                    let encoded_name = value.get_pretty_name();
                                                    let decoded_name: String = encoded_name
                                                        .chars()
                                                        .map(|character| match character {
                                                            'A'..='M' | 'a'..='m' => {
                                                                ((character as u8) + 13) as char
                                                            },
                                                            'n'..='z' | 'N'..='Z' => {
                                                                ((character as u8) - 13) as char
                                                            }
                                                            _ => character,
                                                        })
                                                        .collect();
                                                    Some(json!({
                                                        "name": decoded_name,
                                                        "encoded_name": encoded_name,
                                                    }))
                                                });
                                            object.text =
                                                format!("UserAssist: {} entries", entries.len());
                                            object
                                                .data
                                                .insert("user_assist_activity".into(), json!(entries));
                                            Outcome::Keep
                                        },
                                    )]),
                                ]),
                            ]),
                        ]),
                    ]),
                ]),
            ])]
        },
    }
}
