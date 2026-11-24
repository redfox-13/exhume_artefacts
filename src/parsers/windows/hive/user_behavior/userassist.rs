use serde_json::json;

use super::super::{hive_kind_prefix, parse_value_map, Artefact, Outcome, TrieNode as T};

pub const KIND: &str = hive_kind_prefix!("user_behavior.userassist");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
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
                                            let entries = parse_value_map(cell, |value| {
                                                let encoded_name = value.get_pretty_name();
                                                let decoded_name: String = encoded_name
                                                    .chars()
                                                    .map(|character| match character {
                                                        'A'..='M' | 'a'..='m' => {
                                                            ((character as u8) + 13) as char
                                                        }
                                                        'n'..='z' | 'N'..='Z' => {
                                                            ((character as u8) - 13) as char
                                                        }
                                                        _ => character,
                                                    })
                                                    .collect();
                                                Some((
                                                    decoded_name,
                                                    json!({ "encoded_name": encoded_name }),
                                                ))
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
