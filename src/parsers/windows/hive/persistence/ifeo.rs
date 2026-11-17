use serde_json::{json, Value};

use super::super::{hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("persistence.image_file_execution_options");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Software").sub(vec![
                T::lit("Microsoft").sub(vec![
                    T::lit("Windows NT").sub(vec![
                        T::lit("CurrentVersion").sub(vec![
                            T::lit("Image File Execution Options").sub(vec![T::any().emit(
                                KIND,
                                |object, cell| {
                                    let values: Vec<Value> = parse_values(cell, |value| {
                                        Some(json!({
                                            "name": value.get_pretty_name(),
                                            "value": super::super::value_text(value),
                                        }))
                                    });
                                    object.text =
                                        format!("Image execution options: {}", cell.key_name);
                                    object.data.insert("image_name".into(), json!(cell.key_name));
                                    object
                                        .data
                                        .insert("image_execution_options".into(), json!(values));
                                    Outcome::Keep
                                },
                            )]),
                        ]),
                    ]),
                ]),
            ])]
        },
    }
}
