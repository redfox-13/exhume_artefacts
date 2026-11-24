use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("persistence.image_file_execution_options");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let image_file_execution_options = || {
                T::lit("Windows NT").sub(vec![T::lit("CurrentVersion").sub(vec![
                    T::lit("Image File Execution Options").sub(vec![T::any().emit(
                        KIND,
                        |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = format!("Image execution options: {}", cell.key_name);
                            object
                                .data
                                .insert("image_name".into(), json!(cell.key_name));
                            object
                                .data
                                .insert("image_execution_options".into(), json!(values));
                            Outcome::Keep
                        },
                    )]),
                ])])
            };
            vec![
                T::lit("Microsoft").sub(vec![image_file_execution_options()]),
                T::lit("Wow6432Node").sub(vec![
                    T::lit("Microsoft").sub(vec![image_file_execution_options()]),
                ]),
                T::lit("Software").sub(vec![
                    T::lit("Microsoft").sub(vec![image_file_execution_options()]),
                    T::lit("Wow6432Node").sub(vec![
                        T::lit("Microsoft").sub(vec![image_file_execution_options()]),
                    ]),
                ]),
            ]
        },
    }
}
