use serde_json::json;

use super::super::{hive_kind_prefix, registry_value_map, Artefact, Outcome, TrieNode as T};

pub const KIND: &str = hive_kind_prefix!("file_operations.typed_paths");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![
                T::lit("Software").sub(vec![T::lit("Microsoft").sub(vec![T::lit("Windows").sub(
                    vec![
                        T::lit("CurrentVersion").sub(vec![T::lit("Explorer").sub(vec![T::lit(
                            "TypedPaths",
                        )
                        .emit(KIND, |object, cell| {
                            let entries = registry_value_map(cell);
                            object.text = format!("Typed file paths: {} entries", entries.len());
                            object.data.insert("typed_file_paths".into(), json!(entries));
                            Outcome::Keep
                        })])]),
                    ],
                )])]),
            ]
        },
    }
}
