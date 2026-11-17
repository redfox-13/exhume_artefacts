use serde_json::{json, Value};

use super::super::{hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("file_operations.recent_docs");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Software").sub(vec![T::lit("Microsoft").sub(vec![
                T::lit("Windows").sub(vec![T::lit("CurrentVersion").sub(vec![
                    T::lit("Explorer").sub(vec![T::lit("RecentDocs").emit(
                        KIND,
                        |object, cell| {
                            let entries: Vec<Value> = parse_values(cell, |value| {
                                Some(json!({
                                    "name": value.get_pretty_name(),
                                    "value": super::super::value_text(value),
                                }))
                            });
                            object.text = format!("Recent documents: {} entries", entries.len());
                            object.data.insert("recent_documents".into(), json!(entries));
                            Outcome::Keep
                        },
                    )]),
                ])]),
            ])]) ]
        },
    }
}
