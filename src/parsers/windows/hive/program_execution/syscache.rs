use serde_json::{json, Value};

use super::super::{hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("program_execution.syscache");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("DefaultObjectStore").sub(vec![
                T::lit("ObjectTable").sub(vec![T::any().emit(KIND, |object, cell| {
                    let values: Vec<Value> = parse_values(cell, |value| {
                        Some(json!({
                            "name": value.get_pretty_name(),
                            "value": super::super::value_text(value),
                        }))
                    });
                    object.text = format!("Syscache file record: {}", cell.key_name);
                    object.data.insert("record_id".into(), json!(cell.key_name));
                    object
                        .data
                        .insert("syscache_record_properties".into(), json!(values));
                    Outcome::Keep
                })]),
            ])]
        },
    }
}
