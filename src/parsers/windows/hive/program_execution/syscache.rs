use serde_json::json;

use super::super::{hive_kind_prefix, registry_value_map, Artefact, Outcome, TrieNode as T};

pub const KIND: &str = hive_kind_prefix!("program_execution.syscache");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("DefaultObjectStore").sub(vec![
                T::lit("ObjectTable").sub(vec![T::any().emit(KIND, |object, cell| {
                    let values = registry_value_map(cell);
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
