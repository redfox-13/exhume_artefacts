use serde_json::{json, Value};

use crate::formats::timestamps::windows_filetime_to_json;

use super::super::{hive_kind_prefix, parse_value_map, Artefact, Outcome, TrieNode as T};

pub const KIND: &str = hive_kind_prefix!("program_execution.dam");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::pre("ControlSet").sub(vec![T::lit("Services").sub(vec![
                T::lit("dam").sub(vec![T::lit("State").sub(vec![T::lit("UserSettings").sub(vec![
                    T::any().emit(KIND, |object, cell| {
                        let entries = parse_value_map(cell, |value| {
                            let bytes = value.detail.value_bytes().unwrap_or_default();
                            let timestamp = bytes
                                .get(..8)
                                .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                                .map(u64::from_le_bytes)
                                .map(windows_filetime_to_json)
                                .unwrap_or(Value::Null);
                            Some((
                                value.get_pretty_name(),
                                json!({ "last_execution_time": timestamp }),
                            ))
                        });
                        object.text = format!("DAM user {}: {} entries", cell.key_name, entries.len());
                        object.data.insert("user_sid".into(), json!(cell.key_name));
                        object
                            .data
                            .insert("dam_execution_records".into(), json!(entries));
                        Outcome::Keep
                    }),
                ])])]),
            ])])]
        },
    }
}
