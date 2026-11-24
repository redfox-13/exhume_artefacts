use serde_json::{json, Value};
use notatin::cell_key_value::CellKeyValueDataTypes;

use crate::formats::timestamps::windows_filetime_to_json;

use super::super::{
    hive_kind_prefix, parse_value_map, Artefact, Outcome, TrieNode as T,
};

pub const KIND: &str = hive_kind_prefix!("program_execution.bam");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::pre("ControlSet").sub(vec![T::lit("Services").sub(vec![
                T::lit("bam").sub(vec![T::lit("State").sub(vec![T::lit("UserSettings").sub(vec![
                    T::any().emit(KIND, |object, cell| {
                        let entries = parse_value_map(cell, |value| {
                            if value.data_type != CellKeyValueDataTypes::REG_BIN {
                                return None;
                            }

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
                        let record_status = if entries.is_empty() {
                            object.text = format!(
                                "BAM user {}: no REG_BINARY execution records",
                                cell.key_name
                            );
                            "no_reg_binary_records"
                        } else {
                            object.text =
                                format!("BAM user {}: {} entries", cell.key_name, entries.len());
                            "reg_binary_records_found"
                        };
                        object.data.insert("user_sid".into(), json!(cell.key_name));
                        object
                            .data
                            .insert("record_status".into(), json!(record_status));
                        object
                            .data
                            .insert("bam_execution_records".into(), json!(entries));
                        Outcome::Keep
                    }),
                ])])]),
            ])])]
        },
    }
}
