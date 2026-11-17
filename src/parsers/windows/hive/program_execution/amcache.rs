use serde_json::{json, Value};

use super::super::{hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("program_execution.amcache");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Root").sub(vec![
                T::lit("InventoryApplicationFile").sub(vec![T::any().emit(
                    KIND,
                    |object, cell| {
                        let values: Vec<Value> = parse_values(cell, |value| {
                            Some(json!({
                                "name": value.get_pretty_name(),
                                "value": super::super::value_text(value),
                            }))
                        });
                        object.text = format!("Amcache file entry: {}", cell.key_name);
                        object.data.insert("file_entry".into(), json!(cell.key_name));
                        object
                            .data
                            .insert("file_inventory_properties".into(), json!(values));
                        Outcome::Keep
                    },
                )]),
                T::lit("InventoryApplication").sub(vec![T::any().emit(
                    KIND,
                    |object, cell| {
                        let values: Vec<Value> = parse_values(cell, |value| {
                            Some(json!({
                                "name": value.get_pretty_name(),
                                "value": super::super::value_text(value),
                            }))
                        });
                        object.text = format!("Amcache application entry: {}", cell.key_name);
                        object.data.insert("application_entry".into(), json!(cell.key_name));
                        object
                            .data
                            .insert("application_inventory_properties".into(), json!(values));
                        Outcome::Keep
                    },
                )]),
            ])]
        },
    }
}
