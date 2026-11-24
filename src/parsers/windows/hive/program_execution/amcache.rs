use serde_json::json;

use super::super::{hive_kind_prefix, registry_value_map, Artefact, Outcome, TrieNode as T};

pub const KIND: &str = hive_kind_prefix!("program_execution.amcache");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Root").sub(vec![
                T::lit("InventoryApplicationFile").sub(vec![T::any().emit(
                    KIND,
                    |object, cell| {
                        let values = registry_value_map(cell);
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
                        let values = registry_value_map(cell);
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
