use serde_json::{json, Value};

use super::super::{hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("network.port_proxy");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::pre("ControlSet").sub(vec![T::lit("Services").sub(vec![
                T::lit("PortProxy").sub(vec![T::any().sub(vec![T::any().emit(
                    KIND,
                    |object, cell| {
                        let entries: Vec<Value> = parse_values(cell, |value| {
                            Some(json!({
                                "name": value.get_pretty_name(),
                                "mapping": super::super::value_text(value),
                            }))
                        });
                        object.text = format!("PortProxy {}: {} mappings", cell.path, entries.len());
                        object
                            .data
                            .insert("port_proxy_mappings".into(), json!(entries));
                        Outcome::Keep
                    },
                )])]),
            ])])]
        },
    }
}
