use serde_json::json;

use super::super::{hive_kind_prefix, parse_value_map, value_text, Artefact, Outcome, TrieNode as T};

pub const KIND: &str = hive_kind_prefix!("network.port_proxy");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::pre("ControlSet").sub(vec![T::lit("Services").sub(vec![
                T::lit("PortProxy").sub(vec![T::any().sub(vec![T::any().emit(
                    KIND,
                    |object, cell| {
                        let entries = parse_value_map(cell, |value| {
                            Some((
                                value.get_pretty_name(),
                                json!(value_text(value)),
                            ))
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
