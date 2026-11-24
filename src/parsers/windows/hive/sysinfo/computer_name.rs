use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, parse_value_map, registry_value_map, value_text};

pub const KIND: &str = hive_kind_prefix!("sysinfo.computer_name");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::pre("ControlSet").sub(vec![
                T::lit("Control").sub(vec![T::lit("ComputerName").sub(vec![
                    T::lit("ComputerName").emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = format!("Configured computer name: {}", cell.key_name);
                        object
                            .data
                            .insert("configured_computer_name_values".into(), json!(values));
                        Outcome::Keep
                    }),
                    T::lit("ActiveComputerName").emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = format!("Active computer name: {}", cell.key_name);
                        object
                            .data
                            .insert("active_computer_name_values".into(), json!(values));
                        Outcome::Keep
                    }),
                ])]),
                T::lit("Services").sub(vec![T::lit("Tcpip").sub(vec![T::lit("Parameters").emit(
                    KIND,
                    |object, cell| {
                        let identity_values = parse_value_map(cell, |value| {
                            let name = value.get_pretty_name();
                            matches!(
                                name.to_ascii_lowercase().as_str(),
                                "hostname" | "nv hostname" | "domain" | "nv domain"
                            )
                            .then(|| {
                                (
                                    name,
                                    json!(value_text(value)),
                                )
                            })
                        });
                        object.text = "TCP/IP host and domain identity".into();
                        object
                            .data
                            .insert("tcpip_identity_values".into(), json!(identity_values));
                        Outcome::Keep
                    },
                )])]),
            ])]
        },
    }
}
