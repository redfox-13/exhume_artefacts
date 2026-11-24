use notatin::cell_key_node::CellKeyNode;
use serde_json::json;

use super::super::{Artefact, Outcome, ObjectOutput, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("network.interfaces");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![
                T::pre("ControlSet").sub(vec![
                    T::lit("Services").sub(vec![T::lit("Tcpip").sub(vec![
                        T::lit("Parameters").emit(KIND, tcpip_parameters).sub(vec![
                            T::lit("Interfaces").sub(vec![T::any().emit(KIND, interface)]),
                        ]),
                    ])]),
                    T::lit("Control").sub(vec![
                        T::lit("Network").sub(vec![
                            T::lit("{4d36e972-e325-11ce-bfc1-08002be10318}").sub(vec![
                                T::any().sub(vec![T::lit("Connection").emit(KIND, interface)]),
                            ]),
                        ]),
                        T::lit("NetworkSetup2").sub(vec![
                            T::lit("Interfaces").sub(vec![T::any().emit(KIND, interface)]),
                        ]),
                    ]),
                ]),
                T::lit("Microsoft").sub(vec![T::lit("Windows NT").sub(vec![
                    T::lit("CurrentVersion").sub(vec![
                        T::lit("NetworkCards").sub(vec![T::any().emit(KIND, interface)]),
                    ]),
                ])]),
            ]
        },
    }
}

fn interface(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let values = registry_value_map(cell);
    let interface_id = if cell.key_name.eq_ignore_ascii_case("Connection") {
        cell.path.split('\\').rev().nth(1).unwrap_or(&cell.key_name)
    } else {
        &cell.key_name
    };
    object.text = format!("Network interface configuration: {}", interface_id);
    object
        .data
        .insert("interface_id".into(), json!(interface_id));
    object
        .data
        .insert("network_interface_settings".into(), json!(values));
    Outcome::Keep
}

fn tcpip_parameters(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let settings = registry_value_map(cell);
    object.text = "Global TCP/IP parameters".into();
    object
        .data
        .insert("tcpip_global_settings".into(), json!(settings));
    Outcome::Keep
}
