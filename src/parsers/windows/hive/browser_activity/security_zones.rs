use notatin::cell_key_node::CellKeyNode;
use serde_json::json;

use super::super::{Artefact, Outcome, ObjectOutput, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("browser_activity.security_zones");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let internet_settings_tree = || {
                T::lit("Windows").sub(vec![T::lit("CurrentVersion").sub(vec![
                    T::lit("Internet Settings").sub(vec![
                        T::lit("Zones").sub(vec![T::any().emit(KIND, zone_settings)]),
                        T::lit("ZoneMap").sub(vec![
                            T::lit("Domains").sub(vec![zone_map_nodes(6)]),
                            T::lit("EscDomains").sub(vec![zone_map_nodes(6)]),
                            T::lit("Ranges").sub(vec![zone_map_nodes(4)]),
                            T::lit("ProtocolDefaults").emit(KIND, zone_settings),
                        ]),
                    ]),
                ])])
            };
            vec![
                T::lit("Microsoft").sub(vec![internet_settings_tree()]),
                T::lit("Software").sub(vec![
                    T::lit("Microsoft").sub(vec![internet_settings_tree()]),
                    T::lit("Policies").sub(vec![T::lit("Microsoft").sub(vec![
                        T::lit("Windows").sub(vec![T::lit("CurrentVersion").sub(vec![
                            T::lit("Internet Settings").emit(KIND, zone_settings),
                        ])]),
                        T::lit("Internet Explorer")
                            .emit(KIND, zone_settings)
                            .sub(vec![T::any().emit(KIND, zone_settings)]),
                    ])]),
                ]),
                T::lit("Policies").sub(vec![T::lit("Microsoft").sub(vec![
                    T::lit("Windows").sub(vec![T::lit("CurrentVersion").sub(vec![
                        T::lit("Internet Settings").emit(KIND, zone_settings),
                    ])]),
                    T::lit("Internet Explorer")
                        .emit(KIND, zone_settings)
                        .sub(vec![T::any().emit(KIND, zone_settings)]),
                ])]),
            ]
        },
    }
}

fn zone_map_nodes(depth: u8) -> T {
    let node = T::any().emit(KIND, zone_settings);
    if depth == 0 {
        node
    } else {
        node.sub(vec![zone_map_nodes(depth - 1)])
    }
}

fn zone_settings(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let values = registry_value_map(cell);
    let zone_id = cell.key_name.parse::<u8>().ok();
    let zone_name = match zone_id {
        Some(0) => Some("my_computer"),
        Some(1) => Some("local_intranet"),
        Some(2) => Some("trusted_sites"),
        Some(3) => Some("internet"),
        Some(4) => Some("restricted_sites"),
        _ => None,
    };
    object.text = format!("Browser security-zone settings: {}", cell.key_name);
    object
        .data
        .insert("zone_registry_key".into(), json!(cell.key_name));
    object.data.insert("zone_id".into(), json!(zone_id));
    object.data.insert("zone_name".into(), json!(zone_name));
    object
        .data
        .insert("browser_security_settings".into(), json!(values));
    Outcome::Keep
}
