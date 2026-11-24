use notatin::cell_key_node::CellKeyNode;
use serde_json::json;

use super::super::{Artefact, Outcome, ObjectOutput, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("network.proxy_settings");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let internet_settings_path = || {
                T::lit("Windows").sub(vec![T::lit("CurrentVersion").sub(vec![
                    T::lit("Internet Settings")
                        .emit(KIND, proxy_values)
                        .sub(vec![T::lit("Connections").emit(KIND, proxy_values)]),
                ])])
            };
            vec![
                T::lit("Microsoft").sub(vec![internet_settings_path()]),
                T::lit("Software").sub(vec![
                    T::lit("Microsoft").sub(vec![internet_settings_path()]),
                ]),
                T::lit("Policies").sub(vec![T::lit("Microsoft").sub(vec![T::lit("Windows").sub(
                    vec![T::lit("CurrentVersion").sub(vec![
                        T::lit("Internet Settings").emit(KIND, proxy_values),
                    ])],
                )])]),
                T::lit("Software").sub(vec![T::lit("Policies").sub(vec![
                    T::lit("Microsoft").sub(vec![
                        T::lit("Windows").sub(vec![T::lit("CurrentVersion").sub(vec![
                            T::lit("Internet Settings").emit(KIND, proxy_values),
                        ])]),
                        T::lit("Internet Explorer").emit(KIND, proxy_values),
                    ]),
                ])]),
            ]
        },
    }
}

fn proxy_values(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let settings = registry_value_map(cell);
    object.text = format!("Internet proxy settings: {}", cell.key_name);
    object.data.insert("proxy_settings".into(), json!(settings));
    Outcome::Keep
}
