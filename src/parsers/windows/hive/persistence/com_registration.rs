use notatin::cell_key_node::CellKeyNode;
use serde_json::json;

use super::super::{
    Artefact, ObjectOutput, Outcome, TrieNode as T, hive_kind_prefix, parse_value_map, value_text
};

pub const KIND: &str = hive_kind_prefix!("persistence.com_registration");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let clsid_tree = || {
                T::lit("CLSID").sub(vec![T::any().combine(KIND, class_registration).sub(vec![
                    T::any().combine(KIND, class_subkey),
                    T::lit("InprocServer32").emit(KIND, com_server),
                    T::lit("InprocHandler32").emit(KIND, com_server),
                    T::lit("LocalServer32").emit(KIND, com_server),
                ])])
            };
            vec![
                T::lit("Classes").sub(vec![
                    clsid_tree(),
                    T::lit("Wow6432Node").sub(vec![clsid_tree()]),
                ]),
                T::lit("Software").sub(vec![T::lit("Classes").sub(vec![
                    clsid_tree(),
                    T::lit("Wow6432Node").sub(vec![clsid_tree()]),
                ])]),
                clsid_tree(),
                T::lit("Wow6432Node").sub(vec![clsid_tree()]),
            ]
        },
    }
}

fn class_registration(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let properties = parse_value_map(cell, |value| {
        Some((
            value.get_pretty_name(),
            json!(value_text(value)),
        ))
    });
    object.text = format!("COM class registration: {}", cell.key_name);
    object.data.insert("class_id".into(), json!(cell.key_name));
    object
        .data
        .insert("class_registration_values".into(), json!(properties));
    object.data.insert("class_subkeys".into(), json!([]));
    Outcome::Keep
}

fn class_subkey(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    object
        .data
        .entry("class_subkeys")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .expect("class_subkeys is initialized as an array")
        .push(json!(cell.key_name));
    Outcome::Keep
}

fn com_server(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let values = parse_value_map(cell, |value| {
        Some((
            value.get_pretty_name(),
            json!(value_text(value)),
        ))
    });
    let class_id = cell.path.split('\\').rev().nth(1).unwrap_or_default();
    object.text = format!("COM server registration: {} ({})", class_id, cell.key_name);
    object.data.insert("class_id".into(), json!(class_id));
    object
        .data
        .insert("server_type".into(), json!(cell.key_name));
    object.data.insert("server_values".into(), json!(values));
    Outcome::Keep
}
