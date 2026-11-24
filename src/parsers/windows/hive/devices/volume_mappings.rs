use notatin::cell_key_node::CellKeyNode;
use serde_json::json;

use super::super::{
    Artefact, Outcome, ObjectOutput, TrieNode as T, hive_kind_prefix, parse_value_map, registry_value_map,
};

pub const KIND: &str = hive_kind_prefix!("devices.volume_mappings");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![
                T::lit("MountedDevices").emit(KIND, mounted_devices),
                T::pre("ControlSet").sub(vec![T::lit("Control").sub(vec![
                    T::lit("DeviceClasses").sub(vec![
                        T::lit("{53f56307-b6bf-11d0-94f2-00a0c91efb8b}").sub(vec![
                            device_class_nodes(5),
                        ]),
                    ]),
                ])]),
                T::lit("Software").sub(vec![T::lit("Microsoft").sub(vec![T::lit("Windows").sub(
                    vec![T::lit("CurrentVersion").sub(vec![
                        T::lit("Explorer").sub(vec![T::lit("MountPoints2").sub(vec![
                            mount_point_nodes(3),
                        ])]),
                    ])],
                )])]),
            ]
        },
    }
}

fn mounted_devices(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let mappings = parse_value_map(cell, |value| {
        let bytes = value.detail.value_bytes().unwrap_or_default();
        Some((
            value.get_pretty_name(),
            json!({
                "target_identifier": decode_mount_target(&bytes),
                "target_byte_length": bytes.len(),
            }),
        ))
    });
    object.text = format!("Mounted volume mappings: {} entries", mappings.len());
    object
        .data
        .insert("mounted_volume_mappings".into(), json!(mappings));
    Outcome::Keep
}

fn device_class_nodes(depth: u8) -> T {
    let node = T::any().emit(KIND, |object, cell| {
        let values = registry_value_map(cell);
        object.text = format!("Storage device mount record: {}", cell.key_name);
        object
            .data
            .insert("device_mount_record_values".into(), json!(values));
        Outcome::Keep
    });
    if depth == 0 {
        node
    } else {
        node.sub(vec![device_class_nodes(depth - 1)])
    }
}

fn mount_point_nodes(depth: u8) -> T {
    let node = T::any().emit(KIND, mount_point);
    if depth == 0 {
        node
    } else {
        node.sub(vec![mount_point_nodes(depth - 1)])
    }
}

fn mount_point(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let values = registry_value_map(cell);
    object.text = format!("User mount-point history: {}", cell.key_name);
    object
        .data
        .insert("mount_point_key".into(), json!(cell.key_name));
    object
        .data
        .insert("mount_point_properties".into(), json!(values));
    Outcome::Keep
}

fn decode_mount_target(bytes: &[u8]) -> Option<String> {
    let wide_bytes = bytes.chunks_exact(2).collect::<Vec<_>>();
    if bytes.len() % 2 == 0
        && wide_bytes
            .iter()
            .all(|word| word[1] == 0 && (word[0].is_ascii_graphic() || word[0] == 0))
    {
        let text = wide_bytes
            .iter()
            .map(|word| word[0])
            .take_while(|byte| *byte != 0)
            .collect::<Vec<_>>();
        if !text.is_empty() {
            return Some(String::from_utf8_lossy(&text).into_owned());
        }
    }

    if bytes
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    {
        return Some(String::from_utf8_lossy(bytes).into_owned());
    }

    None
}
