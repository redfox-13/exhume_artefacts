use notatin::cell_key_node::CellKeyNode;
use serde_json::{Value, json};

use super::super::{
    Artefact, Outcome, ObjectOutput, TrieNode as T, hive_kind_prefix, registry_value_map,
};

pub const KIND: &str = hive_kind_prefix!("file_operations.shellbags");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let shellbag_keys = || {
                vec![
                    T::lit("BagMRU")
                        .emit(KIND, shellbag_items)
                        .sub(vec![shellbag_item_nodes(16)]),
                    T::lit("Bags")
                        .emit(KIND, shellbag_view_settings)
                        .sub(vec![shellbag_view_nodes(8)]),
                ]
            };
            vec![
                T::lit("Software").sub(vec![
                    T::lit("Microsoft").sub(vec![
                        T::lit("Windows").sub(vec![T::lit("Shell").sub(shellbag_keys())]),
                    ]),
                    T::lit("Classes").sub(vec![T::lit("Local Settings").sub(vec![
                        T::lit("Software").sub(vec![T::lit("Microsoft").sub(vec![
                            T::lit("Windows").sub(vec![T::lit("Shell").sub(shellbag_keys())]),
                        ])]),
                    ])]),
                    T::lit("Classes").sub(vec![T::lit("Wow6432Node").sub(vec![
                        T::lit("Local Settings").sub(vec![T::lit("Software").sub(vec![
                            T::lit("Microsoft").sub(vec![
                                T::lit("Windows").sub(vec![T::lit("Shell").sub(shellbag_keys())]),
                            ]),
                        ])]),
                    ])]),
                ]),
                T::lit("Local Settings").sub(vec![T::lit("Software").sub(vec![
                    T::lit("Microsoft").sub(vec![
                        T::lit("Windows").sub(vec![T::lit("Shell").sub(shellbag_keys())]),
                    ]),
                ])]),
            ]
        },
    }
}

fn shellbag_item_nodes(depth: u8) -> T {
    let node = T::any().emit(KIND, shellbag_items);
    if depth == 0 {
        node
    } else {
        node.sub(vec![shellbag_item_nodes(depth - 1)])
    }
}

fn shellbag_view_nodes(depth: u8) -> T {
    let node = T::any().emit(KIND, shellbag_view_settings);
    if depth == 0 {
        node
    } else {
        node.sub(vec![shellbag_view_nodes(depth - 1)])
    }
}

fn shellbag_items(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let mru_order = cell
        .value_iter()
        .find(|value| value.get_pretty_name().eq_ignore_ascii_case("MRUListEx"))
        .map(|value| {
            value
                .detail
                .value_bytes()
                .unwrap_or_default()
                .chunks_exact(4)
                .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                .take_while(|index| *index != u32::MAX)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let entries: Vec<Value> = cell.value_iter().filter_map(|value| {
        let value_name = value.get_pretty_name();
        if value_name.eq_ignore_ascii_case("MRUListEx")
            || value_name.eq_ignore_ascii_case("NodeSlot")
        {
            return None;
        }

        let bytes = value.detail.value_bytes().unwrap_or_default();
        let item_index = value_name.parse::<u32>().ok();
        let mru_rank = item_index.and_then(|index| {
            mru_order
                .iter()
                .position(|candidate| *candidate == index)
                .map(|position| position + 1)
        });

        Some(json!({
            "value_name": value_name,
            "item_index": item_index,
            "mru_rank": mru_rank,
            "shell_item_type": bytes.get(2).copied(),
            "shell_item_type_label": bytes.get(2).and_then(|kind| shell_item_type_label(*kind)),
            "pidl_byte_length": bytes.len(),
            "embedded_text_hints": embedded_text_hints(&bytes),
        }))
    }).collect();

    object.text = format!("ShellBag folder history node: {}", cell.key_name);
    object.data.insert("shellbag_items".into(), json!(entries));
    object.data.insert("mru_order".into(), json!(mru_order));
    Outcome::Keep
}

fn shellbag_view_settings(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let settings = registry_value_map(cell);
    object.text = format!("ShellBag folder view settings: {}", cell.key_name);
    object
        .data
        .insert("shellbag_view_settings".into(), json!(settings));
    Outcome::Keep
}

fn embedded_text_hints(bytes: &[u8]) -> Vec<String> {
    let utf16 = bytes
        .chunks_exact(2)
        .map(|word| u16::from_le_bytes([word[0], word[1]]))
        .collect::<Vec<_>>();
    let wide_hints = String::from_utf16_lossy(&utf16);
    let ascii_hints = String::from_utf8_lossy(bytes);

    let mut hints = Vec::new();
    for text in [wide_hints.as_ref(), ascii_hints.as_ref()] {
        for fragment in text.split(|character: char| {
            character.is_control()
                || !(character.is_alphanumeric()
                    || matches!(character, ' ' | '.' | '_' | '-' | ':' | '\\' | '/'))
        }) {
            let fragment = fragment.trim();
            if fragment.chars().count() >= 3
                && fragment.chars().any(char::is_alphabetic)
                && !hints.iter().any(|hint| hint == fragment)
            {
                hints.push(fragment.to_owned());
            }
        }
    }
    hints
}

fn shell_item_type_label(kind: u8) -> Option<&'static str> {
    match kind {
        0x00 => Some("variable_or_property_item"),
        0x01 => Some("control_panel_item"),
        0x1f => Some("system_folder"),
        0x2e => Some("device"),
        0x2f => Some("drive"),
        0x31 | 0x32 | 0x35 | 0x74 | 0xb1 => Some("file_or_folder"),
        0x41 | 0x42 | 0x46 | 0x47 | 0xc3 => Some("network_location"),
        0x52 => Some("shell_item"),
        0x61 => Some("uri"),
        _ => None,
    }
}
