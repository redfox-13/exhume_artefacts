use notatin::cell_key_node::CellKeyNode;
use serde_json::{Value, json};

use super::super::{
    Artefact, Outcome, ObjectOutput, TrieNode as T, hive_kind_prefix, parse_value_map,
    registry_value_map, value_text,
};

pub const KIND: &str = hive_kind_prefix!("network.mapped_drives");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![
                T::lit("Network").sub(vec![T::any().emit(KIND, mapped_drive)]),
                T::lit("Software").sub(vec![T::lit("Microsoft").sub(vec![T::lit("Windows").sub(
                    vec![
                        T::lit("CurrentVersion").sub(vec![T::lit("Explorer").sub(vec![
                            T::lit("Map Network Drive MRU").emit(KIND, mapped_drive_mru),
                        ])]),
                    ],
                )])]),
                T::pre("ControlSet").sub(vec![T::lit("Services").sub(vec![
                    T::lit("LanmanServer").sub(vec![T::lit("Shares").emit(KIND, local_shares)]),
                ])]),
            ]
        },
    }
}

fn mapped_drive(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let properties = registry_value_map(cell);
    object.text = format!("Mapped network drive: {}", cell.key_name);
    object
        .data
        .insert("drive_letter".into(), json!(cell.key_name));
    object
        .data
        .insert("mapped_drive_properties".into(), json!(properties));
    Outcome::Keep
}

fn mapped_drive_mru(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let mru_order = cell
        .value_iter()
        .find(|value| value.get_pretty_name().eq_ignore_ascii_case("MRUList"))
        .map(|value| value_text(&value))
        .unwrap_or_default();
    let entries: Vec<Value> = cell.value_iter().filter_map(|value| {
        let name = value.get_pretty_name();
        if name.eq_ignore_ascii_case("MRUList") {
            return None;
        }
        let rank = name
            .chars()
            .next()
            .and_then(|letter| mru_order.chars().position(|candidate| candidate == letter))
            .map(|position| position + 1);
        Some(json!({
            "value_name": name,
            "mru_rank": rank,
            "unc_path": value_text(&value),
        }))
    }).collect();
    object.text = format!("Mapped-drive path history: {} entries", entries.len());
    object
        .data
        .insert("mapped_drive_history".into(), json!(entries));
    Outcome::Keep
}

fn local_shares(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let shares = parse_value_map(cell, |value| {
        Some((
            value.get_pretty_name(),
            json!(value_text(value)),
        ))
    });
    object.text = format!("Configured local network shares: {} entries", shares.len());
    object
        .data
        .insert("local_network_shares".into(), json!(shares));
    Outcome::Keep
}
