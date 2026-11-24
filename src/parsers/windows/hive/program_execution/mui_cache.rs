use notatin::cell_key_node::CellKeyNode;
use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, parse_value_map, ObjectOutput, value_text};

pub const KIND: &str = hive_kind_prefix!("program_execution.mui_cache");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![
                T::lit("Software").sub(vec![
                    T::lit("Microsoft").sub(vec![T::lit("Windows").sub(vec![
                        T::lit("ShellNoRoam").sub(vec![
                            T::lit("MUICache").emit(KIND, mui_cache_values),
                        ]),
                    ])]),
                    T::lit("Classes").sub(vec![T::lit("Local Settings").sub(vec![
                        T::lit("Software").sub(vec![T::lit("Microsoft").sub(vec![
                            T::lit("Windows").sub(vec![
                                T::lit("Shell").sub(vec![
                                    T::lit("MUICache").emit(KIND, mui_cache_values),
                                ]),
                            ]),
                        ])]),
                    ])]),
                ]),
                T::lit("Local Settings").sub(vec![T::lit("Software").sub(vec![
                    T::lit("Microsoft").sub(vec![T::lit("Windows").sub(vec![
                        T::lit("Shell").sub(vec![T::lit("MUICache").emit(KIND, mui_cache_values)]),
                    ])]),
                ])]),
            ]
        },
    }
}

fn mui_cache_values(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let entries = parse_value_map(cell, |value| {
        Some((
            value.get_pretty_name(),
            json!(value_text(value)),
        ))
    });
    object.text = format!("MUI application-name cache: {} entries", entries.len());
    object
        .data
        .insert("mui_cache_entries".into(), json!(entries));
    Outcome::Keep
}
