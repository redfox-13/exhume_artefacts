use notatin::cell_key_node::CellKeyNode;
use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map, ObjectOutput};

pub const KIND: &str = hive_kind_prefix!("persistence.print_components");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![
                T::pre("ControlSet").sub(vec![T::lit("Control").sub(vec![T::lit("Print").sub(
                    vec![
                        T::lit("Monitors").sub(vec![T::any().emit(KIND, print_component)]),
                        T::lit("Providers").sub(vec![T::any().emit(KIND, print_component)]),
                        T::lit("Printers").sub(vec![T::any().emit(KIND, print_component)]),
                        T::lit("Environments").sub(vec![T::any().sub(vec![
                            T::lit("Print Processors")
                                .sub(vec![T::any().emit(KIND, print_component)]),
                        ])]),
                    ],
                )])]),
            ]
        },
    }
}

fn print_component(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let values = registry_value_map(cell);
    object.text = format!("Windows print component: {}", cell.key_name);
    object
        .data
        .insert("print_component_name".into(), json!(cell.key_name));
    object
        .data
        .insert("print_component_settings".into(), json!(values));
    Outcome::Keep
}
