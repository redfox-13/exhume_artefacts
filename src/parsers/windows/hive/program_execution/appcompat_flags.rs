use notatin::cell_key_node::CellKeyNode;
use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map, ObjectOutput};

pub const KIND: &str = hive_kind_prefix!("program_execution.appcompat_flags");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let appcompat_flags_path = || {
                T::lit("Windows NT").sub(vec![T::lit("CurrentVersion").sub(vec![
                    T::lit("AppCompatFlags").sub(vec![
                        T::lit("Layers").emit(KIND, appcompat_values),
                        T::lit("Compatibility Assistant").sub(vec![
                            T::lit("Persisted").emit(KIND, appcompat_values),
                            T::lit("Store").emit(KIND, appcompat_values),
                        ]),
                        T::lit("Custom")
                            .emit(KIND, appcompat_values)
                            .sub(vec![T::any().emit(KIND, appcompat_values)]),
                        T::lit("InstalledSDB")
                            .emit(KIND, appcompat_values)
                            .sub(vec![T::any().emit(KIND, appcompat_values)]),
                    ]),
                ])])
            };
            vec![
                T::lit("Microsoft").sub(vec![appcompat_flags_path()]),
                T::lit("Wow6432Node")
                    .sub(vec![T::lit("Microsoft").sub(vec![appcompat_flags_path()])]),
                T::lit("Wow6432Node")
                    .sub(vec![T::lit("Software").sub(vec![
                        T::lit("Microsoft").sub(vec![appcompat_flags_path()]),
                    ])]),
                T::lit("Software").sub(vec![
                    T::lit("Microsoft").sub(vec![appcompat_flags_path()]),
                    T::lit("Wow6432Node")
                        .sub(vec![T::lit("Microsoft").sub(vec![appcompat_flags_path()])]),
                ]),
            ]
        },
    }
}

fn appcompat_values(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let values = registry_value_map(cell);
    object.text = format!("Application compatibility settings: {}", cell.key_name);
    object
        .data
        .insert("appcompat_settings".into(), json!(values));
    Outcome::Keep
}
