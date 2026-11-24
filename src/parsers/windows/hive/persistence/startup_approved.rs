use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("persistence.startup_approved");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let startup_approved_path = || {
                T::lit("Windows").sub(vec![T::lit("CurrentVersion").sub(vec![
                    T::lit("Explorer").sub(vec![T::lit("StartupApproved").sub(vec![
                        T::any().emit(KIND, |object, cell| {
                            let entries = registry_value_map(cell);
                            object.text = format!(
                                "StartupApproved {}: {} entries",
                                cell.key_name,
                                entries.len()
                            );
                            object
                                .data
                                .insert("startup_approval_entries".into(), json!(entries));
                            Outcome::Keep
                        }),
                    ])]),
                ])])
            };
            vec![
                T::lit("Microsoft").sub(vec![startup_approved_path()]),
                T::lit("Software")
                    .sub(vec![T::lit("Microsoft").sub(vec![startup_approved_path()])]),
            ]
        },
    }
}
