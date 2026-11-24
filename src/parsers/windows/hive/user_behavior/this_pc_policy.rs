use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("user_behavior.this_pc_policy");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let policy = || {
                T::lit("Microsoft").sub(vec![T::lit("Windows").sub(vec![
                    T::lit("CurrentVersion").sub(vec![T::lit("Explorer").sub(vec![
                        T::lit("FolderDescriptions").sub(vec![T::any().sub(vec![
                            T::lit("PropertyBag").emit(KIND, |object, cell| {
                                let values = registry_value_map(cell);
                                object.text = format!("This PC folder policy: {}", cell.path);
                                object.data.insert("folder_guid".into(), json!(cell.path
                                    .rsplit('\\')
                                    .nth(1)
                                    .unwrap_or_default()));
                                object
                                    .data
                                    .insert("folder_policy_values".into(), json!(values));
                                Outcome::Keep
                            }),
                        ])]),
                    ])]),
                ])])
            };
            vec![policy(), T::lit("Software").sub(vec![policy()])]
        },
    }
}
