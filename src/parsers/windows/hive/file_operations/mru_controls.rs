use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("file_operations.recent_document_controls");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let controls = || {
                T::lit("Microsoft").sub(vec![T::lit("Windows").sub(vec![
                    T::lit("CurrentVersion").sub(vec![
                        T::lit("Explorer").sub(vec![T::lit("Advanced").emit(
                            KIND,
                            |object, cell| {
                                let values = registry_value_map(cell);
                                object.text = "Recent-document and jump-list tracking settings".into();
                                object
                                    .data
                                    .insert("recent_document_controls".into(), json!(values));
                                Outcome::Keep
                            },
                        )]),
                        T::lit("Policies").sub(vec![
                            T::lit("Comdlg32").emit(KIND, |object, cell| {
                                let values = registry_value_map(cell);
                                object.text = "Common dialog MRU policy settings".into();
                                object.data.insert("mru_controls".into(), json!(values));
                                Outcome::Keep
                            }),
                            T::lit("Explorer").emit(KIND, |object, cell| {
                                let values = registry_value_map(cell);
                                object.text = "Recent-document history policy settings".into();
                                object.data.insert("mru_controls".into(), json!(values));
                                Outcome::Keep
                            }),
                        ]),
                    ]),
                ])])
            };
            vec![controls(), T::lit("Software").sub(vec![controls()])]
        },
    }
}
