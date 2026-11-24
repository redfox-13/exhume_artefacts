use serde_json::json;

use super::super::{hive_kind_prefix, registry_value_map, Artefact, Outcome, TrieNode as T};

pub const KIND: &str = hive_kind_prefix!("file_operations.comdlg32");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Software").sub(vec![
                T::lit("Microsoft").sub(vec![
                    T::lit("Windows").sub(vec![
                        T::lit("CurrentVersion").sub(vec![
                            T::lit("Explorer").sub(vec![
                                T::lit("ComDlg32").sub(vec![
                                    T::lit("OpenSavePidlMRU").sub(vec![T::any().emit(
                                        KIND,
                                        |object, cell| {
                                            let entries = registry_value_map(cell);
                                            object.text = format!(
                                                "Open/save PIDL dialog history: {} entries",
                                                entries.len()
                                            );
                                            object.data.insert(
                                                "open_save_pidl_mru".into(),
                                                json!(entries),
                                            );
                                            Outcome::Keep
                                        },
                                    )]),
                                    T::lit("OpenSaveMRU")
                                        .emit(KIND, |object, cell| {
                                            let entries = registry_value_map(cell);
                                            object.text = format!(
                                                "Open/save MRU {}: {} values",
                                                cell.key_name,
                                                entries.len()
                                            );
                                            object.data.insert(
                                                "open_save_mru_key".into(),
                                                json!(cell.key_name),
                                            );
                                            object.data.insert(
                                                "open_save_mru_values".into(),
                                                json!(entries),
                                            );
                                            Outcome::Keep
                                        })
                                        .sub(vec![T::any().emit(KIND, |object, cell| {
                                            let entries = registry_value_map(cell);
                                            object.text = format!(
                                                "Open/save MRU extension {}: {} values",
                                                cell.key_name,
                                                entries.len()
                                            );
                                            object.data.insert(
                                                "open_save_mru_key".into(),
                                                json!(cell.key_name),
                                            );
                                            object.data.insert(
                                                "open_save_mru_values".into(),
                                                json!(entries),
                                            );
                                            Outcome::Keep
                                        })]),
                                    T::lit("LastVisitedMRU").emit(KIND, |object, cell| {
                                        let entries = registry_value_map(cell);
                                        object.text = format!(
                                            "Last-visited MRU: {} entries",
                                            entries.len()
                                        );
                                        object.data.insert(
                                            "last_visited_mru".into(),
                                            json!(entries),
                                        );
                                        Outcome::Keep
                                    }),
                                    T::lit("LastVisitedPidlMRU").emit(KIND, |object, cell| {
                                        let entries = registry_value_map(cell);
                                        object.text = format!(
                                            "Last-visited PIDL dialog history: {} entries",
                                            entries.len()
                                        );
                                        object.data.insert(
                                            "last_visited_pidl_mru".into(),
                                            json!(entries),
                                        );
                                        Outcome::Keep
                                    }),
                                    T::lit("LastVisitedPidlMRULegacy").emit(
                                        KIND,
                                        |object, cell| {
                                            let entries = registry_value_map(cell);
                                            object.text = format!(
                                                "Legacy last-visited PIDL dialog history: {} entries",
                                                entries.len()
                                            );
                                            object.data.insert(
                                                "last_visited_pidl_mru_legacy".into(),
                                                json!(entries),
                                            );
                                            Outcome::Keep
                                        },
                                    ),
                                    T::lit("CIDSizeMRU").emit(KIND, |object, cell| {
                                        let entries = registry_value_map(cell);
                                        object.text = format!(
                                            "Common dialog size preferences: {} entries",
                                            entries.len()
                                        );
                                        object.data.insert(
                                            "common_dialog_size_preferences".into(),
                                            json!(entries),
                                        );
                                        Outcome::Keep
                                    }),
                                    T::lit("FirstFolder").emit(KIND, |object, cell| {
                                        let entries = registry_value_map(cell);
                                        object.text = format!(
                                            "Common dialog initial folders: {} entries",
                                            entries.len()
                                        );
                                        object.data.insert(
                                            "common_dialog_first_folders".into(),
                                            json!(entries),
                                        );
                                        Outcome::Keep
                                    }),
                                ]),
                                T::lit("StreamMRU").emit(KIND, |object, cell| {
                                    let entries = registry_value_map(cell);
                                    object.text =
                                        format!("Explorer Stream MRU: {} entries", entries.len());
                                    object
                                        .data
                                        .insert("explorer_stream_mru".into(), json!(entries));
                                    Outcome::Keep
                                }),
                            ]),
                        ]),
                    ]),
                ]),
            ])]
        },
    }
}
