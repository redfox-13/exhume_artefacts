use serde_json::{json, Value};

use super::super::{hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("persistence.startup_approved");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Software").sub(vec![T::lit("Microsoft").sub(vec![
                T::lit("Windows").sub(vec![T::lit("CurrentVersion").sub(vec![
                    T::lit("Explorer").sub(vec![T::lit("StartupApproved").sub(vec![T::any()
                        .emit(KIND, |object, cell| {
                            let entries: Vec<Value> = parse_values(cell, |value| {
                                Some(json!({
                                    "name": value.get_pretty_name(),
                                }))
                            });
                            object.text = format!("StartupApproved {}: {} entries", cell.key_name, entries.len());
                            object
                                .data
                                .insert("startup_approval_entries".into(), json!(entries));
                            Outcome::Keep
                        })])]),
                ])]),
            ])])]
        },
    }
}
