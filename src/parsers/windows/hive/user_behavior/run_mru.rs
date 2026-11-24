use serde_json::json;

use super::super::{
    hive_kind_prefix, parse_value_map, value_text, Artefact, Outcome, TrieNode as T,
};

pub const KIND: &str = hive_kind_prefix!("user_behavior.run_mru");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Software").sub(vec![T::lit("Microsoft").sub(vec![
                T::lit("Windows").sub(vec![T::lit("CurrentVersion").sub(vec![
                    T::lit("Explorer").sub(vec![T::lit("RunMRU").emit(
                        KIND,
                        |object, cell| {
                            let entries = parse_value_map(cell, |value| {
                                Some((
                                    value.get_pretty_name(),
                                    json!(value_text(value)),
                                ))
                            });
                            object.text = format!("Run dialog MRU: {} entries", entries.len());
                            object
                                .data
                                .insert("run_most_recently_used".into(), json!(entries));
                            Outcome::Keep
                        },
                    )]),
                ])]),
            ])]) ]
        },
    }
}
