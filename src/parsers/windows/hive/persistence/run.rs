use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, parse_value_map, value_text};

pub const KIND: &str = hive_kind_prefix!("persistence.run");

/// Microsoft\Windows\CurrentVersion\Run*, and Policies\Explorer\Run
pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let run_locations = || {
                T::lit("Windows").sub(vec![T::lit("CurrentVersion").sub(vec![
                    T::pre("Run").emit(KIND, |object, cell| {
                        let entries = parse_value_map(cell, |value| {
                            Some((
                                value.get_pretty_name(),
                                json!(value_text(value)),
                            ))
                        });
                        object.text =
                            format!("RUN KEY {}: {} entries", cell.key_name, entries.len());
                        object.data.insert("run_commands".into(), json!(entries));
                        Outcome::Keep
                    }),
                    T::lit("Policies").sub(vec![T::lit("Explorer").sub(vec![T::lit("Run").emit(
                        KIND,
                        |object, cell| {
                            let entries = parse_value_map(cell, |value| {
                                Some((
                                    value.get_pretty_name(),
                                    json!(value_text(value)),
                                ))
                            });
                            object.text =
                                format!("RUN KEY {}: {} entries", cell.key_name, entries.len());
                            object.data.insert("run_commands".into(), json!(entries));
                            Outcome::Keep
                        },
                    )])]),
                ])])
            };
            vec![
                T::lit("Microsoft").sub(vec![run_locations()]),
                T::lit("Wow6432Node").sub(vec![T::lit("Microsoft").sub(vec![run_locations()])]),
                T::lit("Software").sub(vec![
                    T::lit("Microsoft").sub(vec![run_locations()]),
                    T::lit("Wow6432Node").sub(vec![T::lit("Microsoft").sub(vec![run_locations()])]),
                ]),
                T::lit("Microsoft").sub(vec![T::lit("Windows NT").sub(vec![
                    T::lit("CurrentVersion").sub(vec![T::lit("Terminal Server").sub(vec![
                        T::lit("Install").sub(vec![T::lit("Software")
                            .sub(vec![T::lit("Microsoft").sub(vec![run_locations()])])]),
                    ])]),
                ])]),
            ]
        },
    }
}
