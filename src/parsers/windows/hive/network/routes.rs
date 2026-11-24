use serde_json::json;

use super::super::{hive_kind_prefix, parse_value_map, value_text, Artefact, Outcome, TrieNode as T};

pub const KIND: &str = hive_kind_prefix!("network.persistent_routes");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::pre("ControlSet").sub(vec![T::lit("Services").sub(vec![
                T::lit("Tcpip").sub(vec![T::lit("Parameters").sub(vec![
                    T::lit("PersistentRoutes").emit(KIND, |object, cell| {
                        let entries = parse_value_map(cell, |value| {
                            Some((
                                value.get_pretty_name(),
                                json!(value_text(value)),
                            ))
                        });
                        object.text = format!("Persistent routes: {} entries", entries.len());
                        object.data.insert("persistent_routes".into(), json!(entries));
                        Outcome::Keep
                    }),
                ])]),
            ])])]
        },
    }
}
