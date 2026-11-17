use serde_json::{json, Value};

use super::super::{hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("network.persistent_routes");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::pre("ControlSet").sub(vec![T::lit("Services").sub(vec![
                T::lit("Tcpip").sub(vec![T::lit("Parameters").sub(vec![
                    T::lit("PersistentRoutes").emit(KIND, |object, cell| {
                        let entries: Vec<Value> = parse_values(cell, |value| {
                            Some(json!({
                                "destination": value.get_pretty_name(),
                                "route": super::super::value_text(value),
                            }))
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
