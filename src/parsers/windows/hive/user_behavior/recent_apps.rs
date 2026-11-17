use serde_json::{json, Value};

use super::super::{hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("user_behavior.recent_apps");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Software").sub(vec![
                T::lit("Microsoft").sub(vec![
                    T::lit("Windows").sub(vec![
                        T::lit("CurrentVersion").sub(vec![
                            T::lit("Search").sub(vec![T::lit("RecentApps").sub(vec![T::any()
                                .emit(KIND, |object, cell| {
                                    let values: Vec<Value> = parse_values(cell, |value| {
                                        Some(json!({
                                            "name": value.get_pretty_name(),
                                            "value": super::super::value_text(value),
                                        }))
                                    });
                                    object.text = format!("Recent application: {}", cell.key_name);
                                    object.data.insert(
                                        "application_id".into(),
                                        json!(cell.key_name),
                                    );
                                    object
                                        .data
                                        .insert("recent_application_properties".into(), json!(values));
                                    Outcome::Keep
                                })])]),
                        ]),
                    ]),
                ]),
            ])]
        },
    }
}
