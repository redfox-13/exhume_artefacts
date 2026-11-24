use serde_json::json;

use super::super::{hive_kind_prefix, registry_value_map, Artefact, Outcome, TrieNode as T};

pub const KIND: &str = hive_kind_prefix!("user_behavior.recent_apps");

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
                                    let values = registry_value_map(cell);
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
