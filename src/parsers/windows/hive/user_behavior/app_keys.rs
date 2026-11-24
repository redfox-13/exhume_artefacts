use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("user_behavior.app_keys");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let app_keys = || {
                T::lit("Microsoft").sub(vec![T::lit("Windows").sub(vec![
                    T::lit("CurrentVersion").sub(vec![T::lit("Explorer").sub(vec![
                        T::lit("AppKey").sub(vec![T::any().emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = format!("Explorer application key: {}", cell.key_name);
                            object.data.insert("app_key_name".into(), json!(cell.key_name));
                            object.data.insert("app_key_values".into(), json!(values));
                            Outcome::Keep
                        })]),
                    ])]),
                ])])
            };
            vec![app_keys(), T::lit("Software").sub(vec![app_keys()])]
        },
    }
}
