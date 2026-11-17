use serde_json::{json, Value};

use super::super::{hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("system.user_profiles");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Microsoft").sub(vec![T::lit("Windows NT").sub(vec![
                T::lit("CurrentVersion").sub(vec![T::lit("ProfileList").sub(vec![T::any()
                    .emit(KIND, |object, cell| {
                        let values: Vec<Value> = parse_values(cell, |value| {
                            Some(json!({
                                "name": value.get_pretty_name(),
                                "value": super::super::value_text(value),
                            }))
                        });
                        object.text = format!("User profile: {}", cell.key_name);
                        object.data.insert("profile_sid".into(), json!(cell.key_name));
                        object
                            .data
                            .insert("user_profile_properties".into(), json!(values));
                        Outcome::Keep
                    })])]),
            ])])]
        },
    }
}
