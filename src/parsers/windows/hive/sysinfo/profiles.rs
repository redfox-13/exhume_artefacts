use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("sysinfo.user_profiles");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Microsoft").sub(vec![T::lit("Windows NT").sub(vec![
                T::lit("CurrentVersion").sub(vec![
                    T::lit("ProfileList").sub(vec![T::any().emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = format!("User profile: {}", cell.key_name);
                        object
                            .data
                            .insert("profile_sid".into(), json!(cell.key_name));
                        object
                            .data
                            .insert("user_profile_properties".into(), json!(values));
                        Outcome::Keep
                    })]),
                    T::lit("ProfileGuid").sub(vec![T::any().emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = format!("User profile GUID: {}", cell.key_name);
                        object
                            .data
                            .insert("profile_guid".into(), json!(cell.key_name));
                        object
                            .data
                            .insert("user_profile_guid_properties".into(), json!(values));
                        Outcome::Keep
                    })]),
                ]),
            ])])]
        },
    }
}
