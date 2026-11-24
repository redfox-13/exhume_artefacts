use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("user_behavior.last_logged_on");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let logon_ui = || {
                T::lit("Microsoft").sub(vec![T::lit("Windows").sub(vec![
                    T::lit("CurrentVersion").sub(vec![
                        T::lit("Authentication").sub(vec![T::lit("LogonUI").emit(
                            KIND,
                            |object, cell| {
                                let values = registry_value_map(cell);
                                object.text = "Last logon user and authentication UI values".into();
                                object.data.insert("logon_ui_values".into(), json!(values));
                                Outcome::Keep
                            },
                        )]),
                    ]),
                ])])
            };
            vec![logon_ui(), T::lit("Software").sub(vec![logon_ui()])]
        },
    }
}
