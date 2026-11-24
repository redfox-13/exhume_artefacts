use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("persistence.wsh_settings");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let settings = || {
                T::lit("Microsoft").sub(vec![T::lit("Windows Script Host").sub(vec![
                    T::lit("Settings").emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "Windows Script Host settings".into();
                        object.data.insert("wsh_settings".into(), json!(values));
                        Outcome::Keep
                    }),
                ])])
            };
            vec![settings(), T::lit("Software").sub(vec![settings()])]
        },
    }
}
