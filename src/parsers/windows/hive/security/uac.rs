use serde_json::json;

use super::super::{hive_kind_prefix, registry_value_map, Artefact, Outcome, TrieNode as T};

pub const KIND: &str = hive_kind_prefix!("security.uac");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let uac = || T::lit("Microsoft").sub(vec![
                T::lit("Windows").sub(vec![T::lit("CurrentVersion").sub(vec![
                    T::lit("Policies").sub(vec![T::lit("System").emit(
                        KIND,
                        |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = "User Account Control policy".into();
                            object
                                .data
                                .insert("uac_policy_settings".into(), json!(values));
                            Outcome::Keep
                        },
                    )]),
                ])]),
            ]);
            vec![
                T::lit("Software").sub(vec![uac()]),
                T::lit("Wow6432Node").sub(vec![uac()]),
            ]
        },
    }
}
