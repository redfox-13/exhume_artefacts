use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("security.security_center");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let security_center = || {
                T::lit("Microsoft").sub(vec![T::lit("Security Center").emit(
                    KIND,
                    |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "Windows Security Center settings".into();
                        object
                            .data
                            .insert("security_center_values".into(), json!(values));
                        Outcome::Keep
                    },
                )])
            };
            let policy = || {
                T::lit("Policies").sub(vec![T::lit("Microsoft").sub(vec![
                    T::lit("Windows NT").sub(vec![T::lit("Security Center").emit(
                        KIND,
                        |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = "Windows Security Center policy settings".into();
                            object
                                .data
                                .insert("security_center_values".into(), json!(values));
                            Outcome::Keep
                        },
                    )]),
                ])])
            };
            vec![
                security_center(),
                policy(),
                T::lit("Software").sub(vec![security_center(), policy()]),
            ]
        },
    }
}
