use serde_json::json;

use super::super::{hive_kind_prefix, registry_value_map, Artefact, Outcome, TrieNode as T};

pub const KIND: &str = hive_kind_prefix!("security.defender");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let defender = || {
                T::lit("Windows Defender")
                    .emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "Windows Defender configuration".into();
                        object
                            .data
                            .insert("defender_settings".into(), json!(values));
                        Outcome::Keep
                    })
                    .sub(vec![
                    T::lit("Real-Time Protection").emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "Windows Defender real-time protection policy".into();
                        object
                            .data
                            .insert("defender_protection_settings".into(), json!(values));
                        Outcome::Keep
                    }),
                    T::lit("Exclusions").sub(vec![
                        T::any().emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = format!("Windows Defender exclusion: {}", cell.key_name);
                            object
                                .data
                                .insert("exclusion_type".into(), json!(cell.key_name));
                            object
                                .data
                                .insert("defender_exclusions".into(), json!(values));
                            Outcome::Keep
                        }),
                    ]),
                    T::lit("Spynet").emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "Windows Defender cloud reporting settings".into();
                        object
                            .data
                            .insert("defender_spynet_settings".into(), json!(values));
                        Outcome::Keep
                    }),
                    T::lit("MpEngine").emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "Windows Defender engine settings".into();
                        object
                            .data
                            .insert("defender_engine_settings".into(), json!(values));
                        Outcome::Keep
                    }),
                    T::lit("Features").emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "Windows Defender feature settings".into();
                        object
                            .data
                            .insert("defender_feature_settings".into(), json!(values));
                        Outcome::Keep
                    }),
                ])
            };
            let machine = || {
                T::lit("Microsoft").sub(vec![defender()])
            };
            let policy = || {
                T::lit("Policies").sub(vec![T::lit("Microsoft").sub(vec![defender()])])
            };
            vec![
                T::lit("Software").sub(vec![machine(), policy()]),
                machine(),
                policy(),
            ]
        },
    }
}
