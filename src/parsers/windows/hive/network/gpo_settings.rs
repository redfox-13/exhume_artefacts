use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("network.group_policy_settings");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let powershell = || {
                T::lit("PowerShell").emit(KIND, |object, cell| {
                    let values = registry_value_map(cell);
                    object.text = "PowerShell group policy settings".into();
                    object
                        .data
                        .insert("group_policy_values".into(), json!(values));
                    Outcome::Keep
                })
            };
            let winrm = || {
                T::lit("WinRM").sub(vec![
                    T::lit("Client").emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "WinRM client group policy settings".into();
                        object
                            .data
                            .insert("group_policy_values".into(), json!(values));
                        Outcome::Keep
                    }),
                    T::lit("Service").sub(vec![
                        T::lit("WinRS").emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = "WinRM remote shell group policy settings".into();
                            object
                                .data
                                .insert("group_policy_values".into(), json!(values));
                            Outcome::Keep
                        }),
                    ]).emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "WinRM service group policy settings".into();
                        object
                            .data
                            .insert("group_policy_values".into(), json!(values));
                        Outcome::Keep
                    }),
                ])
            };
            let windows = || {
                T::lit("Windows").sub(vec![
                    powershell(),
                    T::lit("System").emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "Windows system group policy settings".into();
                        object
                            .data
                            .insert("group_policy_values".into(), json!(values));
                        Outcome::Keep
                    }),
                    winrm(),
                ])
            };
            let microsoft = || {
                T::lit("Microsoft").sub(vec![
                    windows(),
                    T::lit("Windows Defender")
                        .emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = "Windows Defender group policy settings".into();
                            object
                                .data
                                .insert("group_policy_values".into(), json!(values));
                            Outcome::Keep
                        })
                        .sub(vec![T::lit("Real-Time Protection").emit(
                            KIND,
                            |object, cell| {
                                let values = registry_value_map(cell);
                                object.text =
                                    "Windows Defender real-time protection group policy".into();
                                object
                                    .data
                                    .insert("group_policy_values".into(), json!(values));
                                Outcome::Keep
                            },
                        )]),
                    T::lit("Windows NT").sub(vec![
                        T::lit("Security Center").emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = "Security Center group policy settings".into();
                            object
                                .data
                                .insert("group_policy_values".into(), json!(values));
                            Outcome::Keep
                        }),
                        T::lit("Terminal Services").emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = "Terminal Services group policy settings".into();
                            object
                                .data
                                .insert("group_policy_values".into(), json!(values));
                            Outcome::Keep
                        }),
                    ]),
                ])
            };
            let policy = || T::lit("Policies").sub(vec![microsoft()]);
            vec![policy(), T::lit("Software").sub(vec![policy()])]
        },
    }
}
