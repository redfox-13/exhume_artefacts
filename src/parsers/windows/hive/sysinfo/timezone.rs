use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, parse_value_map, registry_value_map, value_text};

pub const KIND: &str = hive_kind_prefix!("sysinfo.timezone");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![
                T::pre("ControlSet").sub(vec![
                    T::lit("Control").sub(vec![T::lit("TimeZoneInformation").emit(
                        KIND,
                        |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = "System time-zone configuration".into();
                            object
                                .data
                                .insert("time_zone_settings".into(), json!(values));
                            Outcome::Keep
                        },
                    )]),
                    T::lit("Services").sub(vec![T::lit("W32Time").sub(vec![T::any().emit(
                        KIND,
                        |object, cell| {
                            let values = registry_value_map(cell);
                            object.text =
                                format!("Windows Time service settings: {}", cell.key_name);
                            object
                                .data
                                .insert("windows_time_service_key".into(), json!(cell.key_name));
                            object
                                .data
                                .insert("windows_time_service_settings".into(), json!(values));
                            Outcome::Keep
                        },
                    )])]),
                ]),
                T::lit("Software").sub(vec![T::lit("Microsoft").sub(vec![T::lit("Windows").sub(
                    vec![
                        T::lit("CurrentVersion").sub(vec![T::lit("DateTime").sub(vec![
                            T::lit("Servers").emit(KIND, |object, cell| {
                                let values = parse_value_map(cell, |value| {
                                    Some((
                                        value.get_pretty_name(),
                                        json!(value_text(value)),
                                    ))
                                });
                                object.text =
                                    format!("Configured time servers: {} entries", values.len());
                                object.data.insert("time_servers".into(), json!(values));
                                Outcome::Keep
                            }),
                        ])]),
                    ],
                )])]),
            ]
        },
    }
}
