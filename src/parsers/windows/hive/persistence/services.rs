use serde_json::{Value, json};

use super::super::{
    Artefact, Outcome, TrieNode as T, hive_kind_prefix, parse_value_map, value_text,
};

pub const KIND: &str = hive_kind_prefix!("persistence.service");

/// ControlSet\Services\<name>, service ordering, and SOFTWARE\...\Svchost
pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![
                T::pre("ControlSet").sub(vec![
                    T::lit("Services").sub(vec![
                        T::any()
                            .sub(vec![T::lit("Parameters").combine(KIND, |object, cell| {
                                let params = parse_value_map(cell, |value| {
                                    let data = value_text(value);
                                    match value.get_pretty_name().to_lowercase().as_str() {
                                        "servicedll" => Some(("service_dll".into(), json!(data))),
                                        "servicemain" => Some(("service_main".into(), json!(data))),
                                        _ => None,
                                    }
                                });
                                object.data.extend(params);
                                Outcome::Keep
                            })])
                            .combine(KIND, |object, cell| {
                                let props = parse_value_map(cell, |value| {
                                    let data = value_text(value);
                                    match value.get_pretty_name().to_lowercase().as_str() {
                                        "imagepath" => Some(("image_path".into(), json!(data))),
                                        "displayname" => Some(("display_name".into(), json!(data))),
                                        "objectname" => Some(("object_name".into(), json!(data))),
                                        "group" => Some(("group".into(), json!(data))),
                                        "description" => Some(("description".into(), json!(data))),
                                        "dependonservice" => {
                                            Some(("dependencies".into(), json!(data)))
                                        }
                                        "servicesidtype" => {
                                            Some(("service_sid_type".into(), json!(data)))
                                        }
                                        "failureactions" => {
                                            Some(("failure_actions".into(), json!(data)))
                                        }
                                        "errorcontrol" => {
                                            Some(("error_control".into(), json!(data)))
                                        }
                                        "delayedautostart" => {
                                            Some(("delayed_auto_start".into(), json!(data)))
                                        }
                                        "start" => {
                                            let label = match data.as_str() {
                                                "0" => "boot",
                                                "1" => "system",
                                                "2" => "auto",
                                                "3" => "manual",
                                                "4" => "disabled",
                                                _ => "unknown",
                                            };
                                            Some((
                                                "start".into(),
                                                json!({ "raw": data, "label": label }),
                                            ))
                                        }
                                        "type" => {
                                            let label = match data.as_str() {
                                                "1" => "kernel_driver",
                                                "2" => "filesystem_driver",
                                                "16" => "own_process",
                                                "32" => "share_process",
                                                _ => "other",
                                            };
                                            Some((
                                                "type".into(),
                                                json!({ "raw": data, "label": label }),
                                            ))
                                        }
                                        _ => None,
                                    }
                                });
                                object.text = format!(
                                    "SERVICE: {} -> {}",
                                    cell.key_name,
                                    props
                                        .get("image_path")
                                        .and_then(Value::as_str)
                                        .unwrap_or("no ImagePath"),
                                );
                                object
                                    .data
                                    .insert("service_name".into(), json!(cell.key_name));
                                object.data.extend(props);
                                Outcome::Keep
                            })
                            .sub(vec![T::lit("StartOverride").combine(
                                KIND,
                                |object, cell| {
                                    let overrides = parse_value_map(cell, |value| {
                                            Some((
                                                value.get_pretty_name(),
                                                json!(value_text(value)),
                                            ))
                                        });
                                    object
                                        .data
                                        .insert("start_override".into(), json!(overrides));
                                    Outcome::Keep
                                },
                            )]),
                    ]),
                    T::lit("Control").sub(vec![
                        T::lit("ServiceGroupOrder").emit(KIND, |object, cell| {
                            let values = parse_value_map(cell, |value| {
                                Some((
                                    value.get_pretty_name(),
                                    json!(value_text(value)),
                                ))
                            });
                            object.text = "Service group order".into();
                            object
                                .data
                                .insert("service_group_order".into(), json!(values));
                            Outcome::Keep
                        }),
                        T::lit("GroupOrderList").emit(KIND, |object, cell| {
                            let values = parse_value_map(cell, |value| {
                                Some((
                                    value.get_pretty_name(),
                                    json!(value_text(value)),
                                ))
                            });
                            object.text = "Service group tag order".into();
                            object
                                .data
                                .insert("service_group_tag_order".into(), json!(values));
                            Outcome::Keep
                        }),
                    ]),
                ]),
                T::lit("Software").sub(vec![T::lit("Microsoft").sub(vec![
                    T::lit("Windows NT").sub(vec![T::lit("CurrentVersion").sub(vec![
                        T::lit("Svchost").emit(KIND, |object, cell| {
                            let groups = parse_value_map(cell, |value| {
                                Some((
                                    value.get_pretty_name(),
                                    json!(value_text(value)),
                                ))
                            });
                            object.text =
                                format!("Svchost service groups: {} entries", groups.len());
                            object
                                .data
                                .insert("svchost_service_groups".into(), json!(groups));
                            Outcome::Keep
                        }),
                    ])]),
                ])]),
            ]
        },
    }
}
