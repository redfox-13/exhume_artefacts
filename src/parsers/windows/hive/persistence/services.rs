use serde_json::{json, Map, Value};

use super::super::{TrieNode as T, hive_kind_prefix, Artefact, Outcome, parse_values};

const KIND: &str = hive_kind_prefix!("persistence.service");

/// ControlSet\Services\<name> (+ Parameters\ServiceDll)
pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![
                T::pre("ControlSet").sub(vec![
                    T::lit("Services").sub(vec![
                        T::any()
                            .sub(vec![
                                T::lit("Parameters").combine(KIND, |object, cell| {
                                    let params: Map<String, Value> =
                                        parse_values(cell, |value| {
                                            let data = super::super::value_text(value);
                                            match value.get_pretty_name().to_lowercase().as_str() {
                                                "servicedll" => {
                                                    Some(("service_dll".into(), json!(data)))
                                                }
                                                "servicemain" => {
                                                    Some(("service_main".into(), json!(data)))
                                                }
                                                _ => None,
                                            }
                                        });
                                    object.data.extend(params);
                                    Outcome::Keep
                                }),
                            ])
                            .combine(KIND, |object, cell| {
                                let props: Map<String, Value> =
                                    parse_values(cell, |value| {
                                        let data = super::super::value_text(value);
                                        match value.get_pretty_name().to_lowercase().as_str() {
                                            "imagepath" => {
                                                Some(("image_path".into(), json!(data)))
                                            }
                                            "displayname" => {
                                                Some(("display_name".into(), json!(data)))
                                            }
                                            "objectname" => {
                                                Some(("object_name".into(), json!(data)))
                                            }
                                            "group" => Some(("group".into(), json!(data))),
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
                            }),
                    ]),
                ]),
            ]
        },
    }
}
