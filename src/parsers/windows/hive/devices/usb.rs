use serde_json::{Value, json};

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix};
use super::{device_properties, set_time};

pub const KIND: &str = hive_kind_prefix!("devices.usb");

/// ControlSet\Enum\USB\<VID_..&PID_..>\<serial>
pub fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![
                T::pre("ControlSet").sub(vec![T::lit("Enum").sub(vec![T::lit("USB").sub(vec![
                    T::any().sub(vec![
                                T::any()
                                    .sub(vec![
                                        T::lit("Properties").sub(vec![
                                            T::lit("{83da6326-97a6-4088-9453-a1923f573b29}")
                                                .sub(vec![
                                                    T::lit("0064").combine(KIND, |obj, cell| {
                                                        set_time(obj, cell, "install")
                                                    }),
                                                    T::lit("0065").combine(KIND, |obj, cell| {
                                                        set_time(obj, cell, "first_install")
                                                    }),
                                                    T::lit("0066").combine(KIND, |obj, cell| {
                                                        set_time(obj, cell, "last_arrival")
                                                    }),
                                                    T::lit("0067").combine(KIND, |obj, cell| {
                                                        set_time(obj, cell, "last_removal")
                                                    }),
                                                ]),
                                        ]),
                                    ])
                                    .combine(KIND, |object, cell| {
                                        let parts: Vec<&str> = cell.path.split('\\').collect();

                                        object.text = format!(
                                            "USB DEVICE: {} (Serial: {})",
                                            cell.path, cell.key_name
                                        );
                                        object.data.insert(
                                            "device_instance_id".into(),
                                            json!(cell.key_name),
                                        );
                                        object.data.insert("device_id".into(), json!(parts.get(5)));
                                        object
                                            .data
                                            .insert("control_set".into(), json!(parts.get(2)));
                                        object.data.insert(
                                            "device_properties".into(),
                                            Value::Object(device_properties(cell, true)),
                                        );

                                        Outcome::Keep
                                    }),
                            ]),
                ])])]),
            ]
        },
    }
}
