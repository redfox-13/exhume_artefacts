use serde_json::{json, Value};

use super::super::{hive_kind_prefix, Artefact, Outcome, TrieNode as T};
use super::{device_properties, set_time};

pub const KIND: &str = hive_kind_prefix!("devices.usbstor");

/// ControlSet\Enum\USBSTOR\<Disk&Ven_..&Prod_..&Rev_..>\<serial>
pub fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![
                T::pre("ControlSet").sub(vec![
                    T::lit("Enum").sub(vec![
                        T::lit("USBSTOR").sub(vec![
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
                                        let control_set = cell.path.split('\\').nth(2);

                                        object.text = format!(
                                            "USB STORAGE DEVICE: {} (Serial: {})",
                                            cell.path, cell.key_name
                                        );
                                        object.data.insert(
                                            "device_instance_id".into(),
                                            json!(cell.key_name),
                                        );
                                        object.data.insert("control_set".into(), json!(control_set));
                                        object.data.insert(
                                            "device_properties".into(),
                                            Value::Object(device_properties(cell, false)),
                                        );

                                        Outcome::Keep
                                    }),
                            ]),
                        ]),
                    ]),
                ]),
            ]
        },
    }
}
