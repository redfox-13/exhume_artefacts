use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("devices.printers");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let print = || {
                T::lit("Microsoft").sub(vec![T::lit("Windows NT").sub(vec![
                    T::lit("CurrentVersion").sub(vec![
                        T::lit("Ports").emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = "Configured printer ports".into();
                            object.data.insert("printer_ports".into(), json!(values));
                            Outcome::Keep
                        }),
                        T::lit("Print").sub(vec![T::lit("Printers").sub(vec![
                            T::any().emit(KIND, |object, cell| {
                                let values = registry_value_map(cell);
                                object.text = format!("Installed printer: {}", cell.key_name);
                                object.data.insert("printer_name".into(), json!(cell.key_name));
                                object.data.insert("printer_values".into(), json!(values));
                                Outcome::Keep
                            }),
                        ])]),
                    ]),
                ])])
            };
            vec![print(), T::lit("Software").sub(vec![print()])]
        },
    }
}
