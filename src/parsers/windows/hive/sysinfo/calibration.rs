use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("sysinfo.display_calibration");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let calibration = || {
                T::lit("Microsoft").sub(vec![T::lit("Windows NT").sub(vec![
                    T::lit("CurrentVersion").sub(vec![T::lit("ICM").sub(vec![
                        T::lit("Calibration").emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = "Display calibration configuration".into();
                            object
                                .data
                                .insert("display_calibration_values".into(), json!(values));
                            Outcome::Keep
                        }),
                    ])]),
                ])])
            };
            vec![
                calibration(),
                T::lit("Software").sub(vec![calibration()]),
            ]
        },
    }
}
