use serde_json::json;

use crate::formats::timestamps::windows_filetime_to_json;

use super::super::{
    Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map,
};

pub const KIND: &str = hive_kind_prefix!("program_execution.heap_leak_detection");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let diagnosed_apps = || {
                T::lit("Microsoft").sub(vec![T::lit("RADAR").sub(vec![
                    T::lit("HeapLeakDetection").sub(vec![
                        T::lit("DiagnosedApplications").sub(vec![T::any().emit(
                            KIND,
                            |object, cell| {
                                let values = registry_value_map(cell);
                                let last_detection_time = cell
                                    .value_iter()
                                    .find(|value| {
                                        value
                                            .get_pretty_name()
                                            .eq_ignore_ascii_case("LastDetectionTime")
                                    })
                                    .and_then(|value| {
                                        let bytes = value.detail.value_bytes()?;
                                        let bytes: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
                                        Some(windows_filetime_to_json(u64::from_le_bytes(bytes)))
                                    });
                                object.text =
                                    format!("Heap leak diagnosed application: {}", cell.key_name);
                                object.data.insert("application_name".into(), json!(cell.key_name));
                                object.data.insert(
                                    "last_detection_time".into(),
                                    json!(last_detection_time),
                                );
                                object
                                    .data
                                    .insert("heap_detection_values".into(), json!(values));
                                Outcome::Keep
                            },
                        )]),
                    ]),
                ])])
            };
            vec![
                diagnosed_apps(),
                T::lit("Software").sub(vec![diagnosed_apps()]),
            ]
        },
    }
}
