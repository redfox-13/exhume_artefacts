use serde_json::json;

use crate::formats::timestamps::windows_filetime_to_json;

use super::super::{
    Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map,
};

pub const KIND: &str = hive_kind_prefix!("devices.readyboost_history");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let devices = || {
                T::lit("Microsoft").sub(vec![T::lit("Windows NT").sub(vec![
                    T::lit("CurrentVersion").sub(vec![T::lit("EMDMgmt").sub(vec![
                        T::any().emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            let last_tested_time = cell
                                .value_iter()
                                .find(|value| {
                                    value
                                        .get_pretty_name()
                                        .eq_ignore_ascii_case("LastTestedTime")
                                })
                                .and_then(|value| {
                                    let bytes = value.detail.value_bytes()?;
                                    let bytes: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
                                    Some(windows_filetime_to_json(u64::from_le_bytes(bytes)))
                                });
                            let identifiers = cell.key_name.split('#').collect::<Vec<_>>();
                            object.text = format!("ReadyBoost device: {}", cell.key_name);
                            object
                                .data
                                .insert("device_registry_name".into(), json!(cell.key_name));
                            object.data.insert(
                                "device_model".into(),
                                json!(identifiers.get(1)),
                            );
                            object.data.insert(
                                "device_serial_number".into(),
                                json!(identifiers.get(2)),
                            );
                            object
                                .data
                                .insert("last_tested_time".into(), json!(last_tested_time));
                            object
                                .data
                                .insert("readyboost_device_values".into(), json!(values));
                            Outcome::Keep
                        }),
                    ])]),
                ])])
            };
            vec![devices(), T::lit("Software").sub(vec![devices()])]
        },
    }
}
