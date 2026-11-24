use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("devices.portable_devices");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let devices = || {
                T::lit("Microsoft").sub(vec![T::lit("Windows Portable Devices").sub(vec![
                    T::lit("Devices").sub(vec![T::any().emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        let half = cell
                            .key_name
                            .split("##")
                            .nth(1)
                            .or_else(|| cell.key_name.split("??").nth(1))
                            .unwrap_or_default();
                        let split = half.split('#').collect::<Vec<_>>();
                        object.text = format!("Portable device: {}", cell.key_name);
                        object
                            .data
                            .insert("device_instance_id".into(), json!(cell.key_name));
                        object
                            .data
                            .insert("device_type".into(), json!(split.get(1)));
                        object
                            .data
                            .insert("device_serial_number".into(), json!(split.get(2)));
                        object.data.insert(
                            "friendly_name".into(),
                            values
                                .iter()
                                .find(|(name, _)| name.eq_ignore_ascii_case("FriendlyName"))
                                .map(|(_, value)| value.clone())
                                .unwrap_or(serde_json::Value::Null),
                        );
                        object
                            .data
                            .insert("portable_device_values".into(), json!(values));
                        Outcome::Keep
                    })]),
                ])])
            };
            vec![devices(), T::lit("Software").sub(vec![devices()])]
        },
    }
}
