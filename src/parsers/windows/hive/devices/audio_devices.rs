use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("devices.audio_endpoints");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let endpoint = |direction: &'static str| {
                T::lit(direction).sub(vec![T::any().sub(vec![
                    T::lit("Properties").emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = "Audio endpoint device name".into();
                            object.data.insert(
                                "audio_direction".into(),
                                json!(if cell.path.to_ascii_lowercase().contains("\\capture\\") {
                                    "capture"
                                } else {
                                    "render"
                                }),
                            );
                            object.data.insert(
                                "audio_device_name".into(),
                                values
                                    .iter()
                                    .find(|(name, _)| {
                                        name.eq_ignore_ascii_case("{a45c254e-df1c-4efd-8020-67d146a850e0},2")
                                    })
                                    .map(|(_, value)| value.clone())
                                    .unwrap_or(serde_json::Value::Null),
                            );
                            object
                                .data
                                .insert("audio_endpoint_properties".into(), json!(values));
                            Outcome::Keep
                        }),
                ])])
            };
            let audio = || {
                T::lit("Microsoft").sub(vec![T::lit("Windows").sub(vec![
                    T::lit("CurrentVersion").sub(vec![T::lit("MMDevices").sub(vec![
                        T::lit("Audio").sub(vec![endpoint("Capture"), endpoint("Render")]),
                    ])]),
                ])])
            };
            vec![audio(), T::lit("Software").sub(vec![audio()])]
        },
    }
}
