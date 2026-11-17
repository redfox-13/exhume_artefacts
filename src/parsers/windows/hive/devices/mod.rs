//! Devices profile (SYSTEM hive)
use notatin::cell_key_node::CellKeyNode;
use serde_json::{json, Map, Value};

use super::{Artefact, ObjectOutput, Outcome};
pub(super) mod usb;
pub(super) mod usbstor;

pub(super) fn profile() -> Vec<Artefact> {
    vec![
        usb::artefact(),
        usbstor::artefact()
    ]
}

pub(super) fn device_properties(
    cell: &CellKeyNode,
    include_location_information: bool,
) -> Map<String, Value> {
    super::parse_values(cell, |value| {
        let name = value.get_pretty_name();
        let data = super::value_text(value);

        match name.as_str() {
            "Mfg" => Some(("manufacturer".into(), json!(data))),
            "DeviceDesc" => Some(("device_description".into(), json!(data))),
            "FriendlyName" => Some(("friendly_name".into(), json!(data))),
            "HardwareID" => Some(("hardware_ids".into(), json!(data))),
            "CompatibleIDs" => Some(("compatible_ids".into(), json!(data))),
            "Class" => Some(("class".into(), json!(data))),
            "LocationInformation" if include_location_information => {
                Some(("location_information".into(), json!(data)))
            }
            "Service" => {
                let description = match data.to_lowercase().as_str() {
                    "usbstor" => "USB Mass Storage Driver",
                    "usb" => "USB Driver",
                    "usbhub" => "USB Hub Driver",
                    "usbhub3" => "USB 3.0 Hub Driver",
                    "hidusb" => "USB Human Interface Device Driver",
                    "disk" => "Disk Driver",
                    _ => "Unknown Driver Service",
                };

                Some((
                    "service".into(),
                    json!(format!("{} ({})", description, data)),
                ))
            }
            "ParentIdPrefix" => Some(("parent_id_prefix".into(), json!(data))),
            _ => None,
        }
    })
}

pub(super) fn set_time(object: &mut ObjectOutput, cell: &CellKeyNode, field: &str) -> Outcome {
    let (ts_unix, ts_unix_ms, ts_rfc3339) = super::parse_time(cell);

    object
        .data
        .entry("device_times")
        .or_insert_with(|| json!({}))[field] = json!({
        "timestamp": ts_rfc3339,
        "timestamp_unix": ts_unix,
        "timestamp_unix_ms": ts_unix_ms,
    });

    Outcome::Keep
}
