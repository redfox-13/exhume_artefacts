//! Devices profile (SYSTEM hive)
use notatin::cell_key_node::CellKeyNode;
use serde_json::{Map, Value, json};

use super::{Artefact, ObjectOutput, Outcome, parse_time, parse_value_map, value_text};
pub(super) mod usb;
pub(super) mod usbstor;
pub(super) mod volume_mappings;
pub(super) mod emdmgmt;
pub(super) mod audio_devices;
pub(super) mod portable_devices;
pub(super) mod print_devices;

pub(super) fn artefacts() -> Vec<Artefact> {
    vec![
        usb::artefact(),
        usbstor::artefact(),
        volume_mappings::artefact(),
        emdmgmt::artefact(),
        audio_devices::artefact(),
        portable_devices::artefact(),
        print_devices::artefact(),
    ]
}

pub(super) fn device_properties(
    cell: &CellKeyNode,
    include_location_information: bool,
) -> Map<String, Value> {
    parse_value_map(cell, |value| {
        let name = value.get_pretty_name();
        let data = value_text(value);

        match name.to_lowercase().as_str() {
            "mfg" => Some(("manufacturer".into(), json!(data))),
            "devicedesc" => Some(("device_description".into(), json!(data))),
            "friendlyname" => Some(("friendly_name".into(), json!(data))),
            "hardwareid" => Some(("hardware_ids".into(), json!(data))),
            "compatibleids" => Some(("compatible_ids".into(), json!(data))),
            "class" => Some(("class".into(), json!(data))),
            "locationinformation" if include_location_information => {
                Some(("location_information".into(), json!(data)))
            }
            "service" => {
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
            "parentidprefix" => Some(("parent_id_prefix".into(), json!(data))),
            _ => None,
        }
    })
}

pub(super) fn set_time(object: &mut ObjectOutput, cell: &CellKeyNode, field: &str) -> Outcome {
    let (ts_unix, ts_unix_ms, ts_rfc3339) = parse_time(cell);

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
