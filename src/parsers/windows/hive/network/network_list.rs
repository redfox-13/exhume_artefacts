use chrono::NaiveDate;
use serde_json::{Value, json};

use super::super::{
    Artefact, ObjectOutput, Outcome, TrieNode as T, hive_kind_prefix, parse_value_map, value_text
};
use notatin::cell_key_node::CellKeyNode;
use notatin::cell_key_value::CellKeyValue;

pub const KIND: &str = hive_kind_prefix!("network.network_list");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Software").sub(vec![T::lit("Microsoft").sub(vec![
                T::lit("Windows NT").sub(vec![T::lit("CurrentVersion").sub(vec![
                    T::lit("NetworkList").sub(vec![
                        T::lit("Profiles").sub(vec![T::any().emit(KIND, |object, cell| {
                            let values = parse_value_map(cell, |value| {
                                let name = value.get_pretty_name();
                                let data = match name.to_ascii_lowercase().as_str() {
                                    "datecreated" | "datelastconnected" => systemtime_value(value),
                                    "nametype" => network_type(value),
                                    _ => json!(value_text(value)),
                                };
                                Some((name, data))
                            });
                            object.text = format!("Network profile: {}", cell.key_name);
                            object
                                .data
                                .insert("profile_id".into(), json!(cell.key_name));
                            object
                                .data
                                .insert("network_profile_properties".into(), json!(values));
                            Outcome::Keep
                        })]),
                        T::lit("Signatures").sub(vec![
                            T::lit("Managed").sub(vec![T::any().emit(KIND, |object, cell| {
                                signature_output(object, cell, "managed");
                                Outcome::Keep
                            })]),
                            T::lit("Unmanaged").sub(vec![T::any().emit(KIND, |object, cell| {
                                signature_output(object, cell, "unmanaged");
                                Outcome::Keep
                            })]),
                        ]),
                        T::lit("Nla").sub(vec![T::lit("Cache").sub(vec![T::lit("Intranet").sub(
                            vec![T::any().emit(KIND, |object, cell| {
                                object.text = format!("Network location cache: {}", cell.key_name);
                                object
                                    .data
                                    .insert("intranet_domain_or_ip".into(), json!(cell.key_name));
                                Outcome::Keep
                            })],
                        )])]),
                        T::lit("Nla").sub(vec![T::lit("Wireless").sub(vec![T::any().emit(
                            KIND,
                            |object, cell| {
                                let encoded_value = cell
                                    .get_value("")
                                    .map(|value| value_text(&value));
                                object.text = "Network location wireless cache entry".into();
                                object
                                    .data
                                    .insert("wireless_cache_key".into(), json!(cell.key_name));
                                object.data.insert(
                                    "wireless_cache_value".into(),
                                    json!(encoded_value),
                                );
                                object.data.insert(
                                    "decoded_wireless_network_name".into(),
                                    json!(encoded_value.as_deref().and_then(decode_hex_ascii)),
                                );
                                Outcome::Keep
                            },
                        )])]),
                    ]),
                ])]),
            ])])]
        },
    }
}

fn systemtime_value(value: &CellKeyValue) -> Value {
    let bytes = value.detail.value_bytes().unwrap_or_default();
    let Some(fields) = bytes.get(..16).filter(|_| bytes.len() == 16).map(|bytes| {
        bytes
            .chunks_exact(2)
            .map(|word| u16::from_le_bytes([word[0], word[1]]))
            .collect::<Vec<_>>()
    }) else {
        return Value::Null;
    };
    let timestamp = NaiveDate::from_ymd_opt(
        i32::from(fields[0]),
        u32::from(fields[1]),
        u32::from(fields[3]),
    )
    .and_then(|date| {
        date.and_hms_milli_opt(
            u32::from(fields[4]),
            u32::from(fields[5]),
            u32::from(fields[6]),
            u32::from(fields[7]),
        )
    })
    .map(|datetime| datetime.format("%Y-%m-%dT%H:%M:%S%.3f").to_string());

    json!({ "local_datetime": timestamp })
}

fn network_type(value: &CellKeyValue) -> Value {
    let raw = value_text(value);
    let label = match raw.parse::<u32>().ok() {
        Some(0x47) => "wireless",
        Some(0x06) => "wired",
        Some(0x17) => "broadband",
        _ => "unknown",
    };
    json!({ "raw": raw, "label": label })
}

fn signature_output(object: &mut ObjectOutput, cell: &CellKeyNode, signature_type: &str) {
    let values = parse_value_map(cell, |value| {
        let name = value.get_pretty_name();
        let data = if name.eq_ignore_ascii_case("DefaultGatewayMac") {
            gateway_mac(value)
                .map_or_else(|| json!(value_text(value)), |mac| json!(mac))
        } else {
            json!(value_text(value))
        };
        Some((name, data))
    });
    let profile_guid = cell
        .get_value("ProfileGuid")
        .map(|value| value_text(&value));
    object.text = format!("Network signature ({signature_type}): {}", cell.key_name);
    object
        .data
        .insert("signature_type".into(), json!(signature_type));
    object
        .data
        .insert("signature_key".into(), json!(cell.key_name));
    object
        .data
        .insert("profile_guid".into(), json!(profile_guid));
    object
        .data
        .insert("default_gateway_mac".into(), json!(gateway_mac_value(cell)));
    object
        .data
        .insert("network_signature_properties".into(), json!(values));
}

fn gateway_mac(value: &CellKeyValue) -> Option<String> {
    let bytes = value.detail.value_bytes().unwrap_or_default();
    let address = bytes.get(..6)?;
    Some(
        address
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join("-"),
    )
}

fn gateway_mac_value(cell: &CellKeyNode) -> Option<String> {
    cell.get_value("DefaultGatewayMac")
        .as_ref()
        .and_then(gateway_mac)
}

fn decode_hex_ascii(value: &str) -> Option<String> {
    if value.is_empty() || value.len() % 2 != 0 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(pair, 16).ok().map(char::from)
        })
        .collect()
}
