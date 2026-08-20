//! macOS network configuration and DHCP lease plist parser.
//!
//! One parser handles the closely related plist stores catalogued by Exhume:
//! - `preferences.plist` (`NetworkServices`) -> configured network services;
//! - `NetworkInterfaces.plist` (`Interfaces`) -> physical/logical interfaces;
//! - `com.apple.airport.preferences.plist` and the newer
//!   `com.apple.wifi.known-networks.plist` -> Wi-Fi settings/known networks;
//! - `/private/var/db/dhcpclient/leases/*.plist` -> DHCP lease metadata.
//!
//! Dispatch is based on stable root keys rather than filenames. The indexer
//! retains the original source path for provenance and as a fallback for DHCP
//! interface names such as `leases/en0.plist`. Passwords and opaque DHCP
//! packets are never emitted.

use crate::core::{ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::parsers::macos::common::input::FileEvidence;
use crate::parsers::macos::common::timestamps::apple_absolute_to_json;
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use plist::{Dictionary, Value as Plist};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::io::Cursor;
use std::time::SystemTime;

const PARSER_NAME: &str = "macos_network";
const SERVICES_SCHEMA: &str = "macos_systemconfiguration_services_v1";
const INTERFACES_SCHEMA: &str = "macos_systemconfiguration_interfaces_v1";
const WIFI_SCHEMA: &str = "macos_wifi_preferences_v1";
const DHCP_SCHEMA: &str = "macos_dhcp_lease_v1";

#[derive(Default)]
pub struct MacosNetworkParser;

impl Parser for MacosNetworkParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse macOS SystemConfiguration interfaces/services, Wi-Fi preferences and DHCP client lease plists."
    }

    fn requires_source_metadata(&self) -> bool {
        true
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        match obj.kind {
            "macos.network.wifi_network" => {
                let Some(ts_unix_ms) = obj.json["timestamps"]["last_connected"]["unix_ms"].as_i64()
                else {
                    return Vec::new();
                };
                let ssid = obj.json["network"]["ssid"]
                    .as_str()
                    .unwrap_or("unknown Wi-Fi network");
                vec![TimelineEvent {
                    ts_unix_ms,
                    event_type: "macos.network.wifi_connected",
                    description: Some(format!("Last connected to Wi-Fi network {ssid}")),
                    actor: None,
                }]
            }
            "macos.network.dhcp_lease" => {
                let Some(ts_unix_ms) = obj.json["timestamps"]["lease_start"]["unix_ms"].as_i64()
                else {
                    return Vec::new();
                };
                let address = obj.json["lease"]["ip_address"]
                    .as_str()
                    .unwrap_or("unknown address");
                let interface = obj.json["lease"]["interface"].as_str().map(str::to_owned);
                vec![TimelineEvent {
                    ts_unix_ms,
                    event_type: "macos.network.dhcp_lease",
                    description: Some(format!("DHCP lease assigned {address}")),
                    actor: interface,
                }]
            }
            _ => Vec::new(),
        }
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = FileEvidence::read_primary(input)?;
        let root = Plist::from_reader(Cursor::new(&evidence.bytes))
            .map_err(|err| anyhow::anyhow!("not a valid macOS network plist: {err}"))?;
        let Some(dict) = root.as_dictionary() else {
            bail!("not a supported macOS network plist (root is not a dictionary)");
        };

        if dict
            .get("NetworkServices")
            .and_then(Plist::as_dictionary)
            .is_some()
        {
            return emit_network_services(dict, &evidence, sink);
        }
        if dict.get("Interfaces").and_then(Plist::as_array).is_some() {
            return emit_interfaces(dict, &evidence, sink);
        }
        if is_dhcp_lease(dict) {
            return emit_dhcp_lease(dict, &evidence, sink);
        }
        if is_wifi_configuration(dict) {
            return emit_wifi_configuration(dict, &evidence, sink);
        }

        bail!("not a supported macOS network/Wi-Fi/DHCP plist (unrecognised root keys)")
    }
}

fn emit_network_services(
    root: &Dictionary,
    evidence: &FileEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let Some(services) = root.get("NetworkServices").and_then(Plist::as_dictionary) else {
        return Ok(());
    };

    for (index, (service_id, value)) in services.iter().enumerate() {
        let Some(service) = value.as_dictionary() else {
            continue;
        };
        let interface = child_dict(service, "Interface");
        let ipv4 = child_dict(service, "IPv4");
        let ipv6 = child_dict(service, "IPv6");
        let dns = child_dict(service, "DNS");
        let proxies = child_dict(service, "Proxies");

        let name = text(service.get("UserDefinedName"))
            .or_else(|| interface.and_then(|d| text(d.get("UserDefinedName"))));
        let device = interface.and_then(|d| text(d.get("DeviceName")));
        let display_text = name
            .clone()
            .or_else(|| device.clone())
            .unwrap_or_else(|| service_id.clone());

        let json = json!({
            "platform": "macos",
            "app": "systemconfiguration",
            "record_type": "network_service",
            "source": evidence.source_json("network_service", index as i64, SERVICES_SCHEMA),
            "configuration": {
                "model": text(root.get("Model")),
                "current_set": text(root.get("CurrentSet")),
            },
            "service": {
                "id": service_id,
                "name": name,
                "enabled": !bool_or_integer(service.get("__INACTIVE__")).unwrap_or(false),
                "interface": {
                    "device": device,
                    "hardware": interface.and_then(|d| text(d.get("Hardware"))),
                    "type": interface.and_then(|d| text(d.get("Type"))),
                    "subtype": interface.and_then(|d| text(d.get("SubType"))),
                },
                "ipv4": {
                    "method": ipv4.and_then(|d| text(d.get("ConfigMethod"))),
                    "addresses": ipv4.map(|d| string_array(d.get("Addresses"))).unwrap_or(Value::Null),
                    "router": ipv4.and_then(|d| text(d.get("Router"))),
                    "subnet_masks": ipv4.map(|d| string_array(d.get("SubnetMasks"))).unwrap_or(Value::Null),
                },
                "ipv6": {
                    "method": ipv6.and_then(|d| text(d.get("ConfigMethod"))),
                    "addresses": ipv6.map(|d| string_array(d.get("Addresses"))).unwrap_or(Value::Null),
                },
                "dns": {
                    "servers": dns.map(|d| string_array(d.get("ServerAddresses"))).unwrap_or(Value::Null),
                    "search_domains": dns.map(|d| string_array(d.get("SearchDomains"))).unwrap_or(Value::Null),
                    "domain": dns.and_then(|d| text(d.get("DomainName"))),
                },
                "proxies": proxy_json(proxies),
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "macos.network.service",
            text: display_text,
            json,
        })?;
    }
    Ok(())
}

fn emit_interfaces(
    root: &Dictionary,
    evidence: &FileEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let Some(interfaces) = root.get("Interfaces").and_then(Plist::as_array) else {
        return Ok(());
    };

    for (index, value) in interfaces.iter().enumerate() {
        let Some(interface) = value.as_dictionary() else {
            continue;
        };
        let info = child_dict(interface, "SCNetworkInterfaceInfo");
        let bsd_name = text(interface.get("BSD Name"));
        let display_name = info
            .and_then(|d| text(d.get("UserDefinedName")))
            .or_else(|| text(interface.get("UserDefinedName")));
        let display_text = display_name
            .clone()
            .or_else(|| bsd_name.clone())
            .unwrap_or_else(|| format!("interface {index}"));

        let json = json!({
            "platform": "macos",
            "app": "systemconfiguration",
            "record_type": "network_interface",
            "source": evidence.source_json("interface", index as i64, INTERFACES_SCHEMA),
            "interface": {
                "index": index,
                "bsd_name": bsd_name,
                "display_name": display_name,
                "type": text(interface.get("SCNetworkInterfaceType")),
                "active": bool_value(interface.get("Active")),
                "built_in": bool_value(interface.get("IOBuiltin")),
                "hidden_configuration": bool_value(interface.get("HiddenConfiguration")),
                "mac_address": mac_address(interface.get("IOMACAddress")),
                "matching_macs": mac_array(interface.get("MatchingMACs")),
                "io_interface_type": integer_value(interface.get("IOInterfaceType")),
                "io_interface_unit": integer_value(interface.get("IOInterfaceUnit")),
                "io_path": text(interface.get("IOPathMatch")),
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "macos.network.interface",
            text: display_text,
            json,
        })?;
    }
    Ok(())
}

fn emit_wifi_configuration(
    root: &Dictionary,
    evidence: &FileEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let global_json = json!({
        "platform": "macos",
        "app": "wifi",
        "record_type": "wifi_configuration",
        "source": evidence.source_json("wifi_configuration", 0, WIFI_SCHEMA),
        "configuration": {
            "version": integer_value(root.get("Version")),
            "device_uuid": text(root.get("DeviceUUID")),
            "power_enabled": bool_value(root.get("PowerEnabled")),
            "auto_hotspot_mode": text(root.get("AutoHotspotMode")),
            "private_mac_mode": integer_value(root.get("PrivateMACAddressModeSystemSetting")),
            "preferred_order": value_array(root.get("PreferredOrder")),
        },
    });
    sink(ObjectParsed {
        parser: PARSER_NAME,
        kind: "macos.network.wifi_configuration",
        text: "Wi-Fi configuration".to_string(),
        json: global_json,
    })?;

    let mut emitted = HashSet::new();
    let mut index = 1i64;

    if let Some(known) = root.get("KnownNetworks").and_then(Plist::as_dictionary) {
        for (key, value) in known {
            if let Some(network) = value.as_dictionary() {
                emit_wifi_network(key, network, evidence, &mut emitted, &mut index, sink)?;
            }
        }
    }

    if let Some(remembered) = root.get("RememberedNetworks").and_then(Plist::as_array) {
        for (position, value) in remembered.iter().enumerate() {
            if let Some(network) = value.as_dictionary() {
                emit_wifi_network(
                    &format!("remembered:{position}"),
                    network,
                    evidence,
                    &mut emitted,
                    &mut index,
                    sink,
                )?;
            }
        }
    }

    // Sonoma and newer `com.apple.wifi.known-networks.plist` stores profiles
    // directly under opaque `wifi.network.ssid.*` keys.
    for (key, value) in root {
        let Some(network) = value.as_dictionary() else {
            continue;
        };
        if key.starts_with("wifi.network.") || has_ssid_key(network) {
            emit_wifi_network(key, network, evidence, &mut emitted, &mut index, sink)?;
        }
    }

    Ok(())
}

fn emit_wifi_network(
    key: &str,
    network: &Dictionary,
    evidence: &FileEvidence,
    emitted: &mut HashSet<String>,
    index: &mut i64,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let ssid = first_text(
        network,
        &["SSID_STR", "SSIDString", "SSID", "DisplayName", "Name"],
    );
    let network_id = first_text(network, &["UUID", "NetworkID", "UniqueIdentifier"])
        .unwrap_or_else(|| key.to_string());
    let signature = format!("{}\u{1f}{}", network_id, ssid.as_deref().unwrap_or(""));
    if !emitted.insert(signature) {
        return Ok(());
    }

    let bssid = first_mac(network, &["BSSID", "BSSID_STR"]);
    let last_connected = first_timestamp(
        network,
        &[
            "LastConnected",
            "lastConnected",
            "LastConnectedDate",
            "LastConnectionDate",
        ],
    );
    let added = first_timestamp(network, &["AddedAt", "AddedDate", "CreatedAt"]);
    let text = ssid.clone().unwrap_or_else(|| network_id.clone());

    let json = json!({
        "platform": "macos",
        "app": "wifi",
        "record_type": "known_wifi_network",
        "source": evidence.source_json("wifi_network", *index, WIFI_SCHEMA),
        "timestamps": {
            "added": added,
            "last_connected": last_connected,
            "captive_login": first_timestamp(network, &["CaptiveWebSheetLoginDate", "CaptiveLoginDate"]),
        },
        "network": {
            "id": network_id,
            "ssid": ssid,
            "bssid": bssid,
            "security_type": first_text(network, &["SecurityType", "Security", "AuthType"]),
            "auto_join": first_bool(network, &["AutoJoin", "AutoJoinEnabled"]),
            "hidden": first_bool(network, &["Hidden", "HiddenNetwork"]),
            "captive": first_bool(network, &["Captive", "WasCaptiveNetwork"]),
            "passpoint": first_bool(network, &["Passpoint", "IsPasspoint"]),
            "personal_hotspot": first_bool(network, &["PersonalHotspot", "IsPersonalHotspot"]),
            "private_mac_mode": first_integer(network, &["PrivateMACAddressModeUserSetting", "PrivateMACAddressMode"]),
            "roaming_profile_type": first_text(network, &["RoamingProfileType"]),
        },
    });

    sink(ObjectParsed {
        parser: PARSER_NAME,
        kind: "macos.network.wifi_network",
        text,
        json,
    })?;
    *index += 1;
    Ok(())
}

fn emit_dhcp_lease(
    root: &Dictionary,
    evidence: &FileEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let start = first_timestamp(root, &["LeaseStartDate", "LeaseStartTime"]);
    let length = first_integer(root, &["LeaseLength", "LeaseDuration"]);
    let expiration = start["unix_ms"]
        .as_i64()
        .zip(length)
        .and_then(|(start_ms, seconds)| start_ms.checked_add(seconds.checked_mul(1_000)?))
        .map(unix_ms_to_json)
        .unwrap_or(Value::Null);
    let address = first_text(root, &["IPAddress", "yiaddr"]);
    let interface = first_text(root, &["InterfaceName", "Interface", "BSDName"])
        .or_else(|| dhcp_interface_from_path(&evidence.source_label));
    let ssid = first_text(root, &["SSID", "SSID_STR", "NetworkName"]);
    let text = address
        .clone()
        .map(|ip| match interface.as_deref() {
            Some(name) => format!("{name}: {ip}"),
            None => ip,
        })
        .unwrap_or_else(|| "DHCP lease".to_string());

    let json = json!({
        "platform": "macos",
        "app": "dhcpclient",
        "record_type": "dhcp_lease",
        "source": evidence.source_json("dhcp_lease", 0, DHCP_SCHEMA),
        "timestamps": {
            "lease_start": start,
            "lease_expiration": expiration,
        },
        "lease": {
            "interface": interface,
            "ssid": ssid,
            "ip_address": address,
            "subnet_mask": first_text(root, &["SubnetMask", "subnet_mask"]),
            "router_ip": first_text(root, &["RouterIPAddress", "Router", "router"]),
            "router_hardware_address": first_mac(root, &["RouterHardwareAddress", "RouterMACAddress"]),
            "server_identifier": first_text(root, &["ServerIdentifier", "DHCPServerIdentifier"]),
            "domain_name": first_text(root, &["DomainName", "Domain"]),
            "dns_servers": first_string_array(root, &["DNSServers", "DomainNameServers"]),
            "lease_length_seconds": length,
            "client_identifier": first_data_summary(root, &["ClientIdentifier", "ClientID"]),
            "packet_length": root.get("Packet").and_then(Plist::as_data).map(|data| data.len()),
        },
    });

    let object = ObjectParsed {
        parser: PARSER_NAME,
        kind: "macos.network.dhcp_lease",
        text,
        json,
    };
    sink(object)
}

fn is_dhcp_lease(dict: &Dictionary) -> bool {
    dict.contains_key("LeaseStartDate")
        || dict.contains_key("LeaseLength")
        || (dict.contains_key("IPAddress")
            && (dict.contains_key("RouterIPAddress") || dict.contains_key("Packet")))
}

fn dhcp_interface_from_path(path: &str) -> Option<String> {
    let filename = path.rsplit(['/', '\\']).next()?;
    let interface = filename.strip_suffix(".plist")?;
    non_empty(interface)
}

fn is_wifi_configuration(dict: &Dictionary) -> bool {
    [
        "KnownNetworks",
        "RememberedNetworks",
        "PreferredOrder",
        "PowerEnabled",
        "AutoHotspotMode",
        "PrivateMACAddressModeSystemSetting",
    ]
    .iter()
    .any(|key| dict.contains_key(*key))
        || dict.keys().any(|key| key.starts_with("wifi.network."))
}

fn has_ssid_key(dict: &Dictionary) -> bool {
    ["SSID_STR", "SSIDString", "SSID"]
        .iter()
        .any(|key| dict.contains_key(*key))
}

fn child_dict<'a>(dict: &'a Dictionary, key: &str) -> Option<&'a Dictionary> {
    dict.get(key).and_then(Plist::as_dictionary)
}

fn text(value: Option<&Plist>) -> Option<String> {
    match value? {
        Plist::String(value) => non_empty(value),
        Plist::Data(bytes) => match std::str::from_utf8(bytes) {
            Ok(value) => non_empty(value.trim_end_matches('\0')),
            Err(_) => Some(format!("hex:{}", hex::encode(bytes))),
        },
        Plist::Integer(value) => value
            .as_signed()
            .map(|value| value.to_string())
            .or_else(|| value.as_unsigned().map(|value| value.to_string())),
        _ => None,
    }
}

fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn integer_value(value: Option<&Plist>) -> Option<i64> {
    value.and_then(Plist::as_signed_integer)
}

fn bool_value(value: Option<&Plist>) -> Option<bool> {
    value.and_then(Plist::as_boolean)
}

fn first_text(dict: &Dictionary, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| text(dict.get(*key)))
}

fn first_integer(dict: &Dictionary, keys: &[&str]) -> Option<i64> {
    keys.iter().find_map(|key| integer_value(dict.get(*key)))
}

fn first_bool(dict: &Dictionary, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|key| bool_value(dict.get(*key)))
}

fn first_mac(dict: &Dictionary, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| mac_address(dict.get(*key)))
}

fn mac_address(value: Option<&Plist>) -> Option<String> {
    match value? {
        Plist::Data(bytes) if !bytes.is_empty() => Some(
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        ),
        Plist::String(value) => non_empty(value),
        _ => None,
    }
}

fn mac_array(value: Option<&Plist>) -> Value {
    match value.and_then(Plist::as_array) {
        Some(values) => Value::Array(
            values
                .iter()
                .filter_map(|value| mac_address(Some(value)).map(Value::String))
                .collect(),
        ),
        None => Value::Null,
    }
}

fn string_array(value: Option<&Plist>) -> Value {
    match value {
        Some(Plist::Array(values)) => Value::Array(
            values
                .iter()
                .filter_map(|value| text(Some(value)).map(Value::String))
                .collect(),
        ),
        Some(value) => text(Some(value)).map(Value::String).unwrap_or(Value::Null),
        None => Value::Null,
    }
}

fn value_array(value: Option<&Plist>) -> Value {
    string_array(value)
}

fn first_string_array(dict: &Dictionary, keys: &[&str]) -> Value {
    keys.iter()
        .map(|key| string_array(dict.get(*key)))
        .find(|value| !value.is_null())
        .unwrap_or(Value::Null)
}

fn first_data_summary(dict: &Dictionary, keys: &[&str]) -> Value {
    for key in keys {
        match dict.get(*key) {
            Some(Plist::Data(bytes)) => {
                return json!({ "hex": hex::encode(bytes), "length": bytes.len() });
            }
            Some(value) => {
                if let Some(value) = text(Some(value)) {
                    return Value::String(value);
                }
            }
            None => {}
        }
    }
    Value::Null
}

fn first_timestamp(dict: &Dictionary, keys: &[&str]) -> Value {
    keys.iter()
        .map(|key| plist_timestamp(dict.get(*key)))
        .find(|value| !value.is_null())
        .unwrap_or(Value::Null)
}

fn plist_timestamp(value: Option<&Plist>) -> Value {
    match value {
        Some(Plist::Date(date)) => {
            let system_time: SystemTime = (*date).into();
            let datetime: DateTime<Utc> = system_time.into();
            json!({
                "original": date.to_xml_format(),
                "original_epoch": "plist_date",
                "unix_ms": datetime.timestamp_millis(),
                "rfc3339": datetime.to_rfc3339(),
            })
        }
        Some(Plist::Real(value)) => apple_absolute_to_json(Some(*value)),
        Some(Plist::Integer(value)) => value
            .as_signed()
            .map(|value| apple_absolute_to_json(Some(value as f64)))
            .unwrap_or(Value::Null),
        Some(Plist::String(value)) => DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|datetime| {
                json!({
                    "original": value,
                    "original_epoch": "rfc3339",
                    "unix_ms": datetime.timestamp_millis(),
                    "rfc3339": datetime.to_rfc3339(),
                })
            })
            .unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

fn unix_ms_to_json(unix_ms: i64) -> Value {
    let seconds = unix_ms.div_euclid(1_000);
    let millis = unix_ms.rem_euclid(1_000) as u32;
    json!({
        "original": unix_ms,
        "original_epoch": "derived_unix_milliseconds",
        "unix_ms": unix_ms,
        "rfc3339": DateTime::<Utc>::from_timestamp(seconds, millis * 1_000_000)
            .map(|datetime| datetime.to_rfc3339()),
    })
}

fn proxy_json(proxies: Option<&Dictionary>) -> Value {
    let Some(proxies) = proxies else {
        return Value::Null;
    };
    json!({
        "http": {
            "enabled": bool_or_integer(proxies.get("HTTPEnable")),
            "host": text(proxies.get("HTTPProxy")),
            "port": integer_value(proxies.get("HTTPPort")),
        },
        "https": {
            "enabled": bool_or_integer(proxies.get("HTTPSEnable")),
            "host": text(proxies.get("HTTPSProxy")),
            "port": integer_value(proxies.get("HTTPSPort")),
        },
        "pac": {
            "enabled": bool_or_integer(proxies.get("ProxyAutoConfigEnable")),
            "url": text(proxies.get("ProxyAutoConfigURLString")),
        },
        "exceptions": string_array(proxies.get("ExceptionsList")),
    })
}

fn bool_or_integer(value: Option<&Plist>) -> Option<bool> {
    bool_value(value).or_else(|| integer_value(value).map(|value| value != 0))
}

#[cfg(test)]
mod tests {
    use super::MacosNetworkParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use anyhow::Result;

    fn run(plist: &str) -> Result<Vec<crate::ObjectParsed>> {
        let parser = MacosNetworkParser;
        let mut objects = Vec::new();
        parser.run_into(
            ParserInput::Bytes(plist.as_bytes().to_vec()),
            &mut |object| {
                objects.push(object);
                Ok(())
            },
        )?;
        Ok(objects)
    }

    #[test]
    fn parses_network_services() -> Result<()> {
        let objects = run(r#"<?xml version="1.0" encoding="UTF-8"?>
            <plist version="1.0"><dict>
              <key>CurrentSet</key><string>/Sets/SET-1</string>
              <key>Model</key><string>MacBookAir10,1</string>
              <key>NetworkServices</key><dict>
                <key>SERVICE-1</key><dict>
                  <key>UserDefinedName</key><string>Wi-Fi</string>
                  <key>Interface</key><dict>
                    <key>DeviceName</key><string>en0</string>
                    <key>Hardware</key><string>AirPort</string>
                    <key>Type</key><string>Ethernet</string>
                  </dict>
                  <key>IPv4</key><dict><key>ConfigMethod</key><string>DHCP</string></dict>
                  <key>DNS</key><dict><key>ServerAddresses</key><array><string>1.1.1.1</string></array></dict>
                </dict>
              </dict>
            </dict></plist>"#)?;
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].kind, "macos.network.service");
        assert_eq!(objects[0].json["service"]["name"], "Wi-Fi");
        assert_eq!(objects[0].json["service"]["interface"]["device"], "en0");
        assert_eq!(objects[0].json["service"]["ipv4"]["method"], "DHCP");
        assert_eq!(objects[0].json["service"]["dns"]["servers"][0], "1.1.1.1");
        Ok(())
    }

    #[test]
    fn parses_network_interfaces() -> Result<()> {
        let objects = run(r#"<?xml version="1.0" encoding="UTF-8"?>
            <plist version="1.0"><dict><key>Interfaces</key><array><dict>
              <key>Active</key><true/>
              <key>BSD Name</key><string>en0</string>
              <key>IOBuiltin</key><true/>
              <key>IOMACAddress</key><data>ABEiM0RV</data>
              <key>SCNetworkInterfaceType</key><string>IEEE80211</string>
              <key>SCNetworkInterfaceInfo</key><dict><key>UserDefinedName</key><string>Wi-Fi</string></dict>
            </dict></array></dict></plist>"#)?;
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].kind, "macos.network.interface");
        assert_eq!(objects[0].json["interface"]["bsd_name"], "en0");
        assert_eq!(
            objects[0].json["interface"]["mac_address"],
            "00:11:22:33:44:55"
        );
        assert_eq!(objects[0].json["interface"]["type"], "IEEE80211");
        Ok(())
    }

    #[test]
    fn parses_known_wifi_networks_and_timeline() -> Result<()> {
        let objects = run(r#"<?xml version="1.0" encoding="UTF-8"?>
            <plist version="1.0"><dict>
              <key>PowerEnabled</key><true/>
              <key>PreferredOrder</key><array><string>TestNet</string></array>
              <key>KnownNetworks</key><dict><key>PROFILE-1</key><dict>
                <key>SSID_STR</key><string>TestNet</string>
                <key>SecurityType</key><string>WPA2 Personal</string>
                <key>AutoJoin</key><true/>
                <key>LastConnected</key><date>2024-07-21T06:13:20Z</date>
              </dict></dict>
            </dict></plist>"#)?;
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].kind, "macos.network.wifi_configuration");
        let network = &objects[1];
        assert_eq!(network.kind, "macos.network.wifi_network");
        assert_eq!(network.json["network"]["ssid"], "TestNet");
        assert_eq!(network.json["network"]["auto_join"], true);
        assert_eq!(
            network.json["timestamps"]["last_connected"]["rfc3339"],
            "2024-07-21T06:13:20+00:00"
        );
        let events = MacosNetworkParser.extract_timeline_events(network);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].description.as_deref(),
            Some("Last connected to Wi-Fi network TestNet")
        );
        Ok(())
    }

    #[test]
    fn parses_modern_known_networks_store() -> Result<()> {
        let objects = run(r#"<?xml version="1.0" encoding="UTF-8"?>
            <plist version="1.0"><dict>
              <key>wifi.network.ssid.546573744e6574</key><dict>
                <key>SSID</key><data>VGVzdE5ldA==</data>
                <key>SecurityType</key><string>WPA3 Personal</string>
                <key>PrivateMACAddressModeUserSetting</key><integer>2</integer>
                <key>AddedAt</key><date>2024-07-20T12:00:00Z</date>
              </dict>
            </dict></plist>"#)?;
        assert_eq!(objects.len(), 2);
        let network = &objects[1];
        assert_eq!(network.kind, "macos.network.wifi_network");
        assert_eq!(network.json["network"]["ssid"], "TestNet");
        assert_eq!(network.json["network"]["security_type"], "WPA3 Personal");
        assert_eq!(network.json["network"]["private_mac_mode"], 2);
        assert_eq!(
            network.json["timestamps"]["added"]["rfc3339"],
            "2024-07-20T12:00:00+00:00"
        );
        Ok(())
    }

    #[test]
    fn parses_dhcp_lease_and_derives_expiration() -> Result<()> {
        let objects = run(r#"<?xml version="1.0" encoding="UTF-8"?>
            <plist version="1.0"><dict>
              <key>InterfaceName</key><string>en0</string>
              <key>IPAddress</key><string>192.168.1.42</string>
              <key>RouterIPAddress</key><string>192.168.1.1</string>
              <key>RouterHardwareAddress</key><data>qrvM3e7/</data>
              <key>LeaseStartDate</key><date>2024-07-21T06:13:20Z</date>
              <key>LeaseLength</key><integer>3600</integer>
              <key>Packet</key><data>AQIDBA==</data>
            </dict></plist>"#)?;
        assert_eq!(objects.len(), 1);
        let lease = &objects[0];
        assert_eq!(lease.kind, "macos.network.dhcp_lease");
        assert_eq!(lease.json["lease"]["ip_address"], "192.168.1.42");
        assert_eq!(
            lease.json["lease"]["router_hardware_address"],
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(lease.json["lease"]["packet_length"], 4);
        assert_eq!(
            lease.json["timestamps"]["lease_expiration"]["rfc3339"],
            "2024-07-21T07:13:20+00:00"
        );
        let events = MacosNetworkParser.extract_timeline_events(lease);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor.as_deref(), Some("en0"));
        Ok(())
    }

    #[test]
    fn infers_dhcp_interface_from_source_filename() {
        assert_eq!(
            super::dhcp_interface_from_path("/volume_0/private/var/db/dhcpclient/leases/en7.plist")
                .as_deref(),
            Some("en7")
        );
        assert!(super::dhcp_interface_from_path("<stream>").is_none());
    }
}
