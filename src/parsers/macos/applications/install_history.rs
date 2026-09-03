//! `/Library/Receipts/InstallHistory.plist` parser.

use super::common::{parse_plist, scope_from_path};
use super::common::{plist_date_to_json, sorted_keys, string, string_array, timestamp_unix_ms};
use crate::core::{ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::parsers::macos::common::input::FileEvidence;
use anyhow::{Result, bail};
use plist::Dictionary;
use serde_json::json;

const PARSER_NAME: &str = "macos_install_history";
const SCHEMA_VARIANT: &str = "macos_install_history_plist_v1";

#[derive(Default)]
pub struct MacosInstallHistoryParser;

impl Parser for MacosInstallHistoryParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse macOS InstallHistory.plist application, package, configuration-data and operating-system installation events."
    }

    fn requires_source_metadata(&self) -> bool {
        true
    }

    fn extract_timeline_events(&self, object: &ObjectParsed) -> Vec<TimelineEvent> {
        if object.kind != "macos.software.install_event" {
            return Vec::new();
        }
        let Some(ts_unix_ms) = timestamp_unix_ms(&object.json["timestamps"]["recorded"]) else {
            return Vec::new();
        };
        let subject_type = object.json["subject_type"].as_str().unwrap_or("software");
        let event_type = match subject_type {
            "application" => "macos.application.install_recorded",
            "configuration_data" => "macos.system.configuration_installed",
            "system_update" => "macos.system.update_installed",
            _ => "macos.package.install_recorded",
        };
        let description = object.json["installation"]["display_name"]
            .as_str()
            .map(|name| {
                object.json["installation"]["display_version"]
                    .as_str()
                    .filter(|version| !version.is_empty())
                    .map_or_else(
                        || format!("InstallHistory recorded {name}"),
                        |version| format!("InstallHistory recorded {name} {version}"),
                    )
            });
        vec![TimelineEvent {
            ts_unix_ms,
            event_type,
            description,
            actor: object.json["installation"]["process"]
                .as_str()
                .map(str::to_owned),
        }]
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = FileEvidence::read_primary(input)?;
        let root = parse_plist(&evidence, "InstallHistory plist")?;
        let Some(entries) = root.as_array() else {
            bail!("not an InstallHistory plist (root is not an array)");
        };

        for (index, entry) in entries.iter().enumerate() {
            let Some(dict) = entry.as_dictionary() else {
                continue;
            };
            emit_entry(&evidence, dict, index, sink)?;
        }
        Ok(())
    }
}

fn emit_entry(
    evidence: &FileEvidence,
    dict: &Dictionary,
    index: usize,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let display_name = string(dict, "displayName");
    let display_version = string(dict, "displayVersion");
    let process = string(dict, "processName");
    let content_type = string(dict, "contentType");
    let package_ids = string_array(dict.get("packageIdentifiers"));
    let recorded = plist_date_to_json(dict.get("date"));
    let subject_type = classify_subject(
        content_type.as_deref(),
        process.as_deref(),
        display_name.as_deref(),
        &package_ids,
    );
    let install_method = classify_install_method(process.as_deref());

    let mut warnings = Vec::new();
    if recorded.is_null() {
        warnings.push("event_missing_valid_plist_date");
    }
    if display_name.is_none() && package_ids.is_empty() {
        warnings.push("event_missing_display_name_and_package_identifiers");
    }

    let text = display_name
        .clone()
        .map(|name| {
            display_version
                .as_deref()
                .filter(|version| !version.is_empty())
                .map_or(name.clone(), |version| format!("{name} {version}"))
        })
        .or_else(|| package_ids.first().cloned())
        .unwrap_or_else(|| format!("InstallHistory event #{index}"));

    let json = json!({
        "platform": "macos",
        "app": "application_inventory",
        "record_type": "install_event",
        "subject_type": subject_type,
        "source": evidence.source_json("history_entry", index as i64, SCHEMA_VARIANT),
        "assertion": {
            "type": "install_history_event",
            "state": "historical_install_or_update",
            "confidence": "operating_system_record",
            "does_not_assert_current_presence": true,
        },
        "identity": {
            "package_ids": package_ids,
        },
        "installation": {
            "display_name": display_name,
            "display_version": display_version,
            "content_type": content_type,
            "process": process,
            "method": install_method,
            "scope": scope_from_path(&evidence.source_label),
        },
        "timestamps": {
            "recorded": recorded,
        },
        "record": {
            "schema_keys": sorted_keys(dict),
        },
        "warnings": warnings,
    });

    sink(ObjectParsed {
        parser: PARSER_NAME,
        kind: "macos.software.install_event",
        text,
        json,
    })
}

fn classify_subject(
    content_type: Option<&str>,
    process: Option<&str>,
    display_name: Option<&str>,
    package_ids: &[String],
) -> &'static str {
    if content_type.is_some_and(|value| value.eq_ignore_ascii_case("config-data")) {
        "configuration_data"
    } else if process.is_some_and(|value| value.eq_ignore_ascii_case("appstoreagent")) {
        "application"
    } else if process.is_some_and(|value| value.eq_ignore_ascii_case("softwareupdated"))
        || display_name.is_some_and(|value| value.starts_with("macOS "))
    {
        "system_update"
    } else if !package_ids.is_empty() {
        "package"
    } else {
        "software"
    }
}

fn classify_install_method(process: Option<&str>) -> &'static str {
    match process {
        Some(value) if value.eq_ignore_ascii_case("appstoreagent") => "app_store",
        Some(value) if value.eq_ignore_ascii_case("softwareupdated") => "software_update",
        Some(value) if value.eq_ignore_ascii_case("installer") => "installer",
        Some(value) if value.eq_ignore_ascii_case("CoreServicesUIAgent") => "core_services_ui",
        Some(_) => "other_process",
        None => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::MacosInstallHistoryParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use anyhow::Result;

    const HISTORY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><array>
  <dict>
    <key>date</key><date>2024-07-21T06:24:38Z</date>
    <key>displayName</key><string>WhatsApp</string>
    <key>displayVersion</key><string>24.14.85</string>
    <key>packageIdentifiers</key><array><string>net.whatsapp.WhatsApp</string></array>
    <key>processName</key><string>appstoreagent</string>
  </dict>
  <dict>
    <key>date</key><date>2024-07-21T06:43:36Z</date>
    <key>displayName</key><string>macOS 14.5</string>
    <key>displayVersion</key><string>14.5</string>
    <key>processName</key><string>softwareupdated</string>
  </dict>
  <dict>
    <key>contentType</key><string>config-data</string>
    <key>displayName</key><string>XProtectPayloads</string>
    <key>packageIdentifiers</key><array><string>com.apple.pkg.XProtectPayloads</string></array>
  </dict>
</array></plist>"#;

    #[test]
    fn parses_all_history_subjects_without_calling_everything_an_app() -> Result<()> {
        let parser = MacosInstallHistoryParser;
        let mut objects = Vec::new();
        parser.run_into(
            ParserInput::Bytes(HISTORY.as_bytes().to_vec()),
            &mut |object| {
                objects.push(object);
                Ok(())
            },
        )?;

        assert_eq!(objects.len(), 3);
        assert!(
            objects
                .iter()
                .all(|object| object.kind == "macos.software.install_event")
        );
        assert_eq!(objects[0].json["subject_type"], "application");
        assert_eq!(objects[0].json["installation"]["method"], "app_store");
        assert_eq!(
            objects[0].json["identity"]["package_ids"][0],
            "net.whatsapp.WhatsApp"
        );
        assert_eq!(objects[1].json["subject_type"], "system_update");
        assert_eq!(objects[2].json["subject_type"], "configuration_data");

        let timeline = parser.extract_timeline_events(&objects[0]);
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].ts_unix_ms, 1_721_543_078_000);
        assert_eq!(timeline[0].event_type, "macos.application.install_recorded");
        assert_eq!(timeline[0].actor.as_deref(), Some("appstoreagent"));
        assert!(parser.extract_timeline_events(&objects[2]).is_empty());
        Ok(())
    }

    #[test]
    fn rejects_dictionary_root() {
        let parser = MacosInstallHistoryParser;
        let result = parser.run_into(
            ParserInput::Bytes(b"<plist version=\"1.0\"><dict/></plist>".to_vec()),
            &mut |_| Ok(()),
        );
        assert!(result.is_err());
    }
}
