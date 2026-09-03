//! Installer package receipt plist parser.

use super::common::{
    logical_path, parse_plist, plist_date_to_json, sorted_keys, string, timestamp_unix_ms,
    user_from_path,
};
use crate::core::{ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::parsers::macos::common::input::FileEvidence;
use anyhow::{Result, bail};
use serde_json::json;

const PARSER_NAME: &str = "macos_package_receipt";
const SCHEMA_VARIANT: &str = "macos_installer_package_receipt_plist_v1";

#[derive(Default)]
pub struct MacosPackageReceiptParser;

impl Parser for MacosPackageReceiptParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse macOS Installer package receipt plists (identifier, version, prefix, process and InstallDate)."
    }

    fn requires_source_metadata(&self) -> bool {
        true
    }

    fn extract_timeline_events(&self, object: &ObjectParsed) -> Vec<TimelineEvent> {
        if object.kind != "macos.application.package_receipt" {
            return Vec::new();
        }
        let Some(ts_unix_ms) = timestamp_unix_ms(&object.json["timestamps"]["installed"]) else {
            return Vec::new();
        };
        let description = object.json["package"]["identifier"]
            .as_str()
            .map(|identifier| {
                object.json["package"]["version"]
                    .as_str()
                    .filter(|version| !version.is_empty())
                    .map_or_else(
                        || format!("Package receipt installed {identifier}"),
                        |version| format!("Package receipt installed {identifier} {version}"),
                    )
            });
        vec![TimelineEvent {
            ts_unix_ms,
            event_type: "macos.package.installed",
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
        let root = parse_plist(&evidence, "Installer package receipt plist")?;
        let Some(dict) = root.as_dictionary() else {
            bail!("not an Installer package receipt (root is not a dictionary)");
        };
        if dict.is_empty() {
            return Ok(());
        }

        let identifier = string(dict, "PackageIdentifier");
        let filename_identifier = receipt_filename_identifier(&evidence.source_label);
        let version = string(dict, "PackageVersion");
        let prefix_raw = string(dict, "InstallPrefixPath");
        let normalized_prefix = prefix_raw.as_deref().map(normalize_install_prefix);
        let install_scope = install_scope(normalized_prefix.as_deref());
        let install_user = normalized_prefix.as_deref().and_then(user_from_path);
        let process = string(dict, "InstallProcessName");
        let installed = plist_date_to_json(dict.get("InstallDate"));

        let mut warnings = Vec::new();
        if identifier.is_none() {
            warnings.push("receipt_missing_package_identifier");
        }
        if installed.is_null() {
            warnings.push("receipt_missing_valid_install_date");
        }
        if identifier.is_some()
            && filename_identifier.is_some()
            && identifier.as_deref() != filename_identifier.as_deref()
        {
            warnings.push("package_identifier_differs_from_receipt_filename");
        }

        let text = identifier
            .clone()
            .or_else(|| filename_identifier.clone())
            .map(|identifier| {
                version
                    .as_deref()
                    .filter(|version| !version.is_empty())
                    .map_or(identifier.clone(), |version| {
                        format!("{identifier} {version}")
                    })
            })
            .unwrap_or_else(|| "macOS package receipt".to_owned());

        let json = json!({
            "platform": "macos",
            "app": "application_inventory",
            "record_type": "package_receipt",
            "source": evidence.source_json("package_receipt", 0, SCHEMA_VARIANT),
            "assertion": {
                "type": "package_receipt_present",
                "state": "installer_receipt_present",
                "confidence": "operating_system_receipt",
                "does_not_assert_current_bundle_presence": true,
            },
            "identity": {
                "package_ids": identifier.clone().into_iter().collect::<Vec<_>>(),
                "source_filename_id": filename_identifier,
            },
            "package": {
                "identifier": identifier,
                "version": version,
                "file_name": string(dict, "PackageFileName"),
            },
            "installation": {
                "prefix_raw": prefix_raw,
                "prefix": normalized_prefix,
                "scope": install_scope,
                "user": install_user,
                "process": process,
            },
            "timestamps": {
                "installed": installed,
            },
            "record": {
                "schema_keys": sorted_keys(dict),
                "bom_parsed": false,
            },
            "warnings": warnings,
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "macos.application.package_receipt",
            text,
            json,
        })
    }
}

fn normalize_install_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    }
}

fn install_scope(prefix: Option<&str>) -> &'static str {
    match prefix {
        Some(value) if value.starts_with("/Users/") => "user",
        Some(_) => "system",
        None => "unknown",
    }
}

fn receipt_filename_identifier(path: &str) -> Option<String> {
    let filename = logical_path(path).rsplit('/').next()?;
    let identifier = filename.strip_suffix(".plist")?;
    (!identifier.is_empty()).then(|| identifier.to_owned())
}

#[cfg(test)]
mod tests {
    use super::MacosPackageReceiptParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use anyhow::Result;

    const RECEIPT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>InstallDate</key><date>2024-07-21T06:24:38Z</date>
  <key>InstallPrefixPath</key><string>Applications</string>
  <key>InstallProcessName</key><string>appstoreagent</string>
  <key>PackageFileName</key><string>net.whatsapp.WhatsApp.pkg</string>
  <key>PackageIdentifier</key><string>net.whatsapp.WhatsApp</string>
  <key>PackageVersion</key><string>24.14.85</string>
</dict></plist>"#;

    #[test]
    fn parses_package_receipt_and_install_event() -> Result<()> {
        let parser = MacosPackageReceiptParser;
        let mut objects = Vec::new();
        parser.run_into(
            ParserInput::Bytes(RECEIPT.as_bytes().to_vec()),
            &mut |object| {
                objects.push(object);
                Ok(())
            },
        )?;

        assert_eq!(objects.len(), 1);
        let receipt = &objects[0];
        assert_eq!(receipt.kind, "macos.application.package_receipt");
        assert_eq!(
            receipt.json["package"]["identifier"],
            "net.whatsapp.WhatsApp"
        );
        assert_eq!(receipt.json["package"]["version"], "24.14.85");
        assert_eq!(receipt.json["installation"]["prefix"], "/Applications");
        assert_eq!(receipt.json["installation"]["scope"], "system");
        assert_eq!(receipt.json["record"]["bom_parsed"], false);

        let timeline = parser.extract_timeline_events(receipt);
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].ts_unix_ms, 1_721_543_078_000);
        assert_eq!(timeline[0].event_type, "macos.package.installed");
        assert_eq!(timeline[0].actor.as_deref(), Some("appstoreagent"));
        Ok(())
    }

    #[test]
    fn receipt_without_date_is_preserved_but_not_timelined() -> Result<()> {
        let parser = MacosPackageReceiptParser;
        let bytes = b"<plist version=\"1.0\"><dict><key>PackageIdentifier</key><string>com.example.pkg</string></dict></plist>";
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Bytes(bytes.to_vec()), &mut |object| {
            objects.push(object);
            Ok(())
        })?;
        assert_eq!(objects.len(), 1);
        assert!(objects[0].json["timestamps"]["installed"].is_null());
        assert!(parser.extract_timeline_events(&objects[0]).is_empty());
        Ok(())
    }
}
