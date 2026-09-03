//! Application-bundle `Contents/Info.plist` parser.

use super::common::{
    boolean, logical_path, parse_plist, scope_from_path, sorted_keys, string, string_any,
    string_array, user_from_path,
};
use crate::core::{ObjectParsed, Parser, ParserInput};
use crate::parsers::macos::common::input::FileEvidence;
use anyhow::{Result, bail};
use plist::Value as Plist;
use serde_json::{Value, json};

const PARSER_NAME: &str = "macos_app_bundle";
const SCHEMA_VARIANT: &str = "macos_application_info_plist_v1";

#[derive(Default)]
pub struct MacosAppBundleParser;

impl Parser for MacosAppBundleParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse macOS application-bundle Info.plist manifests as bundle-presence observations."
    }

    fn requires_source_metadata(&self) -> bool {
        true
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = FileEvidence::read_primary(input)?;
        let placement = classify_bundle_path(&evidence.source_label);
        if !evidence.source_label.starts_with('/') || placement.bundle_path.is_none() {
            bail!(
                "not a filesystem-backed macOS application bundle manifest: {}",
                evidence.source_label
            );
        }
        let root = parse_plist(&evidence, "application Info.plist")?;
        let Some(dict) = root.as_dictionary() else {
            bail!("not an application Info.plist (root is not a dictionary)");
        };
        if dict.is_empty() {
            return Ok(());
        }

        let bundle_id = string(dict, "CFBundleIdentifier");
        let display_name = string_any(dict, &["CFBundleDisplayName", "CFBundleName"]);
        let bundle_name = string(dict, "CFBundleName");
        let short_version = string(dict, "CFBundleShortVersionString");
        let build_version = string(dict, "CFBundleVersion");
        let executable = string(dict, "CFBundleExecutable");
        let package_type = string(dict, "CFBundlePackageType");
        let mut warnings = Vec::new();
        if bundle_id.is_none() {
            warnings.push("manifest_missing_bundle_identifier");
        }
        if package_type.as_deref().is_some_and(|value| value != "APPL") {
            warnings.push("bundle_package_type_is_not_APPL");
        }

        let text = display_name
            .clone()
            .or_else(|| bundle_id.clone())
            .or_else(|| placement.bundle_path.clone())
            .unwrap_or_else(|| "macOS application bundle".to_owned());

        let json = json!({
            "platform": "macos",
            "app": "application_inventory",
            "record_type": "bundle",
            "source": evidence.source_json("bundle_info", 0, SCHEMA_VARIANT),
            "assertion": {
                "type": "bundle_present",
                "state": "present",
                "confidence": "direct_filesystem_observation",
            },
            "identity": {
                // Info.plist is application-controlled metadata. A future
                // signature enricher may independently verify these values.
                "bundle_id": bundle_id,
                "identity_status": "manifest_declared_unverified",
            },
            "application": {
                "display_name": display_name,
                "bundle_name": bundle_name,
                "version": {
                    "short": short_version,
                    "build": build_version,
                },
                "executable": executable,
                "package_type": package_type,
                "development_region": string(dict, "CFBundleDevelopmentRegion"),
                "minimum_system_version": string_any(dict, &["LSMinimumSystemVersion", "MinimumSystemVersion"]),
                "category_type": string(dict, "LSApplicationCategoryType"),
                "principal_class": string(dict, "NSPrincipalClass"),
                "copyright": string(dict, "NSHumanReadableCopyright"),
                "background_only": boolean(dict, "LSBackgroundOnly"),
                "ui_element": boolean(dict, "LSUIElement"),
                "supported_platforms": string_array(dict.get("CFBundleSupportedPlatforms")),
                "url_types": url_types(dict.get("CFBundleURLTypes")),
                "document_types": document_types(dict.get("CFBundleDocumentTypes")),
            },
            "placement": {
                "bundle_path": placement.bundle_path,
                "logical_bundle_path": placement.logical_bundle_path,
                "parent_bundle_path": placement.parent_bundle_path,
                "scope": placement.scope,
                "user": placement.user,
                "role": placement.role,
                "subrole": placement.subrole,
                "is_embedded": placement.is_embedded,
            },
            "manifest": {
                "schema_keys": sorted_keys(dict),
                "build": {
                    "platform_name": string(dict, "DTPlatformName"),
                    "platform_version": string(dict, "DTPlatformVersion"),
                    "sdk_name": string(dict, "DTSDKName"),
                    "xcode": string(dict, "DTXcode"),
                    "xcode_build": string(dict, "DTXcodeBuild"),
                },
            },
            "warnings": warnings,
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "macos.application.bundle",
            text,
            json,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct BundlePlacement {
    bundle_path: Option<String>,
    logical_bundle_path: Option<String>,
    parent_bundle_path: Option<String>,
    scope: &'static str,
    user: Option<String>,
    role: &'static str,
    subrole: &'static str,
    is_embedded: bool,
}

fn classify_bundle_path(source_path: &str) -> BundlePlacement {
    const INFO_SUFFIX: &str = "/Contents/Info.plist";
    let bundle_path = source_path.strip_suffix(INFO_SUFFIX).map(str::to_owned);
    let logical_bundle_path = bundle_path.as_deref().map(logical_path).map(str::to_owned);
    let parent_bundle_path = logical_bundle_path
        .as_deref()
        .and_then(parent_application_bundle)
        .map(str::to_owned);
    let is_embedded = parent_bundle_path.is_some();
    let logical = logical_bundle_path.as_deref().unwrap_or(source_path);
    let primary = !is_embedded && is_primary_application_path(logical);

    let role = if is_embedded {
        "embedded"
    } else if primary {
        "primary"
    } else {
        "standalone_copy"
    };
    let subrole = if logical.contains("/Contents/Library/LoginItems/") {
        "login_item"
    } else if is_embedded
        && (logical.contains("/Contents/Frameworks/")
            || logical.contains("/Contents/Helpers/")
            || logical
                .rsplit('/')
                .next()
                .is_some_and(|name| name.to_ascii_lowercase().contains("helper.app")))
    {
        "helper"
    } else if logical.contains("/Downloads/") {
        "installer"
    } else if logical.contains("/Application Support/") {
        "managed_or_cached_copy"
    } else if logical.starts_with("/System/") || logical.starts_with("/Library/Apple/System/") {
        "system_component"
    } else {
        "application"
    };

    BundlePlacement {
        bundle_path,
        logical_bundle_path,
        parent_bundle_path,
        scope: scope_from_path(source_path),
        user: user_from_path(source_path),
        role,
        subrole,
        is_embedded,
    }
}

fn parent_application_bundle(bundle_path: &str) -> Option<&str> {
    let without_final_suffix = bundle_path.strip_suffix(".app")?;
    let position = without_final_suffix.rfind(".app/")?;
    Some(&bundle_path[..position + ".app".len()])
}

fn is_primary_application_path(bundle_path: &str) -> bool {
    bundle_path.starts_with("/Applications/")
        || bundle_path.starts_with("/System/Applications/")
        || bundle_path.starts_with("/System/Library/CoreServices/")
        || bundle_path.starts_with("/Library/Apple/System/Library/CoreServices/")
        || user_applications_remainder(bundle_path).is_some()
}

fn user_applications_remainder(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/Users/")?;
    let (_, rest) = rest.split_once('/')?;
    rest.strip_prefix("Applications/")
}

fn url_types(value: Option<&Plist>) -> Value {
    let Some(items) = value.and_then(Plist::as_array) else {
        return Value::Array(Vec::new());
    };
    Value::Array(
        items
            .iter()
            .filter_map(Plist::as_dictionary)
            .map(|item| {
                json!({
                    "name": string(item, "CFBundleURLName"),
                    "role": string(item, "CFBundleTypeRole"),
                    "schemes": string_array(item.get("CFBundleURLSchemes")),
                })
            })
            .collect(),
    )
}

fn document_types(value: Option<&Plist>) -> Value {
    let Some(items) = value.and_then(Plist::as_array) else {
        return Value::Array(Vec::new());
    };
    Value::Array(
        items
            .iter()
            .filter_map(Plist::as_dictionary)
            .map(|item| {
                json!({
                    "name": string(item, "CFBundleTypeName"),
                    "role": string(item, "CFBundleTypeRole"),
                    "extensions": string_array(item.get("CFBundleTypeExtensions")),
                    "content_types": string_array(item.get("LSItemContentTypes")),
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::{MacosAppBundleParser, classify_bundle_path};
    use crate::Parser;
    use crate::core::{CompoundParserInput, ParserFileProvider, ParserInput, ParserSource};
    use anyhow::Result;
    use std::io::Write;

    const INFO: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.example.Chat</string>
  <key>CFBundleDisplayName</key><string>Example Chat</string>
  <key>CFBundleShortVersionString</key><string>4.2</string>
  <key>CFBundleVersion</key><string>420</string>
  <key>CFBundleExecutable</key><string>ExampleChat</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSUIElement</key><integer>1</integer>
  <key>CFBundleURLTypes</key><array><dict>
    <key>CFBundleURLName</key><string>Example Links</string>
    <key>CFBundleURLSchemes</key><array><string>examplechat</string></array>
  </dict></array>
</dict></plist>"#;

    #[test]
    fn parses_declared_bundle_metadata() -> Result<()> {
        let parser = MacosAppBundleParser;
        let mut objects = Vec::new();
        let input = ParserInput::Compound(CompoundParserInput {
            primary: ParserSource::new(
                "primary",
                "/Applications/Example Chat.app/Contents/Info.plist",
                Some(1),
                Some(2),
                Some(3),
            ),
            companions: Vec::new(),
            provider: Box::new(BytesProvider(INFO.as_bytes().to_vec())),
        });
        parser.run_into(input, &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 1);
        let object = &objects[0];
        assert_eq!(object.kind, "macos.application.bundle");
        assert_eq!(object.json["identity"]["bundle_id"], "com.example.Chat");
        assert_eq!(object.json["application"]["display_name"], "Example Chat");
        assert_eq!(object.json["application"]["version"]["short"], "4.2");
        assert_eq!(object.json["application"]["ui_element"], true);
        assert_eq!(
            object.json["application"]["url_types"][0]["schemes"][0],
            "examplechat"
        );
        assert_eq!(
            object.json["identity"]["identity_status"],
            "manifest_declared_unverified"
        );
        Ok(())
    }

    struct BytesProvider(Vec<u8>);

    impl ParserFileProvider for BytesProvider {
        fn copy_to(&mut self, _source: &ParserSource, writer: &mut dyn Write) -> Result<()> {
            writer.write_all(&self.0)?;
            Ok(())
        }
    }

    #[test]
    fn retains_indexed_source_provenance_and_path_classification() -> Result<()> {
        let path = "/volume_2/Applications/Example Chat.app/Contents/Info.plist";
        let input = ParserInput::Compound(CompoundParserInput {
            primary: ParserSource::new("primary", path, Some(41), Some(52), Some(63)),
            companions: Vec::new(),
            provider: Box::new(BytesProvider(INFO.as_bytes().to_vec())),
        });
        let mut objects = Vec::new();
        MacosAppBundleParser.run_into(input, &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        let object = &objects[0].json;
        assert_eq!(object["source"]["path"], path);
        assert_eq!(object["source"]["files"][0]["artifact_id"], 41);
        assert_eq!(object["source"]["files"][0]["system_file_id"], 52);
        assert_eq!(object["source"]["files"][0]["fs_identifier"], 63);
        assert_eq!(object["placement"]["role"], "primary");
        assert_eq!(
            object["placement"]["logical_bundle_path"],
            "/Applications/Example Chat.app"
        );
        Ok(())
    }

    #[test]
    fn classifies_primary_embedded_and_cached_bundles() {
        let primary = classify_bundle_path("/volume_0/Applications/Chat.app/Contents/Info.plist");
        assert_eq!(primary.role, "primary");
        assert!(!primary.is_embedded);
        assert_eq!(
            primary.logical_bundle_path.as_deref(),
            Some("/Applications/Chat.app")
        );

        let embedded = classify_bundle_path(
            "/volume_0/Applications/Chat.app/Contents/Frameworks/Chat Helper.app/Contents/Info.plist",
        );
        assert_eq!(embedded.role, "embedded");
        assert_eq!(embedded.subrole, "helper");
        assert_eq!(
            embedded.parent_bundle_path.as_deref(),
            Some("/Applications/Chat.app")
        );

        let cached = classify_bundle_path(
            "/volume_0/Users/alice/Library/Application Support/Vendor/Updater.app/Contents/Info.plist",
        );
        assert_eq!(cached.role, "standalone_copy");
        assert_eq!(cached.subrole, "managed_or_cached_copy");
        assert_eq!(cached.user.as_deref(), Some("alice"));
    }

    #[test]
    fn rejects_non_dictionary_root() {
        let parser = MacosAppBundleParser;
        let result = parser.run_into(
            ParserInput::Bytes(b"<plist version=\"1.0\"><array/></plist>".to_vec()),
            &mut |_| Ok(()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_pathless_bytes_as_bundle_presence_evidence() {
        let result = MacosAppBundleParser.run_into(
            ParserInput::Bytes(INFO.as_bytes().to_vec()),
            &mut |_| Ok(()),
        );
        assert!(result.is_err());
    }
}
