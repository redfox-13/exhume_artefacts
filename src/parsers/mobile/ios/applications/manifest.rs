use super::INSTALLED_APPLICATION_KIND;
use super::support::{
    PrimaryEvidence, optional_plist_to_json, parent_path, parse_plist, plist_to_json, string,
    strings,
};
use crate::core::{ObjectParsed, Parser, ParserInput};
use anyhow::{Result, bail};
use plist::Value as Plist;
use serde_json::{Map, Value, json};

const PARSER_NAME: &str = "mobile_ios_app_manifest";
const SCHEMA_VARIANT: &str = "ios_application_manifest_v1";

#[derive(Default)]
pub struct IosAppManifestParser;

impl Parser for IosAppManifestParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse direct-root iOS application Info.plist manifests as present installed-application observations."
    }

    fn requires_source_metadata(&self) -> bool {
        true
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        let evidence = PrimaryEvidence::read(input)?;
        let root = parse_plist(&evidence.bytes, &evidence.source_label)?;
        let Some(dict) = root.as_dictionary() else {
            bail!("not an iOS application manifest: plist root is not a dictionary");
        };

        let Some(bundle_id) = string(dict, "CFBundleIdentifier") else {
            bail!("not an iOS application manifest: missing CFBundleIdentifier");
        };
        let package_type = string(dict, "CFBundlePackageType");
        if package_type.as_deref().is_some_and(|value| value != "APPL") {
            bail!("not a root iOS application manifest: CFBundlePackageType is not APPL");
        }

        let path_class = classify_manifest_path(&evidence.source_label);
        if !path_class.direct_root {
            bail!(
                "not a direct-root iOS application manifest: {}",
                evidence.source_label
            );
        }

        let display_name = raw_string(dict, "CFBundleDisplayName");
        let bundle_name = raw_string(dict, "CFBundleName");
        let app_path = parent_path(&evidence.source_label).map(str::to_owned);
        let application_identifier = string(dict, "ApplicationIdentifier");
        let team_id = application_identifier
            .as_deref()
            .and_then(|identifier| identifier.strip_suffix(&format!(".{bundle_id}")))
            .map(str::to_owned);
        let app_tags = strings(dict.get("SBAppTags"));
        let hidden_tag = app_tags.iter().any(|tag| tag == "hidden");
        let executable = string(dict, "CFBundleExecutable");
        let privacy_usage_descriptions = privacy_usage_descriptions(dict);
        let text = display_name
            .clone()
            .or_else(|| bundle_name.clone())
            .unwrap_or_else(|| bundle_id.clone());
        let observation_key = format!(
            "ios-app-manifest:{}:{}:{}",
            path_class.domain,
            bundle_id,
            app_path.as_deref().unwrap_or("<unknown>")
        );

        let json = json!({
            "schema": "ios.application.v1",
            "platform": "ios",
            "record_type": "installed_application",
            "observation_key": observation_key,
            "presence": {
                "present": true,
                "authority": "direct_root_bundle_manifest",
            },
            "identity": {
                "bundle_id": bundle_id,
                "application_identifier": application_identifier,
                "team_id": team_id,
            },
            "display": {
                "name": display_name,
                "bundle_name": bundle_name,
            },
            "version": {
                "short": string(dict, "CFBundleShortVersionString"),
                "build": string(dict, "CFBundleVersion"),
            },
            "classification": {
                "installation_domain": path_class.domain,
                "legacy_layout": path_class.legacy,
                "package_type": package_type,
                "sb_app_tags": app_tags,
                "hidden_tag": hidden_tag,
            },
            "paths": {
                "bundle": app_path,
                "executable": executable,
                "bundle_container": path_class.bundle_container_path,
            },
            "platform_requirements": {
                "minimum_os_version": string(dict, "MinimumOSVersion"),
                "sdk_name": string(dict, "DTSDKName"),
                "sdk_build": string(dict, "DTSDKBuild"),
                "platform_name": string(dict, "DTPlatformName"),
                "platform_version": string(dict, "DTPlatformVersion"),
                "device_families": optional_plist_to_json(dict.get("UIDeviceFamily")),
            },
            "capabilities": {
                "background_modes": optional_plist_to_json(dict.get("UIBackgroundModes")),
                "url_types": optional_plist_to_json(dict.get("CFBundleURLTypes")),
                "queried_url_schemes": optional_plist_to_json(dict.get("LSApplicationQueriesSchemes")),
                "uses_non_exempt_encryption": dict.get("ITSAppUsesNonExemptEncryption").and_then(Plist::as_boolean),
                "privacy_usage_descriptions": privacy_usage_descriptions,
            },
            "timestamps": {
                "installed": Value::Null,
            },
            "source": evidence.source_json("bundle_manifest", 0, SCHEMA_VARIANT),
            "raw": plist_to_json(&root),
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: INSTALLED_APPLICATION_KIND,
            text,
            json,
        })
    }
}

fn raw_string(dict: &plist::Dictionary, key: &str) -> Option<String> {
    dict.get(key)
        .and_then(Plist::as_string)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn privacy_usage_descriptions(dict: &plist::Dictionary) -> Value {
    let mut values = Map::new();
    for (key, value) in dict {
        if key.ends_with("UsageDescription") {
            values.insert(key.clone(), plist_to_json(value));
        }
    }
    Value::Object(values)
}

#[derive(Debug, Clone)]
struct ManifestPathClass {
    domain: &'static str,
    direct_root: bool,
    legacy: bool,
    bundle_container_path: Option<String>,
}

fn classify_manifest_path(path: &str) -> ManifestPathClass {
    let Some(absolute) = path.strip_prefix('/') else {
        return rejected_manifest_path();
    };
    let components = absolute.split('/').collect::<Vec<_>>();
    let logical = match components.as_slice() {
        [namespace, rest @ ..] if is_acquisition_namespace(namespace) => rest,
        _ => components.as_slice(),
    };

    let (domain, legacy) = match logical {
        ["Applications", app, "Info.plist"] if is_application_bundle_component(app) => {
            ("system", false)
        }
        [
            "private",
            "var",
            "containers",
            "Bundle",
            "Application",
            uuid,
            app,
            "Info.plist",
        ] if is_uuid_component(uuid) && is_application_bundle_component(app) => {
            ("bundle_container", false)
        }
        [
            "private",
            "var",
            "mobile",
            "Applications",
            uuid,
            app,
            "Info.plist",
        ] if is_uuid_component(uuid) && is_application_bundle_component(app) => {
            ("legacy_user_application", true)
        }
        _ => return rejected_manifest_path(),
    };

    let bundle_container_path = parent_path(path).and_then(parent_path).map(str::to_owned);
    ManifestPathClass {
        domain,
        direct_root: true,
        legacy,
        bundle_container_path,
    }
}

fn rejected_manifest_path() -> ManifestPathClass {
    ManifestPathClass {
        domain: "unknown",
        direct_root: false,
        legacy: false,
        bundle_container_path: None,
    }
}

fn is_acquisition_namespace(component: &str) -> bool {
    ["filesystem", "volume_"].iter().any(|prefix| {
        component.strip_prefix(prefix).is_some_and(|index| {
            !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
        })
    })
}

fn is_application_bundle_component(component: &str) -> bool {
    component
        .strip_suffix(".app")
        .is_some_and(|name| !name.is_empty() && name != "." && name != "..")
}

fn is_uuid_component(component: &str) -> bool {
    let groups = component.split('-').collect::<Vec<_>>();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, length)| {
            group.len() == length && group.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

#[cfg(test)]
mod tests {
    use super::{IosAppManifestParser, classify_manifest_path};
    use crate::Parser;
    use crate::core::{CompoundParserInput, ParserFileProvider, ParserInput, ParserSource};
    use anyhow::Result;
    use std::io::Write;

    struct BytesProvider(Vec<u8>);

    impl ParserFileProvider for BytesProvider {
        fn copy_to(&mut self, _source: &ParserSource, writer: &mut dyn Write) -> Result<()> {
            writer.write_all(&self.0)?;
            Ok(())
        }
    }

    fn manifest() -> Vec<u8> {
        br#"<?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
          <key>CFBundleIdentifier</key><string>net.example.Forensic</string>
          <key>CFBundleDisplayName</key><string>Forensic App</string>
          <key>CFBundleName</key><string>Forensic</string>
          <key>CFBundlePackageType</key><string>APPL</string>
          <key>CFBundleShortVersionString</key><string>2.4.1</string>
          <key>CFBundleVersion</key><string>241</string>
          <key>MinimumOSVersion</key><string>16.0</string>
          <key>SBAppTags</key><array><string>hidden</string></array>
          <key>NSCameraUsageDescription</key><string>Scan evidence labels</string>
        </dict></plist>"#
            .to_vec()
    }

    #[test]
    fn parses_direct_bundle_manifest_with_provenance() -> Result<()> {
        let path = "/filesystem1/private/var/containers/Bundle/Application/AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE/Forensic.app/Info.plist";
        let input = ParserInput::Compound(CompoundParserInput {
            primary: ParserSource::new("primary", path, Some(11), Some(22), Some(33)),
            companions: Vec::new(),
            provider: Box::new(BytesProvider(manifest())),
        });
        let mut objects = Vec::new();
        IosAppManifestParser.run_into(input, &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].kind, "mobile.application.installed");
        assert_eq!(
            objects[0].json["identity"]["bundle_id"],
            "net.example.Forensic"
        );
        assert_eq!(
            objects[0].json["presence"]["authority"],
            "direct_root_bundle_manifest"
        );
        assert_eq!(objects[0].json["classification"]["hidden_tag"], true);
        assert_eq!(objects[0].json["source"]["files"][0]["system_file_id"], 22);
        assert!(objects[0].json["timestamps"]["installed"].is_null());
        Ok(())
    }

    #[test]
    fn rejects_nested_watch_manifest() {
        let path = "/filesystem1/private/var/containers/Bundle/Application/UUID/App.app/Watch/Watch.app/Info.plist";
        assert!(!classify_manifest_path(path).direct_root);
    }

    #[test]
    fn classifies_system_manifest() {
        let path = "/filesystem1/Applications/Camera.app/Info.plist";
        let class = classify_manifest_path(path);
        assert!(class.direct_root);
        assert_eq!(class.domain, "system");
    }

    #[test]
    fn accepts_only_canonical_roots_with_optional_known_namespace() {
        for path in [
            "/Applications/Camera.app/Info.plist",
            "/filesystem1/Applications/Camera.app/Info.plist",
            "/private/var/containers/Bundle/Application/AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE/Forensic.app/Info.plist",
            "/filesystem1/private/var/containers/Bundle/Application/AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE/Forensic.app/Info.plist",
            "/filesystem1/private/var/mobile/Applications/AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE/Legacy.app/Info.plist",
            "/volume_0/Applications/Camera.app/Info.plist",
            "/volume_12/private/var/containers/Bundle/Application/AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE/Forensic.app/Info.plist",
        ] {
            assert!(classify_manifest_path(path).direct_root, "{path}");
        }
    }

    #[test]
    fn rejects_nested_and_arbitrarily_prefixed_application_paths() {
        for path in [
            "/tmp/Applications/Evil.app/Info.plist",
            "/filesystem1/Documents/Applications/Evil.app/Info.plist",
            "/evidence/filesystem1/Applications/Evil.app/Info.plist",
            "/filesystem1/Applications/Host.app/Watch/Watch.app/Info.plist",
            "/filesystem1/private/var/containers/Bundle/Application/AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE/Host.app/PlugIns/Extension.appex/Info.plist",
            "/prefix/private/var/containers/Bundle/Application/AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE/Evil.app/Info.plist",
            "/filesystem1/filesystem2/Applications/Evil.app/Info.plist",
            "/volume_0/filesystem1/Applications/Evil.app/Info.plist",
            "/volume_x/Applications/Evil.app/Info.plist",
        ] {
            assert!(!classify_manifest_path(path).direct_root, "{path}");
        }
    }

    #[test]
    fn parser_rejects_nested_prefix_even_with_a_valid_manifest() {
        let path = "/filesystem1/Documents/Applications/Evil.app/Info.plist";
        let input = ParserInput::Compound(CompoundParserInput {
            primary: ParserSource::new("primary", path, Some(11), Some(22), Some(33)),
            companions: Vec::new(),
            provider: Box::new(BytesProvider(manifest())),
        });

        assert!(
            IosAppManifestParser
                .run_into(input, &mut |_| Ok(()))
                .is_err()
        );
    }

    #[test]
    fn parser_rejects_pathless_bytes_as_presence_evidence() {
        let input = ParserInput::Bytes(manifest());

        assert!(
            IosAppManifestParser
                .run_into(input, &mut |_| Ok(()))
                .is_err()
        );
    }
}
