//! Container-manager metadata plist parser.

use super::common::{
    boolean, data_array_summaries, data_summary, logical_path, parse_plist, scope_from_path,
    signed_integer, sorted_keys, string, string_any, string_array, user_from_path,
};
use crate::core::{ObjectParsed, Parser, ParserInput};
use crate::parsers::macos::common::input::FileEvidence;
use anyhow::{Result, bail};
use plist::{Dictionary, Value as Plist};
use serde_json::json;

const PARSER_NAME: &str = "macos_container_registration";
const SCHEMA_VARIANT: &str = "macos_containermanagerd_metadata_plist_v1";
const METADATA_FILENAME: &str = "/.com.apple.containermanagerd.metadata.plist";

#[derive(Default)]
pub struct MacosContainerRegistrationParser;

impl Parser for MacosContainerRegistrationParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse macOS containermanagerd metadata linking application, group and daemon containers to bundle identities and users."
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
        let root = parse_plist(&evidence, "containermanagerd metadata plist")?;
        let Some(dict) = root.as_dictionary() else {
            bail!("not containermanagerd metadata (root is not a dictionary)");
        };
        if dict.is_empty() {
            return Ok(());
        }

        let info = dictionary(dict.get("MCMMetadataInfo"));
        let validation =
            info.and_then(|dict| dictionary(dict.get("SandboxProfileDataValidationInfo")));
        let parameters = validation.and_then(|dict| dictionary(dict.get("Parameters")));
        let entitlements = validation.and_then(|dict| dictionary(dict.get("Entitlements")));
        let user_identity = dictionary(dict.get("MCMMetadataUserIdentity"));

        let container_identifier = string(dict, "MCMMetadataIdentifier");
        let bundle_id = parameters.and_then(|dict| string(dict, "application_bundle_id"));
        let application_identifier = entitlements.and_then(|dict| {
            string_any(
                dict,
                &["com.apple.application-identifier", "application-identifier"],
            )
        });
        let team_id =
            entitlements.and_then(|dict| string(dict, "com.apple.developer.team-identifier"));
        let placement = classify_container_path(&evidence.source_label);
        let declared_user = parameters
            .and_then(|dict| string(dict, "_USER"))
            .or_else(|| placement.user.clone());

        let mut warnings = Vec::new();
        if container_identifier.is_none() {
            warnings.push("metadata_missing_container_identifier");
        }
        if placement.container_path.is_none() {
            warnings.push("source_path_is_not_container_metadata_path");
        }
        if placement.kind == "application" && bundle_id.is_none() {
            warnings.push("application_container_missing_declared_bundle_id");
        }

        let text = bundle_id
            .clone()
            .or_else(|| container_identifier.clone())
            .or_else(|| placement.container_path.clone())
            .unwrap_or_else(|| "macOS container registration".to_owned());

        let json = json!({
            "platform": "macos",
            "app": "application_inventory",
            "record_type": "container_registration",
            "source": evidence.source_json("container_metadata", 0, SCHEMA_VARIANT),
            "assertion": {
                "type": "container_registration_present",
                "state": "container_metadata_present",
                "confidence": "container_manager_record",
                "does_not_assert_current_bundle_presence": true,
            },
            "identity": {
                "bundle_id": bundle_id,
                "application_identifier": application_identifier,
                "team_id": team_id,
                "container_identifier": container_identifier,
                "application_groups": entitlements
                    .map(|dict| string_array(dict.get("com.apple.security.application-groups")))
                    .unwrap_or_default(),
                "icloud_containers": entitlements
                    .map(|dict| string_array(dict.get("com.apple.developer.icloud-container-identifiers")))
                    .unwrap_or_default(),
            },
            "placement": {
                "metadata_path": evidence.source_label,
                "container_path": placement.container_path,
                "logical_container_path": placement.logical_container_path,
                "kind": placement.kind,
                "scope": placement.scope,
                "user": declared_user,
                "declared": {
                    "home": parameters.and_then(|dict| string(dict, "_HOME")),
                    "application_bundle": parameters.and_then(|dict| string(dict, "application_bundle")),
                    "application_container": parameters.and_then(|dict| string(dict, "application_container")),
                    "application_container_id": parameters.and_then(|dict| string(dict, "application_container_id")),
                },
            },
            "user_identity": {
                "posix_uid": user_identity.and_then(|dict| signed_integer(dict, "posixUID")),
                "posix_gid": user_identity.and_then(|dict| signed_integer(dict, "posixGID")),
                "persona_id": user_identity.and_then(|dict| string(dict, "personaUniqueString")),
                "type": user_identity.and_then(|dict| signed_integer(dict, "type")),
                "version": user_identity.and_then(|dict| string(dict, "version")),
            },
            "registration": {
                "uuid": string(dict, "MCMMetadataUUID"),
                "metadata_version": signed_integer(dict, "MCMMetadataVersion"),
                "schema_version": signed_integer(dict, "MCMMetadataSchemaVersion"),
                "content_class": signed_integer(dict, "MCMMetadataContentClass"),
                "active_data_protection_class": signed_integer(dict, "MCMMetadataActiveDPClass"),
                "content_protection_class": info.and_then(|dict| signed_integer(dict, "com.apple.MobileInstallation.ContentProtectionClass")),
            },
            "sandbox": {
                "enabled": entitlements.and_then(|dict| boolean(dict, "com.apple.security.app-sandbox")),
                // Opaque identity and compiled sandbox-profile data are not
                // duplicated into artifact JSON. Hash+length retains a stable
                // forensic comparison value while the source file remains
                // available in FileViewer.
                "identity_blobs": data_array_summaries(info.and_then(|dict| dict.get("Identity"))),
                "profile_data": data_summary(info.and_then(|dict| dict.get("SandboxProfileData"))),
                "entitlement_keys": entitlements.map(sorted_keys).unwrap_or_default(),
                "parameter_keys": parameters.map(sorted_keys).unwrap_or_default(),
            },
            "record": {
                "schema_keys": sorted_keys(dict),
            },
            "warnings": warnings,
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "macos.application.container_registration",
            text,
            json,
        })
    }
}

fn dictionary(value: Option<&Plist>) -> Option<&Dictionary> {
    value.and_then(Plist::as_dictionary)
}

#[derive(Debug, PartialEq, Eq)]
struct ContainerPlacement {
    container_path: Option<String>,
    logical_container_path: Option<String>,
    kind: &'static str,
    scope: &'static str,
    user: Option<String>,
}

fn classify_container_path(source_path: &str) -> ContainerPlacement {
    let container_path = source_path
        .strip_suffix(METADATA_FILENAME)
        .map(str::to_owned);
    let logical_container_path = container_path
        .as_deref()
        .map(logical_path)
        .map(str::to_owned);
    let logical = logical_container_path.as_deref().unwrap_or(source_path);
    let kind = if logical.contains("/Library/Group Containers/") {
        "group"
    } else if logical.contains("/Library/Daemon Containers/") {
        "daemon"
    } else if logical.contains("/Library/Containers/") {
        "application"
    } else {
        "unknown"
    };
    ContainerPlacement {
        container_path,
        logical_container_path,
        kind,
        scope: scope_from_path(source_path),
        user: user_from_path(source_path),
    }
}

#[cfg(test)]
mod tests {
    use super::{MacosContainerRegistrationParser, classify_container_path};
    use crate::Parser;
    use crate::core::ParserInput;
    use anyhow::Result;
    use plist::Value as Plist;
    use std::io::Cursor;

    const METADATA: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>MCMMetadataIdentifier</key><string>net.whatsapp.WhatsApp</string>
  <key>MCMMetadataUUID</key><string>989B5D74-CB55-460F-878A-E20184B9B0B0</string>
  <key>MCMMetadataSchemaVersion</key><integer>44</integer>
  <key>MCMMetadataVersion</key><integer>7</integer>
  <key>MCMMetadataUserIdentity</key><dict>
    <key>posixUID</key><integer>501</integer>
    <key>posixGID</key><integer>20</integer>
    <key>personaUniqueString</key><string>PERSONA</string>
  </dict>
  <key>MCMMetadataInfo</key><dict>
    <key>Identity</key><array><data>AQID</data></array>
    <key>SandboxProfileData</key><data>BAUGBw==</data>
    <key>SandboxProfileDataValidationInfo</key><dict>
      <key>Parameters</key><dict>
        <key>_HOME</key><string>/Users/alice</string>
        <key>_USER</key><string>alice</string>
        <key>application_bundle</key><string>/Applications/WhatsApp.app</string>
        <key>application_bundle_id</key><string>net.whatsapp.WhatsApp</string>
        <key>application_container</key><string>/Users/alice/Library/Containers/net.whatsapp.WhatsApp/Data</string>
      </dict>
      <key>Entitlements</key><dict>
        <key>com.apple.application-identifier</key><string>TEAM.net.whatsapp.WhatsApp</string>
        <key>com.apple.developer.team-identifier</key><string>TEAM</string>
        <key>com.apple.security.app-sandbox</key><true/>
        <key>com.apple.security.application-groups</key><array><string>group.net.whatsapp.shared</string></array>
      </dict>
    </dict>
  </dict>
</dict></plist>"#;

    #[test]
    fn parses_binary_container_metadata_without_copying_opaque_blobs() -> Result<()> {
        let root = Plist::from_reader(Cursor::new(METADATA.as_bytes()))?;
        let mut bytes = Vec::new();
        root.to_writer_binary(&mut bytes)?;

        let parser = MacosContainerRegistrationParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Bytes(bytes), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 1);
        let registration = &objects[0];
        assert_eq!(
            registration.kind,
            "macos.application.container_registration"
        );
        assert_eq!(
            registration.json["identity"]["bundle_id"],
            "net.whatsapp.WhatsApp"
        );
        assert_eq!(registration.json["identity"]["team_id"], "TEAM");
        assert_eq!(registration.json["user_identity"]["posix_uid"], 501);
        assert_eq!(registration.json["sandbox"]["enabled"], true);
        assert_eq!(
            registration.json["sandbox"]["identity_blobs"][0]["length"],
            3
        );
        assert_eq!(registration.json["sandbox"]["profile_data"]["length"], 4);
        assert_eq!(
            registration.json["identity"]["application_groups"][0],
            "group.net.whatsapp.shared"
        );
        Ok(())
    }

    #[test]
    fn classifies_application_group_daemon_and_system_containers() {
        let application = classify_container_path(
            "/volume_0/Users/alice/Library/Containers/com.example.App/.com.apple.containermanagerd.metadata.plist",
        );
        assert_eq!(application.kind, "application");
        assert_eq!(application.scope, "user");
        assert_eq!(application.user.as_deref(), Some("alice"));

        let group = classify_container_path(
            "/volume_0/Users/alice/Library/Group Containers/group.example/.com.apple.containermanagerd.metadata.plist",
        );
        assert_eq!(group.kind, "group");

        let daemon = classify_container_path(
            "/volume_0/Users/alice/Library/Daemon Containers/UUID/.com.apple.containermanagerd.metadata.plist",
        );
        assert_eq!(daemon.kind, "daemon");

        let system = classify_container_path(
            "/volume_0/private/var/db/locationd/Library/Containers/com.apple.geod/.com.apple.containermanagerd.metadata.plist",
        );
        assert_eq!(system.kind, "application");
        assert_eq!(system.scope, "system");
    }
}
