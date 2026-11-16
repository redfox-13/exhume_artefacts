use super::APPLICATION_CONTAINER_KIND;
use super::support::{
    PrimaryEvidence, final_component, integer, parent_path, parse_plist, plist_to_json, string,
};
use crate::core::{ObjectParsed, Parser, ParserInput};
use anyhow::{Result, bail};
use plist::Value as Plist;
use serde_json::{Value, json};

const PARSER_NAME: &str = "mobile_ios_app_container";
const SCHEMA_VARIANT: &str = "ios_mcm_container_metadata_v1";

#[derive(Default)]
pub struct IosAppContainerParser;

impl Parser for IosAppContainerParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse iOS MobileContainerManager metadata as application-container observations."
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
            bail!("not MobileContainerManager metadata: plist root is not a dictionary");
        };
        let Some(identifier) = string(dict, "MCMMetadataIdentifier") else {
            bail!("not MobileContainerManager metadata: missing MCMMetadataIdentifier");
        };

        let container_path = parent_path(&evidence.source_label).map(str::to_owned);
        let path_uuid = container_path.as_deref().and_then(final_component);
        let role = classify_container_path(&evidence.source_label);
        let info = dict.get("MCMMetadataInfo").and_then(Plist::as_dictionary);
        let user_identity = dict
            .get("MCMMetadataUserIdentity")
            .map(plist_to_json)
            .unwrap_or(Value::Null);
        let metadata_uuid = string(dict, "MCMMetadataUUID");
        let observation_key = format!(
            "ios-app-container:{role}:{identifier}:{}",
            container_path.as_deref().unwrap_or("<unknown>")
        );

        let json = json!({
            "schema": "ios.application_container.v1",
            "platform": "ios",
            "record_type": "application_container",
            "observation_key": observation_key,
            "presence": {
                "present": true,
                "authority": "mobile_container_manager_metadata",
                "application_presence_authority": false,
            },
            "identity": {
                "identifier": identifier,
            },
            "container": {
                "role": role,
                "path": container_path,
                "path_uuid": path_uuid,
                "metadata_uuid": metadata_uuid,
                "metadata_version": integer(dict.get("MCMMetadataVersion")),
                "schema_version": integer(dict.get("MCMMetadataSchemaVersion")),
                "content_class": integer(dict.get("MCMMetadataContentClass")),
                "active_data_protection_class": integer(dict.get("MCMMetadataActiveDPClass")),
                "content_protection_class": info.and_then(|info| integer(info.get("com.apple.MobileInstallation.ContentProtectionClass"))),
                "static_disk_usage_bytes": info.and_then(|info| integer(info.get("StaticDiskUsage"))),
                "user_identity": user_identity,
            },
            "timestamps": {
                "created": Value::Null,
                "modified": Value::Null,
            },
            "source": evidence.source_json("container_metadata", 0, SCHEMA_VARIANT),
            "raw": plist_to_json(&root),
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: APPLICATION_CONTAINER_KIND,
            text: identifier,
            json,
        })
    }
}

fn classify_container_path(path: &str) -> &'static str {
    for (marker, role) in [
        ("/containers/Bundle/Application/", "bundle"),
        ("/Containers/Data/Application/", "data"),
        ("/Containers/Shared/AppGroup/", "app_group"),
        ("/Containers/Data/PluginKitPlugin/", "plugin_data"),
        ("/containers/Data/System/", "system_data"),
        ("/containers/Shared/SystemGroup/", "system_group"),
    ] {
        if path.contains(marker) {
            return role;
        }
    }
    "unknown"
}

#[cfg(test)]
mod tests {
    use super::IosAppContainerParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use anyhow::Result;
    use plist::{Dictionary, Value};

    #[test]
    fn parses_sanitized_container_metadata() -> Result<()> {
        let mut info = Dictionary::new();
        info.insert(
            "com.apple.MobileInstallation.ContentProtectionClass".into(),
            Value::Integer(3.into()),
        );
        info.insert("StaticDiskUsage".into(), Value::Integer(2048.into()));
        let mut root = Dictionary::new();
        root.insert(
            "MCMMetadataIdentifier".into(),
            Value::String("net.example.Forensic".into()),
        );
        root.insert(
            "MCMMetadataUUID".into(),
            Value::String("METADATA-UUID".into()),
        );
        root.insert("MCMMetadataVersion".into(), Value::Integer(7.into()));
        root.insert("MCMMetadataSchemaVersion".into(), Value::Integer(1.into()));
        root.insert("MCMMetadataInfo".into(), Value::Dictionary(info));
        let mut bytes = Vec::new();
        plist::to_writer_binary(&mut bytes, &Value::Dictionary(root))?;

        let mut objects = Vec::new();
        IosAppContainerParser.run_into(ParserInput::Bytes(bytes), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].kind, "mobile.application.container");
        assert_eq!(
            objects[0].json["identity"]["identifier"],
            "net.example.Forensic"
        );
        assert_eq!(
            objects[0].json["container"]["metadata_uuid"],
            "METADATA-UUID"
        );
        assert_eq!(
            objects[0].json["container"]["static_disk_usage_bytes"],
            2048
        );
        assert_eq!(
            objects[0].json["presence"]["application_presence_authority"],
            false
        );
        Ok(())
    }
}
