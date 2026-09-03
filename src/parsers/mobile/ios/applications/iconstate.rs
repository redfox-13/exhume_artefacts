use super::HOME_SCREEN_ITEM_KIND;
use super::support::{PrimaryEvidence, parse_plist, plist_to_json};
use crate::core::{ObjectParsed, Parser, ParserInput};
use anyhow::{Result, bail};
use plist::Value as Plist;
use serde_json::{Value, json};

const PARSER_NAME: &str = "mobile_ios_iconstate";
const SCHEMA_VARIANT: &str = "ios_springboard_icon_state_v1";

#[derive(Default)]
pub struct IosIconStateParser;

impl Parser for IosIconStateParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse iOS SpringBoard IconState.plist home-screen, dock, folder, and widget placement observations."
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
            bail!("not an iOS IconState plist: root is not a dictionary");
        };
        if !["buttonBar", "iconLists", "today"]
            .iter()
            .any(|key| dict.contains_key(*key))
        {
            bail!("not an iOS IconState plist: no recognised placement surfaces");
        }

        let mut records = Vec::new();
        if let Some(items) = dict.get("buttonBar").and_then(Plist::as_array) {
            walk_items(items, &PlacementContext::new("dock", None), &mut records);
        }
        if let Some(pages) = dict.get("iconLists").and_then(Plist::as_array) {
            walk_pages(
                pages,
                "home_screen",
                &PlacementContext::default(),
                &mut records,
            );
        }
        if let Some(items) = dict.get("today").and_then(Plist::as_array) {
            walk_items(items, &PlacementContext::new("today", None), &mut records);
        }

        for (index, record) in records.into_iter().enumerate() {
            let index = i64::try_from(index).unwrap_or(i64::MAX);
            let text = record
                .bundle_id
                .clone()
                .or_else(|| record.display_name.clone())
                .or_else(|| record.unique_identifier.clone())
                .unwrap_or_else(|| record.item_type.clone());
            let observation_key = format!("ios-iconstate:{}:{index}", evidence.source_label);
            let json = json!({
                "schema": "ios.application_home_screen_item.v1",
                "platform": "ios",
                "record_type": "home_screen_item",
                "observation_key": observation_key,
                "presence": {
                    "placed_on_springboard": true,
                    "application_presence_authority": false,
                },
                "identity": {
                    "bundle_id": record.bundle_id,
                    "component_bundle_id": record.component_bundle_id,
                    "unique_identifier": record.unique_identifier,
                },
                "item": {
                    "type": record.item_type,
                    "display_name": record.display_name,
                    "widget_identifier": record.widget_identifier,
                    "parent_identifier": record.parent_identifier,
                },
                "placement": {
                    "surface": record.context.surface,
                    "page_index": record.context.page_index,
                    "position_path": record.context.position_path,
                    "folder_path": record.context.folder_path,
                },
                "timestamps": {},
                "source": evidence.source_json("placement", index, SCHEMA_VARIANT),
                "raw": plist_to_json(&record.raw),
            });
            sink(ObjectParsed {
                parser: PARSER_NAME,
                kind: HOME_SCREEN_ITEM_KIND,
                text,
                json,
            })?;
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
struct PlacementContext {
    surface: String,
    page_index: Option<u64>,
    position_path: Vec<u64>,
    folder_path: Vec<Value>,
}

impl PlacementContext {
    fn new(surface: &str, page_index: Option<usize>) -> Self {
        Self {
            surface: surface.to_string(),
            page_index: page_index.and_then(|value| u64::try_from(value).ok()),
            ..Self::default()
        }
    }

    fn at_position(&self, position: usize) -> Self {
        let mut next = self.clone();
        next.position_path
            .push(u64::try_from(position).unwrap_or(u64::MAX));
        next
    }
}

struct PlacementRecord {
    context: PlacementContext,
    item_type: String,
    bundle_id: Option<String>,
    component_bundle_id: Option<String>,
    display_name: Option<String>,
    unique_identifier: Option<String>,
    widget_identifier: Option<String>,
    parent_identifier: Option<String>,
    raw: Plist,
}

fn walk_pages(
    pages: &[Plist],
    surface: &str,
    inherited: &PlacementContext,
    output: &mut Vec<PlacementRecord>,
) {
    for (page_index, page) in pages.iter().enumerate() {
        let Some(items) = page.as_array() else {
            continue;
        };
        let mut context = inherited.clone();
        context.surface = surface.to_string();
        context.page_index = u64::try_from(page_index).ok();
        walk_items(items, &context, output);
    }
}

fn walk_items(items: &[Plist], context: &PlacementContext, output: &mut Vec<PlacementRecord>) {
    for (position, item) in items.iter().enumerate() {
        walk_item(item, &context.at_position(position), None, output);
    }
}

fn walk_item(
    item: &Plist,
    context: &PlacementContext,
    inherited_parent: Option<String>,
    output: &mut Vec<PlacementRecord>,
) {
    if let Some(bundle_id) = item.as_string() {
        output.push(PlacementRecord {
            context: context.clone(),
            item_type: "application".to_string(),
            bundle_id: Some(bundle_id.to_string()),
            component_bundle_id: None,
            display_name: None,
            unique_identifier: None,
            widget_identifier: None,
            parent_identifier: inherited_parent,
            raw: item.clone(),
        });
        return;
    }

    let Some(dict) = item.as_dictionary() else {
        return;
    };
    let unique_identifier =
        dict_string(dict, "uniqueIdentifier").or_else(|| dict_string(dict, "displayIdentifier"));
    let display_name =
        dict_string(dict, "displayName").or_else(|| dict_string(dict, "defaultDisplayName"));
    let is_folder = dict
        .get("listType")
        .and_then(Plist::as_string)
        .is_some_and(|value| value == "folder");

    if is_folder {
        output.push(PlacementRecord {
            context: context.clone(),
            item_type: "folder".to_string(),
            bundle_id: None,
            component_bundle_id: None,
            display_name: display_name.clone(),
            unique_identifier: unique_identifier.clone(),
            widget_identifier: None,
            parent_identifier: inherited_parent.clone(),
            raw: item.clone(),
        });
        if let Some(pages) = dict.get("iconLists").and_then(Plist::as_array) {
            let mut nested = context.clone();
            nested.folder_path.push(json!({
                "identifier": unique_identifier,
                "display_name": display_name,
            }));
            nested.position_path.clear();
            walk_pages(pages, &context.surface, &nested, output);
        }
        return;
    }

    let element_type = dict_string(dict, "elementType");
    let container_bundle_id = dict_string(dict, "containerBundleIdentifier");
    let component_bundle_id = dict_string(dict, "bundleIdentifier");
    let bundle_id = container_bundle_id
        .clone()
        .or_else(|| component_bundle_id.clone());
    let widget_identifier = dict_string(dict, "widgetIdentifier");
    let item_type = element_type.clone().unwrap_or_else(|| {
        if dict.contains_key("elements") {
            "widget_stack".to_string()
        } else if widget_identifier.is_some() {
            "widget".to_string()
        } else if bundle_id.is_some() {
            "application".to_string()
        } else {
            "unknown".to_string()
        }
    });

    output.push(PlacementRecord {
        context: context.clone(),
        item_type,
        bundle_id,
        component_bundle_id,
        display_name,
        unique_identifier: unique_identifier.clone(),
        widget_identifier,
        parent_identifier: inherited_parent,
        raw: item.clone(),
    });

    if let Some(elements) = dict.get("elements").and_then(Plist::as_array) {
        for (index, element) in elements.iter().enumerate() {
            walk_item(
                element,
                &context.at_position(index),
                unique_identifier.clone(),
                output,
            );
        }
    }
}

fn dict_string(dict: &plist::Dictionary, key: &str) -> Option<String> {
    dict.get(key)
        .and_then(Plist::as_string)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::IosIconStateParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use anyhow::Result;

    #[test]
    fn parses_apps_folders_and_widgets_without_claiming_installation() -> Result<()> {
        let bytes = br#"<?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
          <key>buttonBar</key><array><string>com.apple.MobileSMS</string></array>
          <key>iconLists</key><array><array>
            <dict>
              <key>listType</key><string>folder</string>
              <key>displayName</key><string>Evidence</string>
              <key>uniqueIdentifier</key><string>FOLDER-1</string>
              <key>iconLists</key><array><array><string>net.example.Forensic</string></array></array>
            </dict>
            <dict>
              <key>iconType</key><string>custom</string>
              <key>displayIdentifier</key><string>STACK-1</string>
              <key>elements</key><array><dict>
                <key>elementType</key><string>widget</string>
                <key>bundleIdentifier</key><string>net.example.Forensic.Widget</string>
                <key>containerBundleIdentifier</key><string>net.example.Forensic</string>
                <key>widgetIdentifier</key><string>ForensicWidget</string>
              </dict></array>
            </dict>
          </array></array>
        </dict></plist>"#;
        let mut objects = Vec::new();
        IosIconStateParser.run_into(ParserInput::Bytes(bytes.to_vec()), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 5);
        assert!(
            objects.iter().all(|object| {
                object.json["presence"]["application_presence_authority"] == false
            })
        );
        let widget = objects
            .iter()
            .find(|object| object.json["item"]["type"] == "widget")
            .expect("widget observation");
        assert_eq!(widget.json["identity"]["bundle_id"], "net.example.Forensic");
        assert_eq!(
            widget.json["identity"]["component_bundle_id"],
            "net.example.Forensic.Widget"
        );
        let nested = objects
            .iter()
            .find(|object| {
                object.text == "net.example.Forensic"
                    && object.json["item"]["type"] == "application"
            })
            .expect("folder application");
        assert_eq!(
            nested.json["placement"]["folder_path"][0]["identifier"],
            "FOLDER-1"
        );
        Ok(())
    }
}
