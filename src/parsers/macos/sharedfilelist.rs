//! macOS Shared File List (`.sfl` / `.sfl2` / `.sfl3`) recent-items parser.
//!
//! These files under `~/Library/Application Support/com.apple.sharedfilelist/`
//! are `NSKeyedArchiver` binary plists holding a list of items, each with an
//! Apple bookmark blob pointing at the referenced file (recent documents,
//! recent applications, favourite volumes, …). We walk the archiver object
//! graph, decode each bookmark and emit one `macos.recent.item` per entry.

use crate::core::{ObjectParsed, Parser, ParserInput};
use crate::parsers::macos::common::bookmark::decode_bookmark;
use crate::parsers::macos::common::input::FileEvidence;
use anyhow::{Result, bail};
use plist::Value as Plist;
use serde_json::json;
use std::io::Cursor;

const PARSER_NAME: &str = "macos_sharedfilelist";
const SCHEMA_VARIANT: &str = "macos_sharedfilelist_v1";

#[derive(Default)]
pub struct MacosSharedFileListParser;

impl Parser for MacosSharedFileListParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse macOS Shared File List (.sfl/.sfl2/.sfl3) recent-items bookmarks into referenced file paths."
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
        let list_name = list_name_from_label(&evidence.source_label);

        let root = Plist::from_reader(Cursor::new(&evidence.bytes))
            .map_err(|e| anyhow::anyhow!("not a valid plist Shared File List: {e}"))?;
        let objects = archiver_objects(&root)?;

        let mut index = 0i64;
        for object in objects {
            let Some(bookmark_value) = dict_lookup(objects, object, "Bookmark") else {
                continue;
            };
            let Some(bytes) = resolve_data(objects, bookmark_value) else {
                continue;
            };
            let Some(target) = decode_bookmark(bytes) else {
                continue;
            };

            let name =
                dict_lookup(objects, object, "Name").and_then(|v| resolve_string(objects, v));
            let uuid =
                dict_lookup(objects, object, "uuid").and_then(|v| resolve_string(objects, v));
            let text = target
                .path
                .clone()
                .or_else(|| name.clone())
                .or_else(|| target.file_name.clone())
                .unwrap_or_default();

            let json = json!({
                "platform": "macos",
                "app": "sharedfilelist",
                "record_type": "recent_item",
                "list": list_name,
                "source": evidence.source_json("item", index, SCHEMA_VARIANT),
                "item": {
                    "name": name,
                    "uuid": uuid,
                    "path": target.path,
                    "file_name": target.file_name,
                    "components": target.components,
                    "volume_name": target.volume_name,
                    "volume_path": target.volume_path,
                    "volume_url": target.volume_url,
                    "cnid_count": target.cnid_count,
                },
            });

            sink(ObjectParsed {
                parser: PARSER_NAME,
                kind: "macos.recent.item",
                text,
                json,
            })?;
            index += 1;
        }

        if index == 0 {
            // A valid plist that carried no bookmark items is not an error, but a
            // plist that is not an NSKeyedArchiver at all should be rejected so
            // the indexer records the mismatch.
            if root
                .as_dictionary()
                .and_then(|d| d.get("$objects"))
                .is_none()
            {
                bail!("not an NSKeyedArchiver Shared File List (missing $objects)");
            }
        }

        Ok(())
    }
}

/// Extract the `$objects` array from an NSKeyedArchiver plist.
fn archiver_objects(root: &Plist) -> Result<&[Plist]> {
    let objects = root
        .as_dictionary()
        .and_then(|d| d.get("$objects"))
        .and_then(Plist::as_array)
        .ok_or_else(|| {
            anyhow::anyhow!("not an NSKeyedArchiver Shared File List (missing $objects)")
        })?;
    Ok(objects.as_slice())
}

/// Look up a logical key on an archived object, handling both an
/// `NSKeyedArchiver`-encoded `NSDictionary` (parallel `NS.keys` / `NS.objects`
/// UID arrays, as `.sfl3` uses) and a plain plist dictionary. Returns the
/// value (typically a UID reference to resolve further).
fn dict_lookup<'a>(objects: &'a [Plist], object: &'a Plist, key: &str) -> Option<&'a Plist> {
    let dict = object.as_dictionary()?;
    match (
        dict.get("NS.keys").and_then(Plist::as_array),
        dict.get("NS.objects").and_then(Plist::as_array),
    ) {
        (Some(keys), Some(values)) => keys
            .iter()
            .zip(values.iter())
            .find(|(k, _)| resolve_string(objects, k).as_deref() == Some(key))
            .map(|(_, v)| v),
        _ => dict.get(key),
    }
}

/// Resolve a value that may be a UID reference into the object table to raw data.
fn resolve_data<'a>(objects: &'a [Plist], value: &'a Plist) -> Option<&'a [u8]> {
    match value {
        Plist::Data(bytes) => Some(bytes),
        Plist::Uid(uid) => objects.get(uid.get() as usize).and_then(Plist::as_data),
        _ => None,
    }
}

/// Resolve a value that may be a UID reference into the object table to a string.
fn resolve_string(objects: &[Plist], value: &Plist) -> Option<String> {
    match value {
        Plist::String(s) => Some(s.clone()),
        Plist::Uid(uid) => {
            let obj = objects.get(uid.get() as usize)?;
            // NSString archives as a plain string; "$null" (index 0) is not one.
            obj.as_string().filter(|s| *s != "$null").map(str::to_owned)
        }
        _ => None,
    }
}

/// Turn `com.apple.LSSharedFileList.RecentDocuments.sfl3` into `RecentDocuments`.
fn list_name_from_label(label: &str) -> Option<String> {
    let file = label.rsplit(['/', '\\']).next().unwrap_or(label);
    let stem = file
        .strip_suffix(".sfl3")
        .or_else(|| file.strip_suffix(".sfl2"))
        .or_else(|| file.strip_suffix(".sfl"))
        .unwrap_or(file);
    let name = stem
        .strip_prefix("com.apple.LSSharedFileList.")
        .unwrap_or(stem);
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::macos::common::bookmark::tests_support::synthetic_bookmark;
    use plist::{Dictionary, Uid, Value};

    #[test]
    fn parses_synthetic_sfl() -> Result<()> {
        // Build a tiny NSKeyedArchiver: $objects = ["$null", <item dict>, <name>, <bookmark data>]
        let bookmark = synthetic_bookmark();

        let mut item = Dictionary::new();
        item.insert("Name".to_string(), Value::Uid(Uid::new(2)));
        item.insert("Bookmark".to_string(), Value::Uid(Uid::new(3)));

        let objects = vec![
            Value::String("$null".to_string()),
            Value::Dictionary(item),
            Value::String("Report".to_string()),
            Value::Data(bookmark),
        ];

        let mut root = Dictionary::new();
        root.insert(
            "$archiver".to_string(),
            Value::String("NSKeyedArchiver".to_string()),
        );
        root.insert("$objects".to_string(), Value::Array(objects));
        let root = Value::Dictionary(root);

        let mut bytes = Vec::new();
        plist::to_writer_binary(&mut bytes, &root)?;

        let parser = MacosSharedFileListParser;
        let mut collected = Vec::new();
        parser.run_into(ParserInput::Bytes(bytes), &mut |object| {
            collected.push(object);
            Ok(())
        })?;

        assert_eq!(collected.len(), 1);
        let item = &collected[0];
        assert_eq!(item.kind, "macos.recent.item");
        assert_eq!(item.json["item"]["path"], "/Users/alice/Report.pdf");
        assert_eq!(item.json["item"]["name"], "Report");
        assert_eq!(item.json["item"]["file_name"], "Report.pdf");
        Ok(())
    }

    #[test]
    fn extracts_list_name() {
        assert_eq!(
            list_name_from_label("/x/com.apple.LSSharedFileList.RecentDocuments.sfl3"),
            Some("RecentDocuments".to_string())
        );
    }
}
