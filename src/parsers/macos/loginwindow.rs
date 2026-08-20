//! macOS loginwindow preference parser.
//!
//! Covers the related preference files used by recent macOS releases:
//! - `/Library/Preferences/com.apple.loginwindow.plist` (system login policy,
//!   recent/last users, guest and console-account state),
//! - `~/Library/Preferences/com.apple.loginwindow.plist` (per-user logout and
//!   saved-state behaviour),
//! - `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`
//!   (`TALAppsToRelaunchAtLogin`), and
//! - `~/Library/Preferences/loginwindow.plist` (OS/build version stamps).
//!
//! `TALAppsToRelaunchAtLogin` describes transient session restoration, not a
//! durable login item. It is therefore emitted as `macos.session.relaunch_item`.
//! The older `AutoLaunchedApplicationDictionary` preference and login/logout
//! hooks are persistence mechanisms and receive `macos.persistence.*` kinds.

use crate::core::{ObjectParsed, Parser, ParserInput};
use crate::parsers::macos::common::input::FileEvidence;
use anyhow::{Result, bail};
use plist::{Dictionary, Value as Plist};
use serde_json::{Value, json};
use std::io::Cursor;

const PARSER_NAME: &str = "macos_loginwindow";
const SCHEMA_VARIANT: &str = "macos_loginwindow_plist_v1";

#[derive(Default)]
pub struct MacosLoginwindowParser;

impl Parser for MacosLoginwindowParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse macOS system, user and ByHost loginwindow preferences, session-relaunch applications, and login/logout hooks."
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
        let root = Plist::from_reader(Cursor::new(&evidence.bytes))
            .map_err(|err| anyhow::anyhow!("not a valid loginwindow plist: {err}"))?;
        let Some(dict) = root.as_dictionary() else {
            bail!("not a loginwindow plist (root is not a dictionary)");
        };
        if dict.is_empty() {
            return Ok(());
        }

        let scope = infer_scope(&evidence.source_label, dict);
        emit_preferences(&evidence, dict, scope, sink)?;
        emit_application_items(
            &evidence,
            dict,
            scope,
            "TALAppsToRelaunchAtLogin",
            "session_relaunch_item",
            "macos.session.relaunch_item",
            sink,
        )?;
        emit_application_items(
            &evidence,
            dict,
            scope,
            "AutoLaunchedApplicationDictionary",
            "login_item",
            "macos.persistence.login_item",
            sink,
        )?;
        emit_hook(&evidence, dict, scope, "LoginHook", "login", sink)?;
        emit_hook(&evidence, dict, scope, "LogoutHook", "logout", sink)?;

        Ok(())
    }
}

fn emit_preferences(
    evidence: &FileEvidence,
    dict: &Dictionary,
    scope: &'static str,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let last_user_name = string(dict, "lastUserName");
    let recent_users = string_array(dict.get("RecentUsers"));
    let relaunch_count = array_len(dict, "TALAppsToRelaunchAtLogin");
    let legacy_login_item_count = array_len(dict, "AutoLaunchedApplicationDictionary");
    let mut preference_keys = dict.keys().cloned().collect::<Vec<_>>();
    preference_keys.sort();

    let text = last_user_name
        .clone()
        .map(|user| format!("loginwindow {scope} preferences (last user: {user})"))
        .unwrap_or_else(|| format!("loginwindow {scope} preferences"));

    let account_info = dict.get("AccountInfo").and_then(Plist::as_dictionary);
    let first_logins = account_info
        .and_then(|account| account.get("FirstLogins"))
        .and_then(Plist::as_dictionary)
        .map(dictionary_keys);
    let on_console = account_info
        .and_then(|account| account.get("OnConsole"))
        .and_then(Plist::as_dictionary)
        .map(dictionary_keys);

    let json = json!({
        "platform": "macos",
        "app": "loginwindow",
        "record_type": "preferences",
        "scope": scope,
        "source": evidence.source_json("preferences", 0, SCHEMA_VARIANT),
        "session": {
            "last_user_mode": string(dict, "lastUser"),
            "last_user_name": last_user_name,
            "recent_users": recent_users,
            "guest_enabled": boolean(dict, "GuestEnabled"),
            "auto_login_user": string_any(dict, &["autoLoginUser", "AutoLoginUser"]),
            "show_full_name": boolean(dict, "SHOWFULLNAME"),
            "logout_reason": string(dict, "TALLogoutReason"),
            "logout_saves_state": boolean(dict, "TALLogoutSavesState"),
            "mini_buddy_launch": boolean(dict, "MiniBuddyLaunch"),
            "one_time_saved_state_migration_complete": boolean(dict, "oneTimeSSMigrationComplete"),
            "relaunch_item_count": relaunch_count,
        },
        "accounts": {
            "maximum_users": account_info
                .and_then(|account| account.get("MaximumUsers"))
                .and_then(Plist::as_signed_integer),
            "first_login_users": first_logins,
            "on_console_users": on_console,
        },
        "security": {
            "hide_500_users": boolean(dict, "Hide500Users"),
            "hide_local_users": boolean(dict, "HideLocalUsers"),
            "disable_console_access": boolean(dict, "DisableConsoleAccess"),
            "retries_until_hint": signed_integer(dict, "RetriesUntilHint"),
        },
        "version": {
            "system_version": string(dict, "SystemVersionStampAsString"),
            "system_version_number": signed_integer(dict, "SystemVersionStampAsNumber"),
            "build_version": string(dict, "BuildVersionStampAsString"),
            "build_version_number": signed_integer(dict, "BuildVersionStampAsNumber"),
            "optimizer_previous_build": string(dict, "OptimizerPreviousBuild"),
        },
        "persistence": {
            "login_hook": string(dict, "LoginHook"),
            "logout_hook": string(dict, "LogoutHook"),
            "legacy_login_item_count": legacy_login_item_count,
        },
        // Preserve schema drift without serialising opaque plist data. The key
        // list tells an investigator exactly which preferences were present.
        "preference_keys": preference_keys,
    });

    sink(ObjectParsed {
        parser: PARSER_NAME,
        kind: "macos.config.loginwindow",
        text,
        json,
    })
}

#[allow(clippy::too_many_arguments)]
fn emit_application_items(
    evidence: &FileEvidence,
    dict: &Dictionary,
    scope: &'static str,
    source_key: &'static str,
    record_type: &'static str,
    kind: &'static str,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let Some(items) = dict.get(source_key).and_then(Plist::as_array) else {
        return Ok(());
    };

    for (index, item) in items.iter().enumerate() {
        let Some(item) = item.as_dictionary() else {
            continue;
        };
        let path = string_any(item, &["Path", "path"]);
        let bundle_id = string_any(item, &["BundleID", "BundleIdentifier", "bundleIdentifier"]);
        let display_name = string_any(item, &["Name", "DisplayName"]);
        let text = path
            .clone()
            .or_else(|| display_name.clone())
            .or_else(|| bundle_id.clone())
            .unwrap_or_else(|| format!("{record_type} #{index}"));
        let mut keys = item.keys().cloned().collect::<Vec<_>>();
        keys.sort();

        let json = json!({
            "platform": "macos",
            "app": "loginwindow",
            "record_type": record_type,
            "scope": scope,
            "source": evidence.source_json(source_key, index as i64, SCHEMA_VARIANT),
            "item": {
                "path": path,
                "bundle_id": bundle_id,
                "display_name": display_name,
                "hidden": bool_any(item, &["Hide", "Hidden", "hide"]),
                "background_state": signed_integer(item, "BackgroundState"),
                "source_preference": source_key,
                "preference_keys": keys,
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind,
            text,
            json,
        })?;
    }

    Ok(())
}

fn emit_hook(
    evidence: &FileEvidence,
    dict: &Dictionary,
    scope: &'static str,
    key: &'static str,
    phase: &'static str,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let Some(path) = string(dict, key) else {
        return Ok(());
    };
    if path.trim().is_empty() {
        return Ok(());
    }

    let json = json!({
        "platform": "macos",
        "app": "loginwindow",
        "record_type": "login_hook",
        "scope": scope,
        "source": evidence.source_json(key, 0, SCHEMA_VARIANT),
        "hook": {
            "phase": phase,
            "path": path,
            "source_preference": key,
        },
    });
    sink(ObjectParsed {
        parser: PARSER_NAME,
        kind: "macos.persistence.login_hook",
        text: path,
        json,
    })
}

fn infer_scope(path: &str, dict: &Dictionary) -> &'static str {
    if path.contains("/ByHost/") || dict.contains_key("TALAppsToRelaunchAtLogin") {
        "by_host"
    } else if (path.ends_with("/loginwindow.plist")
        && !path.ends_with("/com.apple.loginwindow.plist"))
        || dict.contains_key("BuildVersionStampAsString")
        || dict.contains_key("SystemVersionStampAsString")
    {
        "version_stamp"
    } else if path.contains("/Users/")
        || dict.contains_key("TALLogoutReason")
        || dict.contains_key("MiniBuddyLaunch")
    {
        "user"
    } else if path.contains("/Library/Preferences/")
        || dict.contains_key("AccountInfo")
        || dict.contains_key("GuestEnabled")
        || dict.contains_key("RecentUsers")
    {
        "system"
    } else {
        "unknown"
    }
}

fn string(dict: &Dictionary, key: &str) -> Option<String> {
    dict.get(key).and_then(Plist::as_string).map(str::to_owned)
}

fn string_any(dict: &Dictionary, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| string(dict, key))
}

fn boolean(dict: &Dictionary, key: &str) -> Option<bool> {
    dict.get(key).and_then(Plist::as_boolean)
}

fn bool_any(dict: &Dictionary, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|key| boolean(dict, key))
}

fn signed_integer(dict: &Dictionary, key: &str) -> Option<i64> {
    dict.get(key).and_then(Plist::as_signed_integer)
}

fn string_array(value: Option<&Plist>) -> Value {
    match value.and_then(Plist::as_array) {
        Some(items) => Value::Array(
            items
                .iter()
                .filter_map(|item| item.as_string().map(|s| Value::String(s.to_string())))
                .collect(),
        ),
        None => Value::Null,
    }
}

fn array_len(dict: &Dictionary, key: &str) -> usize {
    dict.get(key)
        .and_then(Plist::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

fn dictionary_keys(dict: &Dictionary) -> Vec<String> {
    let mut keys = dict.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    keys
}

#[cfg(test)]
mod tests {
    use super::MacosLoginwindowParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use anyhow::Result;

    #[test]
    fn parses_system_login_policy() -> Result<()> {
        let plist = br#"<?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
          <key>AccountInfo</key><dict>
            <key>FirstLogins</key><dict><key>alice</key><integer>1</integer></dict>
            <key>MaximumUsers</key><integer>3</integer>
            <key>OnConsole</key><dict><key>alice</key><true/></dict>
          </dict>
          <key>GuestEnabled</key><false/>
          <key>lastUser</key><string>loggedIn</string>
          <key>lastUserName</key><string>alice</string>
          <key>RecentUsers</key><array><string>alice</string><string>bob</string></array>
        </dict></plist>"#;

        let parser = MacosLoginwindowParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Bytes(plist.to_vec()), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 1);
        let object = &objects[0];
        assert_eq!(object.kind, "macos.config.loginwindow");
        assert_eq!(object.json["scope"], "system");
        assert_eq!(object.json["session"]["last_user_name"], "alice");
        assert_eq!(object.json["session"]["recent_users"][1], "bob");
        assert_eq!(object.json["session"]["guest_enabled"], false);
        assert_eq!(object.json["accounts"]["maximum_users"], 3);
        assert_eq!(object.json["accounts"]["on_console_users"][0], "alice");
        Ok(())
    }

    #[test]
    fn distinguishes_session_relaunch_items_from_persistent_login_items() -> Result<()> {
        let plist = br#"<?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
          <key>TALAppsToRelaunchAtLogin</key><array><dict>
            <key>BackgroundState</key><integer>2</integer>
            <key>BundleID</key><string>com.example.editor</string>
            <key>Hide</key><false/>
            <key>Path</key><string>/Applications/Editor.app</string>
          </dict></array>
          <key>AutoLaunchedApplicationDictionary</key><array><dict>
            <key>Hide</key><true/>
            <key>Path</key><string>/Applications/Persist.app</string>
          </dict></array>
        </dict></plist>"#;

        let parser = MacosLoginwindowParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Bytes(plist.to_vec()), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 3);
        assert_eq!(objects[0].json["scope"], "by_host");
        assert_eq!(objects[1].kind, "macos.session.relaunch_item");
        assert_eq!(objects[1].json["item"]["bundle_id"], "com.example.editor");
        assert_eq!(objects[1].json["item"]["background_state"], 2);
        assert_eq!(objects[2].kind, "macos.persistence.login_item");
        assert_eq!(objects[2].json["item"]["hidden"], true);
        Ok(())
    }

    #[test]
    fn emits_login_and_logout_hooks() -> Result<()> {
        let plist = br#"<?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
          <key>LoginHook</key><string>/usr/local/bin/on-login</string>
          <key>LogoutHook</key><string>/usr/local/bin/on-logout</string>
        </dict></plist>"#;

        let parser = MacosLoginwindowParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Bytes(plist.to_vec()), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 3);
        assert_eq!(objects[1].kind, "macos.persistence.login_hook");
        assert_eq!(objects[1].json["hook"]["phase"], "login");
        assert_eq!(objects[2].json["hook"]["path"], "/usr/local/bin/on-logout");
        Ok(())
    }

    #[test]
    fn skips_empty_preferences() -> Result<()> {
        let parser = MacosLoginwindowParser;
        let mut objects = Vec::new();
        parser.run_into(
            ParserInput::Bytes(b"<plist version=\"1.0\"><dict></dict></plist>".to_vec()),
            &mut |object| {
                objects.push(object);
                Ok(())
            },
        )?;
        assert!(objects.is_empty());
        Ok(())
    }
}
