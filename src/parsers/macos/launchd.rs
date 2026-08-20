//! macOS launchd job parser for LaunchAgents / LaunchDaemons property lists.
//!
//! These plists are the classic macOS persistence mechanism. We extract the
//! job label, the executed program and arguments, and the launch triggers
//! (RunAtLoad, KeepAlive, StartInterval, StartCalendarInterval, WatchPaths, …),
//! plus the job's domain (user/system/Apple) and type (agent/daemon) inferred
//! from the file path. Emits `macos.persistence.launch_item`.

use crate::core::{ObjectParsed, Parser, ParserInput};
use crate::parsers::macos::common::input::FileEvidence;
use anyhow::{Result, bail};
use plist::Value as Plist;
use serde_json::{Map, Value, json};
use std::io::Cursor;

const PARSER_NAME: &str = "macos_launchd";
const SCHEMA_VARIANT: &str = "macos_launchd_plist_v1";

#[derive(Default)]
pub struct MacosLaunchdParser;

impl Parser for MacosLaunchdParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse macOS launchd LaunchAgents/LaunchDaemons plists (persistence: program, arguments and launch triggers)."
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
        if !evidence.bytes.is_empty() && evidence.bytes.iter().all(|byte| *byte == 0) {
            bail!("launchd plist content is all zeroes (filesystem data unavailable)");
        }
        let root = Plist::from_reader(Cursor::new(&evidence.bytes))
            .map_err(|e| anyhow::anyhow!("not a valid launchd plist: {e}"))?;
        let Some(dict) = root.as_dictionary() else {
            bail!("not a launchd plist (root is not a dictionary)");
        };

        // A launchd job is identified by a Label; without one this is some other
        // plist that happened to match the path.
        let Some(label) = dict
            .get("Label")
            .and_then(Plist::as_string)
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .map(str::to_owned)
        else {
            // Some updater-created LaunchAgent placeholders are valid but empty
            // plist dictionaries. They carry no launch job and should not emit
            // an object or turn the entire extraction pass into an error.
            return Ok(());
        };

        let program = dict
            .get("Program")
            .and_then(Plist::as_string)
            .map(str::to_owned);
        let arguments: Vec<String> = dict
            .get("ProgramArguments")
            .and_then(Plist::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_string().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let executable = program.clone().or_else(|| arguments.first().cloned());

        let (job_type, domain) = classify(&evidence.source_label);
        let text = label.clone();

        let json = json!({
            "platform": "macos",
            "app": "launchd",
            "record_type": "launch_item",
            "job_type": job_type,
            "domain": domain,
            "source": evidence.source_json("job", 0, SCHEMA_VARIANT),
            "job": {
                "label": label,
                "program": program,
                "program_arguments": arguments,
                "executable": executable,
                "disabled": dict.get("Disabled").and_then(Plist::as_boolean),
                "username": dict.get("UserName").and_then(Plist::as_string),
                "groupname": dict.get("GroupName").and_then(Plist::as_string),
                "working_directory": dict.get("WorkingDirectory").and_then(Plist::as_string),
                "root_directory": dict.get("RootDirectory").and_then(Plist::as_string),
                "standard_out_path": dict.get("StandardOutPath").and_then(Plist::as_string),
                "standard_error_path": dict.get("StandardErrorPath").and_then(Plist::as_string),
                "process_type": dict.get("ProcessType").and_then(Plist::as_string),
                "limit_load_to_session_type": plist_to_json(dict.get("LimitLoadToSessionType")),
                "environment_variables": plist_to_json(dict.get("EnvironmentVariables")),
                "mach_services": plist_to_json(dict.get("MachServices")),
                "sockets": plist_to_json(dict.get("Sockets")),
            },
            "triggers": {
                "run_at_load": dict.get("RunAtLoad").and_then(Plist::as_boolean),
                "keep_alive": plist_to_json(dict.get("KeepAlive")),
                "start_interval_seconds": dict.get("StartInterval").and_then(Plist::as_signed_integer),
                "start_calendar_interval": plist_to_json(dict.get("StartCalendarInterval")),
                "start_on_mount": dict.get("StartOnMount").and_then(Plist::as_boolean),
                "watch_paths": string_array(dict.get("WatchPaths")),
                "queue_directories": string_array(dict.get("QueueDirectories")),
                "on_demand": dict.get("OnDemand").and_then(Plist::as_boolean),
                "launch_only_once": dict.get("LaunchOnlyOnce").and_then(Plist::as_boolean),
                "throttle_interval_seconds": dict.get("ThrottleInterval").and_then(Plist::as_signed_integer),
            },
        });

        sink(ObjectParsed {
            parser: PARSER_NAME,
            kind: "macos.persistence.launch_item",
            text,
            json,
        })
    }
}

/// Convert a plist value to JSON without dropping nested launch conditions.
fn plist_to_json(value: Option<&Plist>) -> Value {
    match value {
        Some(Plist::Array(values)) => Value::Array(
            values
                .iter()
                .map(|value| plist_to_json(Some(value)))
                .collect(),
        ),
        Some(Plist::Dictionary(values)) => {
            let mut object = Map::new();
            for (key, value) in values {
                object.insert(key.clone(), plist_to_json(Some(value)));
            }
            Value::Object(object)
        }
        Some(Plist::Boolean(value)) => Value::Bool(*value),
        Some(Plist::Data(bytes)) => json!({
            "encoding": "hex",
            "data": hex::encode(bytes),
            "length": bytes.len(),
        }),
        Some(Plist::Date(value)) => Value::String(value.to_xml_format()),
        Some(Plist::Real(value)) => json!(*value),
        Some(Plist::Integer(value)) => value
            .as_signed()
            .map(|value| json!(value))
            .or_else(|| value.as_unsigned().map(|value| json!(value)))
            .unwrap_or(Value::Null),
        Some(Plist::String(value)) => Value::String(value.clone()),
        Some(Plist::Uid(value)) => json!(value.get()),
        Some(_) | None => Value::Null,
    }
}

fn string_array(value: Option<&Plist>) -> Value {
    match value.and_then(Plist::as_array) {
        Some(items) => Value::Array(
            items
                .iter()
                .filter_map(|v| v.as_string().map(|s| Value::String(s.to_string())))
                .collect(),
        ),
        None => Value::Null,
    }
}

/// Infer (job_type, domain) from the plist's path.
fn classify(path: &str) -> (&'static str, &'static str) {
    let job_type = if path.contains("/LaunchDaemons/") {
        "daemon"
    } else if path.contains("/LaunchAgents/") {
        "agent"
    } else {
        "unknown"
    };
    let domain = if path.contains("/System/Library/") || path.contains("/Library/Apple/") {
        "apple"
    } else if path.contains("/Users/") {
        "user"
    } else if path.contains("/Library/") {
        "system"
    } else {
        "unknown"
    };
    (job_type, domain)
}

#[cfg(test)]
mod tests {
    use super::{MacosLaunchdParser, classify};
    use crate::Parser;
    use crate::core::ParserInput;
    use anyhow::Result;

    const PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.evil.persist</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/.hidden/agent</string>
        <string>--daemon</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StartInterval</key><integer>300</integer>
    <key>StartCalendarInterval</key>
    <dict><key>Hour</key><integer>4</integer><key>Minute</key><integer>30</integer></dict>
    <key>EnvironmentVariables</key>
    <dict><key>MODE</key><string>hidden</string></dict>
</dict>
</plist>"#;

    #[test]
    fn parses_launch_agent() -> Result<()> {
        let parser = MacosLaunchdParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Bytes(PLIST.as_bytes().to_vec()), &mut |o| {
            objects.push(o);
            Ok(())
        })?;

        assert_eq!(objects.len(), 1);
        let job = &objects[0];
        assert_eq!(job.kind, "macos.persistence.launch_item");
        assert_eq!(job.json["job"]["label"], "com.evil.persist");
        assert_eq!(job.json["job"]["executable"], "/tmp/.hidden/agent");
        assert_eq!(job.json["job"]["program_arguments"][1], "--daemon");
        assert_eq!(job.json["triggers"]["run_at_load"], true);
        assert_eq!(job.json["triggers"]["keep_alive"], true);
        assert_eq!(job.json["triggers"]["start_interval_seconds"], 300);
        assert_eq!(job.json["triggers"]["start_calendar_interval"]["Hour"], 4);
        assert_eq!(
            job.json["triggers"]["start_calendar_interval"]["Minute"],
            30
        );
        assert_eq!(job.json["job"]["environment_variables"]["MODE"], "hidden");
        Ok(())
    }

    #[test]
    fn classifies_source_paths() {
        assert_eq!(
            classify("/volume_0/Users/alice/Library/LaunchAgents/example.plist"),
            ("agent", "user")
        );
        assert_eq!(
            classify("/volume_0/Library/LaunchDaemons/example.plist"),
            ("daemon", "system")
        );
        assert_eq!(
            classify("/volume_0/System/Library/LaunchAgents/example.plist"),
            ("agent", "apple")
        );
        assert_eq!(classify("<stream>"), ("unknown", "unknown"));
    }

    #[test]
    fn skips_plist_without_label() -> Result<()> {
        let parser = MacosLaunchdParser;
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
