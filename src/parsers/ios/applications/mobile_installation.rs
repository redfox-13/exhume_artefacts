use super::INSTALL_EVENT_KIND;
use super::support::PrimaryEvidence;
use crate::core::{ObjectParsed, Parser, ParserInput};
use anyhow::Result;
use chrono::NaiveDateTime;
use serde_json::{Value, json};

const PARSER_NAME: &str = "mobile_ios_mobileinstallation_log";
const SCHEMA_VARIANT: &str = "ios_mobileinstallation_log_v1";

#[derive(Default)]
pub struct IosMobileInstallationLogParser;

impl Parser for IosMobileInstallationLogParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse timestamped iOS MobileInstallation install, uninstall, registration, and container events without inventing a timezone."
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
        let content = String::from_utf8_lossy(&evidence.bytes);

        for (index, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim_end_matches('\r');
            let Some(header) = parse_header(line) else {
                continue;
            };
            let Some(event) = parse_event(header.message) else {
                continue;
            };
            let line_number = i64::try_from(index + 1).unwrap_or(i64::MAX);
            let observation_key = format!(
                "ios-mobileinstallation:{}:{line_number}",
                evidence.source_label
            );
            let text = event
                .bundle_id
                .as_deref()
                .map(|bundle_id| format!("{}: {bundle_id}", event.event_type))
                .unwrap_or_else(|| event.event_type.to_string());
            let json = json!({
                "schema": "ios.application_install_event.v1",
                "platform": "ios",
                "record_type": "application_install_event",
                "observation_key": observation_key,
                "event": {
                    "type": event.event_type,
                    "success": event.success,
                    "install_type": event.install_type,
                    "bundle_id": event.bundle_id,
                    "version": event.version,
                    "short_version": event.short_version,
                    "persona": event.persona,
                    "path": event.path,
                    "launchservices_install_type": event.launchservices_install_type,
                },
                "process": {
                    "pid": header.pid,
                    "thread": header.thread,
                    "level": header.level,
                },
                "timestamps": {
                    "event": {
                        "raw": header.raw_timestamp,
                        "local": header.local_timestamp,
                        "unix_ms": Value::Null,
                        "timezone": {
                            "status": "unresolved_device_local",
                            "offset_seconds": Value::Null,
                        },
                    },
                },
                "presence": {
                    "historical_observation": true,
                    "application_presence_authority": false,
                },
                "source": evidence.source_json("line", line_number, SCHEMA_VARIANT),
                "raw": {
                    "line": line,
                    "message": header.message,
                },
            });
            sink(ObjectParsed {
                parser: PARSER_NAME,
                kind: INSTALL_EVENT_KIND,
                text,
                json,
            })?;
        }
        Ok(())
    }
}

struct LogHeader<'a> {
    raw_timestamp: &'a str,
    local_timestamp: String,
    pid: Option<u64>,
    level: Option<&'a str>,
    thread: Option<&'a str>,
    message: &'a str,
}

fn parse_header(line: &str) -> Option<LogHeader<'_>> {
    let marker = line.find(" [")?;
    let raw_timestamp = &line[..marker];
    let timestamp = NaiveDateTime::parse_from_str(raw_timestamp, "%a %b %e %H:%M:%S %Y").ok()?;
    let after_open = &line[marker + 2..];
    let pid_end = after_open.find(']')?;
    let pid = after_open[..pid_end].parse::<u64>().ok();
    let mut rest = after_open[pid_end + 1..].trim_start();

    let level = if let Some(level_rest) = rest.strip_prefix('<') {
        let end = level_rest.find('>')?;
        let level = &level_rest[..end];
        rest = level_rest[end + 1..].trim_start();
        Some(level)
    } else {
        None
    };
    let thread = if let Some(thread_rest) = rest.strip_prefix('(') {
        let end = thread_rest.find(')')?;
        let thread = &thread_rest[..end];
        rest = thread_rest[end + 1..].trim_start();
        Some(thread)
    } else {
        None
    };

    Some(LogHeader {
        raw_timestamp,
        local_timestamp: timestamp.format("%Y-%m-%dT%H:%M:%S").to_string(),
        pid,
        level,
        thread,
        message: rest,
    })
}

#[derive(Default)]
struct InstallEvent {
    event_type: &'static str,
    success: Option<bool>,
    install_type: Option<String>,
    bundle_id: Option<String>,
    version: Option<String>,
    short_version: Option<String>,
    persona: Option<String>,
    path: Option<String>,
    launchservices_install_type: Option<i64>,
}

fn parse_event(message: &str) -> Option<InstallEvent> {
    if let Some(body) = message
        .split_once("Installing <MIInstallableBundle ")
        .map(|(_, body)| body)
    {
        return Some(InstallEvent {
            event_type: "install_started",
            bundle_id: field(body, "ID=", ';'),
            persona: nullable(field(body, "Persona=", ',')),
            version: nullable(field(body, "Version=", ',')),
            short_version: nullable(field_any_end(body, "ShortVersion=", &[',', '>'])),
            ..InstallEvent::default()
        });
    }

    for (needle, event_type, success) in [
        ("Install Successful for (", "install_succeeded", true),
        ("Install Failed for (", "install_failed", false),
    ] {
        if let Some(after) = message.split_once(needle).map(|(_, after)| after) {
            let descriptor = after
                .split_once(')')
                .map(|(value, _)| value)
                .unwrap_or(after);
            let (install_type, bundle_id) = descriptor
                .split_once(':')
                .map(|(kind, id)| (clean(kind), clean(id)))
                .unwrap_or((None, clean(descriptor)));
            return Some(InstallEvent {
                event_type,
                success: Some(success),
                install_type,
                bundle_id,
                ..InstallEvent::default()
            });
        }
    }

    if let Some(after) = message.split_once("Install of \"").map(|(_, after)| after) {
        let (path, remainder) = after.split_once('"')?;
        let install_type = remainder
            .split_once(" type ")
            .and_then(|(_, value)| value.split_once(" (").map(|(kind, _)| kind))
            .and_then(clean);
        let launchservices_install_type = remainder
            .split_once("LSInstallType = ")
            .and_then(|(_, value)| value.split_once([',', ')']).map(|(value, _)| value))
            .and_then(|value| value.trim().parse().ok());
        return Some(InstallEvent {
            event_type: "install_requested",
            install_type,
            path: clean(path),
            launchservices_install_type,
            ..InstallEvent::default()
        });
    }

    if let Some(after) = message
        .split_once("Uninstall requested")
        .map(|(_, after)| after)
    {
        let identity = after
            .split_once("identity [")
            .and_then(|(_, value)| value.split_once(']').map(|(identity, _)| identity));
        let (bundle_id, persona) = identity
            .and_then(|identity| identity.split_once('/'))
            .map(|(bundle, persona)| (clean(bundle), nullable(clean(persona))))
            .unwrap_or((None, None));
        return Some(InstallEvent {
            event_type: "uninstall_requested",
            bundle_id,
            persona,
            ..InstallEvent::default()
        });
    }

    if let Some(after) = message
        .split_once("Uninstalling identifier ")
        .map(|(_, after)| after)
    {
        return Some(InstallEvent {
            event_type: "uninstall_started",
            bundle_id: clean(after.split_whitespace().next().unwrap_or(after)),
            ..InstallEvent::default()
        });
    }

    if let Some(after) = message
        .split_once("Made container live for ")
        .map(|(_, after)| after)
    {
        let (bundle_id, path) = after
            .split_once(" at ")
            .map(|(bundle, path)| (clean(bundle), clean(path)))
            .unwrap_or((clean(after), None));
        return Some(InstallEvent {
            event_type: "bundle_container_activated",
            bundle_id,
            path,
            ..InstallEvent::default()
        });
    }

    if let Some(after) = message
        .split_once("Data container for ")
        .map(|(_, after)| after)
    {
        let (bundle_id, path) = after
            .split_once(" is now at ")
            .map(|(bundle, path)| (clean(bundle), clean(path)))
            .unwrap_or((clean(after), None));
        return Some(InstallEvent {
            event_type: "data_container_changed",
            bundle_id,
            path,
            ..InstallEvent::default()
        });
    }

    for (operation, event_type) in [
        (
            "MILaunchServicesRegisterOperation:",
            "launchservices_registered",
        ),
        (
            "MILaunchServicesUnregisterOperation:",
            "launchservices_unregistered",
        ),
    ] {
        if let Some(after) = message.split_once(operation).map(|(_, after)| after) {
            let bundle_id = after
                .split_whitespace()
                .find_map(|token| token.split_once("/MIInstallationDomain").map(|(id, _)| id))
                .and_then(clean);
            return Some(InstallEvent {
                event_type,
                bundle_id,
                ..InstallEvent::default()
            });
        }
    }

    None
}

fn field(value: &str, prefix: &str, terminator: char) -> Option<String> {
    value
        .split_once(prefix)
        .map(|(_, value)| value)
        .and_then(|value| value.split_once(terminator).map(|(value, _)| value))
        .and_then(clean)
}

fn field_any_end(value: &str, prefix: &str, terminators: &[char]) -> Option<String> {
    let value = value.split_once(prefix).map(|(_, value)| value)?;
    let end = value
        .char_indices()
        .find(|(_, character)| terminators.contains(character))
        .map(|(index, _)| index)
        .unwrap_or(value.len());
    clean(&value[..end])
}

fn clean(value: &str) -> Option<String> {
    let value = value
        .trim()
        .trim_matches(|character| matches!(character, '<' | '>' | '(' | ')' | ';' | ','));
    (!value.is_empty()).then(|| value.to_string())
}

fn nullable(value: Option<String>) -> Option<String> {
    value.filter(|value| value != "(null)" && value != "null")
}

#[cfg(test)]
mod tests {
    use super::IosMobileInstallationLogParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use anyhow::Result;

    #[test]
    fn parses_events_and_keeps_device_local_time_unresolved() -> Result<()> {
        let input = br#"Fri Oct  3 15:29:09 2025 [829] <notice> (0x16d16b000) -[MIInstaller _installInstallable:containingSymlink:error:]: Installing <MIInstallableBundle ID=com.example.video; Persona=PERSONA-1, Version=20.39.6, ShortVersion=20.39.6>
Fri Oct  3 15:29:14 2025 [829] <notice> (0x16d16b000) -[MIInstaller performInstallationWithError:]: Install Successful for (Customer:com.example.video); Overall: 6.48s
Mon Oct 27 08:54:22 2025 [705] <notice> (0x16f3cb000) -[MIClientConnection _uninstallIdentities:withOptions:completion:]: Uninstall requested by app (pid 188) for identity [com.example.social/PERSONA-1] with options: {
Mon Oct 27 08:54:22 2025 [705] <notice> (0x16f3cb000) -[MIUninstaller _uninstallBundleWithIdentity:error:]: Uninstalling identifier com.example.social
"#;
        let parser = IosMobileInstallationLogParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Bytes(input.to_vec()), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 4);
        assert_eq!(objects[0].json["event"]["type"], "install_started");
        assert_eq!(objects[0].json["event"]["version"], "20.39.6");
        assert_eq!(objects[1].json["event"]["type"], "install_succeeded");
        assert_eq!(objects[1].json["event"]["install_type"], "Customer");
        assert_eq!(objects[2].json["event"]["type"], "uninstall_requested");
        assert_eq!(objects[2].json["event"]["persona"], "PERSONA-1");
        assert_eq!(
            objects[0].json["timestamps"]["event"]["local"],
            "2025-10-03T15:29:09"
        );
        assert!(objects[0].json["timestamps"]["event"]["unix_ms"].is_null());
        assert_eq!(
            objects[0].json["timestamps"]["event"]["timezone"]["status"],
            "unresolved_device_local"
        );
        assert!(parser.extract_timeline_events(&objects[0]).is_empty());
        Ok(())
    }

    #[test]
    fn parses_install_request_and_container_activation() -> Result<()> {
        let input = br#"Fri Oct  3 15:28:45 2025 [829] <notice> (0x1) Install of "/staging/Video.app" type Placeholder (LSInstallType = 1, Domain: MIInstallationDomainDefault)
Fri Oct  3 15:29:14 2025 [829] <notice> (0x1) Made container live for com.example.video at /private/var/containers/Bundle/Application/UUID
"#;
        let mut objects = Vec::new();
        IosMobileInstallationLogParser.run_into(
            ParserInput::Bytes(input.to_vec()),
            &mut |object| {
                objects.push(object);
                Ok(())
            },
        )?;
        assert_eq!(objects[0].json["event"]["type"], "install_requested");
        assert_eq!(objects[0].json["event"]["launchservices_install_type"], 1);
        assert_eq!(
            objects[1].json["event"]["type"],
            "bundle_container_activated"
        );
        assert_eq!(objects[1].json["event"]["bundle_id"], "com.example.video");
        Ok(())
    }
}
