use serde_json::{json, Map, Value};

use super::super::{TrieNode as T, hive_kind_prefix, Artefact, Outcome, parse_values};

const KIND: &str = hive_kind_prefix!("persistence.winlogon");

/// Microsoft\Windows NT\CurrentVersion\Winlogon
/// Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList
pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![
                T::lit("Microsoft").sub(vec![
                    T::lit("Windows NT").sub(vec![
                        T::lit("CurrentVersion").sub(vec![
                            T::lit("Winlogon").combine(KIND, |object, cell| {
                                let values: Map<String, Value> =
                                    parse_values(cell, |value| {
                                        let name = value.get_pretty_name();
                                        let data = super::super::value_text(value);
                                        match name.to_lowercase().as_str() {
                                            "shell" => Some(("shell".into(), json!(data))),
                                            "userinit" => Some(("userinit".into(), json!(data))),
                                            "taskman" => {
                                                Some(("task_manager".into(), json!(data)))
                                            }
                                            "system" => {
                                                Some(("system_process".into(), json!(data)))
                                            }
                                            "appsetup" => Some(("app_setup".into(), json!(data))),
                                            "uihost" => Some(("ui_host".into(), json!(data))),
                                            "vmapplet" => Some(("vm_applet".into(), json!(data))),
                                            "autoadminlogon" => {
                                                Some(("auto_admin_logon".into(), json!(data)))
                                            }
                                            "forceautologon" => {
                                                Some(("force_auto_logon".into(), json!(data)))
                                            }
                                            "defaultusername" => {
                                                Some(("default_username".into(), json!(data)))
                                            }
                                            "defaultdomainname" => {
                                                Some(("default_domain_name".into(), json!(data)))
                                            }
                                            "defaultpassword" => Some((
                                                "default_password_present".into(),
                                                json!(!data.is_empty()),
                                            )),
                                            "autologoncount" => {
                                                Some(("auto_logon_count".into(), json!(data)))
                                            }
                                            "disablecad" => {
                                                Some(("disable_cad".into(), json!(data)))
                                            }
                                            "disablelockworkstation" => {
                                                Some(("disable_lock_workstation".into(), json!(data)))
                                            }
                                            "sfcdisable" => {
                                                Some(("sfc_disable".into(), json!(data)))
                                            }
                                            "winstationsdisabled" => {
                                                Some(("win_stations_disabled".into(), json!(data)))
                                            }
                                            _ => None,
                                        }
                                    });
                                object.text = format!(
                                    "WINLOGON: Shell: {}, Userinit: {}",
                                    values
                                        .get("shell")
                                        .and_then(Value::as_str)
                                        .unwrap_or("Unknown"),
                                    values
                                        .get("userinit")
                                        .and_then(Value::as_str)
                                        .unwrap_or("Unknown"),
                                );
                                object.data = values;
                                Outcome::Keep
                            }).sub(vec![
                                T::lit("SpecialAccounts").sub(vec![
                                    T::lit("UserList").combine(KIND, |object, cell| {
                                        let accounts: Vec<Value> =
                                            parse_values(cell, |value| {
                                                Some(json!({
                                                    "user": value.get_pretty_name(),
                                                    "hidden_from_logon": value
                                                        .get_content().0
                                                        .to_string() == "0",
                                                }))
                                            });
                                        object.text = format!(
                                            "WINLOGON SPECIAL ACCOUNTS: {} entries",
                                            accounts.len()
                                        );
                                        object.data.insert("accounts".into(), json!(accounts));
                                        Outcome::Keep
                                    }),
                                ]),
                            ]),
                        ]),
                    ]),
                ]),
            ]
        },
    }
}