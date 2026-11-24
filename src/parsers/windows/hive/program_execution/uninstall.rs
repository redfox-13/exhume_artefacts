use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("program_execution.uninstall");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let uninstall = || {
                T::lit("Microsoft").sub(vec![T::lit("Windows").sub(vec![
                    T::lit("CurrentVersion").sub(vec![T::lit("Uninstall").sub(vec![
                        T::any().emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = format!("Installed application: {}", cell.key_name);
                            object
                                .data
                                .insert("uninstall_key".into(), json!(cell.key_name));
                            for field in [
                                "DisplayName",
                                "DisplayVersion",
                                "Publisher",
                                "InstallLocation",
                                "UninstallString",
                            ] {
                                let value = values
                                    .iter()
                                    .find(|(name, _)| name.eq_ignore_ascii_case(field))
                                    .map(|(_, value)| value.clone())
                                    .unwrap_or(serde_json::Value::Null);
                                object.data.insert(field.to_ascii_lowercase().into(), value);
                            }
                            object
                                .data
                                .insert("uninstall_values".into(), json!(values));
                            Outcome::Keep
                        }),
                    ])]),
                ])])
            };
            let wow = || T::lit("Wow6432Node").sub(vec![uninstall()]);
            vec![
                uninstall(),
                wow(),
                T::lit("Software").sub(vec![uninstall(), wow()]),
            ]
        },
    }
}
