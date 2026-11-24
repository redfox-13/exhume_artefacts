use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("security.powershell_execution_policy");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let policy = || {
                T::lit("Microsoft").sub(vec![T::lit("PowerShell").sub(vec![
                    T::lit("1").sub(vec![T::lit("ShellIds").sub(vec![
                        T::lit("Microsoft.PowerShell").emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = "PowerShell execution policy".into();
                            object
                                .data
                                .insert("execution_policy_values".into(), json!(values));
                            Outcome::Keep
                        }),
                    ])]),
                ])])
            };
            vec![policy(), T::lit("Software").sub(vec![policy()])]
        },
    }
}
