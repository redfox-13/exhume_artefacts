use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("persistence.netsh_helpers");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let netsh = || {
                T::lit("Microsoft").sub(vec![T::lit("Netsh").emit(KIND, |object, cell| {
                    let values = registry_value_map(cell);
                    object.text = "Netsh helper and DLL registrations".into();
                    object.data.insert("netsh_helpers".into(), json!(values));
                    Outcome::Keep
                })])
            };
            vec![netsh(), T::lit("Software").sub(vec![netsh()])]
        },
    }
}
