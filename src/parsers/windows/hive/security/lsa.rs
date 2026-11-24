use serde_json::json;

use super::super::{hive_kind_prefix, registry_value_map, Artefact, Outcome, TrieNode as T};

pub const KIND: &str = hive_kind_prefix!("security.lsa");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::pre("ControlSet").sub(vec![T::lit("Control").sub(vec![
                T::lit("Lsa").emit(KIND, |object, cell| {
                    let values = registry_value_map(cell);
                    object.text = "LSA security configuration".into();
                    object
                        .data
                        .insert("lsa_configuration".into(), json!(values));
                    Outcome::Keep
                }),
            ])])]
        },
    }
}
