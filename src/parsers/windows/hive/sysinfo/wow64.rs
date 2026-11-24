use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("sysinfo.wow64_configuration");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let wow64 = || {
                T::lit("Microsoft").sub(vec![T::lit("WOW64").sub(vec![
                    T::lit("x86").emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "WOW64 x86 configuration".into();
                        object.data.insert("wow64_values".into(), json!(values));
                        Outcome::Keep
                    }),
                    T::lit("arm").emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "WOW64 ARM configuration".into();
                        object.data.insert("wow64_values".into(), json!(values));
                        Outcome::Keep
                    }),
                ])])
            };
            vec![wow64(), T::lit("Software").sub(vec![wow64()])]
        },
    }
}
