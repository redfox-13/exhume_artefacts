use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("sysinfo.wbem");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let wbem = || {
                T::lit("Microsoft").sub(vec![T::lit("WBEM").sub(vec![
                    T::lit("WDM").emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "WMI WDM device registrations".into();
                        object.data.insert("wbem_wdm_values".into(), json!(values));
                        Outcome::Keep
                    }),
                    T::lit("CIMOM").emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "WMI CIMOM configuration".into();
                        object.data.insert("wbem_cimom_values".into(), json!(values));
                        Outcome::Keep
                    }),
                ])])
            };
            vec![wbem(), T::lit("Software").sub(vec![wbem()])]
        },
    }
}
