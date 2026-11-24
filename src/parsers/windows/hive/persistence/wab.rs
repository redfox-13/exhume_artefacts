use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("persistence.windows_address_book");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let dll_path = || {
                T::lit("Microsoft").sub(vec![T::lit("WAB").sub(vec![
                    T::lit("DLLPath").emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "Windows Address Book DLL path".into();
                        object.data.insert("wab_dll_path_values".into(), json!(values));
                        Outcome::Keep
                    }),
                ])])
            };
            vec![dll_path(), T::lit("Software").sub(vec![dll_path()])]
        },
    }
}
