use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("sysinfo.spp_clients");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let clients = || {
                T::lit("Microsoft").sub(vec![T::lit("Windows NT").sub(vec![
                    T::lit("CurrentVersion").sub(vec![T::lit("SPP").sub(vec![
                        T::lit("Clients").emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = "Software Protection Platform monitored volumes".into();
                            object.data.insert("spp_client_values".into(), json!(values));
                            Outcome::Keep
                        }),
                    ])]),
                ])])
            };
            vec![clients(), T::lit("Software").sub(vec![clients()])]
        },
    }
}
