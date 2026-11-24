use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("sysinfo.scheduling_agent");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let agent = || {
                T::lit("Microsoft").sub(vec![T::lit("SchedulingAgent").emit(
                    KIND,
                    |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "Windows Scheduling Agent configuration".into();
                        object.data.insert("scheduling_agent_values".into(), json!(values));
                        Outcome::Keep
                    },
                )])
            };
            vec![agent(), T::lit("Software").sub(vec![agent()])]
        },
    }
}
