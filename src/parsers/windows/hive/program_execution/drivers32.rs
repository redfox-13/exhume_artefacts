use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("program_execution.drivers32");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let drivers = || {
                T::lit("Microsoft").sub(vec![T::lit("Windows NT").sub(vec![
                    T::lit("CurrentVersion").sub(vec![T::lit("Drivers32").emit(
                        KIND,
                        |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = "Windows multimedia Drivers32 registrations".into();
                            object
                                .data
                                .insert("drivers32_values".into(), json!(values));
                            Outcome::Keep
                        },
                    )]),
                ])])
            };
            let wow = || T::lit("Wow6432Node").sub(vec![drivers()]);
            vec![drivers(), wow(), T::lit("Software").sub(vec![drivers(), wow()])]
        },
    }
}
