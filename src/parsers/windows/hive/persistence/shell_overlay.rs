use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("persistence.shell_overlay_handlers");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let overlays = || {
                T::lit("Microsoft").sub(vec![T::lit("Windows").sub(vec![
                    T::lit("CurrentVersion").sub(vec![T::lit("Explorer").sub(vec![
                        T::lit("ShellIconOverlayIdentifiers").sub(vec![T::any().emit(
                            KIND,
                            |object, cell| {
                                let values = registry_value_map(cell);
                                object.text =
                                    format!("Shell icon overlay handler: {}", cell.key_name);
                                object
                                    .data
                                    .insert("handler_name".into(), json!(cell.key_name));
                                object
                                    .data
                                    .insert("handler_values".into(), json!(values));
                                Outcome::Keep
                            },
                        )]),
                    ])]),
                ])])
            };
            vec![overlays(), T::lit("Software").sub(vec![overlays()])]
        },
    }
}
