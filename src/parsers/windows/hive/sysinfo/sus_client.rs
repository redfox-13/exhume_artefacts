use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("sysinfo.windows_update_client");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let update = || {
                T::lit("Microsoft").sub(vec![T::lit("Windows").sub(vec![
                    T::lit("CurrentVersion").sub(vec![
                        T::lit("WindowsUpdate").emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            let serial = cell.value_iter().find_map(|value| {
                                if !value.get_pretty_name().eq_ignore_ascii_case(
                                    "SusClientIdValidation",
                                ) {
                                    return None;
                                }
                                let bytes = value.detail.value_bytes()?;
                                let offset = usize::from(*bytes.first()?);
                                let size = usize::from(*bytes.get(2)?);
                                let decoded = bytes.get(offset..offset.checked_add(size)?)?;
                                let text: String = decoded
                                    .iter()
                                    .copied()
                                    .filter(|byte| *byte != 0 && *byte != b' ')
                                    .map(char::from)
                                    .collect();
                                if text.is_empty() { None } else { Some(text) }
                            });
                            object.text = "Windows Update client identifiers".into();
                            object.data.insert("windows_update_values".into(), json!(values));
                            object
                                .data
                                .insert("hdd_serial_number".into(), json!(serial));
                            Outcome::Keep
                        }),
                    ]),
                ])])
            };
            vec![update(), T::lit("Software").sub(vec![update()])]
        },
    }
}
