use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("program_execution.msi_products");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let products = || {
                T::lit("Classes").sub(vec![T::lit("Installer").sub(vec![
                    T::lit("Products").sub(vec![T::any()
                        .combine(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            if cell.key_name.eq_ignore_ascii_case("SourceList") {
                                object.data.insert(
                                    "installer_source_list".into(),
                                    json!(values),
                                );
                                object.data.insert(
                                    "last_used_source".into(),
                                    values.get("LastUsedSource").cloned().unwrap_or_default(),
                                );
                                object.data.insert(
                                    "package_name".into(),
                                    values.get("PackageName").cloned().unwrap_or_default(),
                                );
                            } else {
                                object.text =
                                    format!("Windows Installer product: {}", cell.key_name);
                                object.data.insert(
                                    "product_registry_id".into(),
                                    json!(cell.key_name),
                                );
                                object.data.insert(
                                    "product_name".into(),
                                    values
                                        .iter()
                                        .find(|(name, _)| {
                                            name.eq_ignore_ascii_case("ProductName")
                                        })
                                        .map(|(_, value)| value.clone())
                                        .unwrap_or_default(),
                                );
                                object.data.insert(
                                    "installer_product_values".into(),
                                    json!(values),
                                );
                            }
                            Outcome::Keep
                        })
                        .sub(vec![T::lit("SourceList").combine(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            object
                                .data
                                .insert("installer_source_list".into(), json!(values));
                            object.data.insert(
                                "last_used_source".into(),
                                values.get("LastUsedSource").cloned().unwrap_or_default(),
                            );
                            object.data.insert(
                                "package_name".into(),
                                values.get("PackageName").cloned().unwrap_or_default(),
                            );
                            Outcome::Keep
                        })])]),
                ])])
            };
            vec![
                products(),
                T::lit("Software").sub(vec![products()]),
                T::lit("Wow6432Node").sub(vec![products()]),
                T::lit("Software").sub(vec![
                    T::lit("Wow6432Node").sub(vec![products()]),
                ]),
            ]
        },
    }
}
