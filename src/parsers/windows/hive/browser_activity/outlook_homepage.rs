use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("browser_activity.outlook_webview");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let outlook = || {
                T::lit("Microsoft").sub(vec![T::lit("Office").sub(vec![T::any().sub(vec![
                    T::lit("Outlook").sub(vec![
                        T::lit("WebView").sub(vec![T::lit("Inbox").emit(
                            KIND,
                            |object, cell| {
                                let values = registry_value_map(cell);
                                object.text = "Outlook WebView homepage settings".into();
                                object
                                    .data
                                    .insert("outlook_webview_values".into(), json!(values));
                                Outcome::Keep
                            },
                        )]),
                        T::lit("Security").emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = "Outlook security settings".into();
                            object
                                .data
                                .insert("outlook_security_values".into(), json!(values));
                            Outcome::Keep
                        }),
                    ]),
                ])])])
            };
            vec![outlook(), T::lit("Software").sub(vec![outlook()])]
        },
    }
}
