use serde_json::{Value, json};

use crate::formats::timestamps::{unix_seconds_to_json, windows_filetime_to_json};

use super::super::{
    Artefact, Outcome, TrieNode as T, hive_kind_prefix, parse_value_map, value_text,
};

pub const KIND: &str = hive_kind_prefix!("sysinfo.windows_version");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Microsoft").sub(vec![T::lit("Windows NT").sub(vec![
                T::lit("CurrentVersion").emit(KIND, |object, cell| {
                    let values = parse_value_map(cell, |value| {
                        Some((
                            value.get_pretty_name().to_ascii_lowercase(),
                            json!(value_text(value)),
                        ))
                    });
                    let text = |name: &str| {
                        values
                            .get(name)
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    };

                    let text_any = |names: &[&str]| names.iter().find_map(|name| text(name));
                    let Some(product_name) = text("productname") else {
                        return Outcome::Skip;
                    };

                    let install_date = unix_seconds_to_json(
                        text("installdate")
                        .and_then(|value| value.parse::<i64>().ok())
                    );

                    let install_time = text("installtime")
                        .and_then(|value| value.parse::<u64>().ok())
                        .map(windows_filetime_to_json);

                    let current_build = text_any(&["currentbuildnumber", "currentbuild"]);
                    let edition_id = text_any(&["editionid", "compositioneditionid"]);

                    object.text = format!(
                        "Windows system information: {} (build {})",
                        product_name,
                        current_build.as_deref().unwrap_or("?")
                    );
                    object.data.insert("product_name".into(), json!(product_name));
                    object
                        .data
                        .insert("system_root".into(), json!(text("systemroot")));
                    object
                        .data
                        .insert("release_id".into(), json!(text("releaseid")));
                    object.data.insert(
                        "display_version".into(),
                        json!(text("displayversion")),
                    );
                    object
                        .data
                        .insert("current_version".into(), json!(text("currentversion")));
                    object
                        .data
                        .insert("csd_version".into(), json!(text("csdversion")));
                    object.data.insert(
                        "current_build".into(),
                        json!(current_build),
                    );
                    object
                        .data
                        .insert("build_lab".into(), json!(text("buildlab")));
                    object
                        .data
                        .insert("build_lab_ex".into(), json!(text("buildlabex")));
                    object.data.insert("build_branch".into(), json!(text("buildbranch")));
                    object.data.insert("edition_id".into(), json!(edition_id));
                    object
                        .data
                        .insert("product_id".into(), json!(text("productid")));
                    object.data.insert(
                        "registered_organization".into(),
                        json!(text("registeredorganization")),
                    );
                    object.data.insert(
                        "registered_owner".into(),
                        json!(text("registeredowner")),
                    );
                    object.data.insert("install_date".into(), json!(install_date));
                    object.data.insert("install_time".into(), json!(install_time));
                    object.data.insert(
                        "windows_version_registry_values".into(),
                        json!(values),
                    );
                    Outcome::Keep
                }),
            ])])]
        },
    }
}
