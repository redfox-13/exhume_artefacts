use notatin::cell_key_node::CellKeyNode;
use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, parse_value_map, ObjectOutput, value_text};

pub const KIND: &str = hive_kind_prefix!("program_execution.app_paths");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let app_paths_key = || {
                T::lit("Windows").sub(vec![T::lit("CurrentVersion").sub(vec![
                    T::lit("App Paths").sub(vec![T::any().emit(KIND, app_path_entry)]),
                ])])
            };
            vec![
                T::lit("Microsoft").sub(vec![app_paths_key()]),
                T::lit("Wow6432Node").sub(vec![T::lit("Microsoft").sub(vec![app_paths_key()])]),
                T::lit("Wow6432Node").sub(vec![
                    T::lit("Software").sub(vec![T::lit("Microsoft").sub(vec![app_paths_key()])]),
                ]),
                T::lit("Software").sub(vec![
                    T::lit("Microsoft").sub(vec![app_paths_key()]),
                    T::lit("Wow6432Node").sub(vec![T::lit("Microsoft").sub(vec![app_paths_key()])]),
                ]),
            ]
        },
    }
}

fn app_path_entry(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let values = parse_value_map(cell, |value| {
        Some((
            value.get_pretty_name(),
            json!(value_text(value)),
        ))
    });
    let value_for_name = |name: &str| {
        values
            .iter()
            .find(|(value_name, _)| value_name.eq_ignore_ascii_case(name))
            .and_then(|(_, value)| value.as_str())
            .map(str::to_owned)
    };
    let executable_path = value_for_name("(default)");
    let application_search_path = value_for_name("Path");

    object.text = format!("Registered application path: {}", cell.key_name);
    object
        .data
        .insert("registered_executable".into(), json!(cell.key_name));
    object
        .data
        .insert("executable_path".into(), json!(executable_path));
    object.data.insert(
        "application_search_path".into(),
        json!(application_search_path),
    );
    Outcome::Keep
}
