use serde_json::json;

use super::super::{
    Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map, value_text,
};

pub const KIND: &str = hive_kind_prefix!("persistence.exefile_associations");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let associations = || {
                T::lit("Classes").sub(vec![
                    T::any().emit(KIND, |object, cell| {
                        let default = cell.value_iter().find_map(|value| {
                            value
                                .get_pretty_name()
                                .eq_ignore_ascii_case("(default)")
                                .then(|| value_text(&value))
                        });
                        if default.as_deref() != Some("exefile") {
                            return Outcome::Skip;
                        }
                        object.text = format!("Executable file association: {}", cell.key_name);
                        object.data.insert("file_extension".into(), json!(cell.key_name));
                        object.data.insert("file_handler".into(), json!(default));
                        Outcome::Keep
                    }),
                    T::lit("exefile").sub(vec![T::lit("shell").sub(vec![T::lit("open").sub(vec![
                        T::lit("command").emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = "Executable open command".into();
                            object
                                .data
                                .insert("exefile_open_command".into(), json!(values));
                            Outcome::Keep
                        }),
                    ])])]),
                ])
            };
            let usrclass_handler = || {
                T::lit("exefile").sub(vec![T::lit("shell").sub(vec![T::lit("open").sub(vec![
                    T::lit("command").emit(KIND, |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "Executable open command".into();
                        object
                            .data
                            .insert("exefile_open_command".into(), json!(values));
                        Outcome::Keep
                    }),
                ])])])
            };
            vec![
                T::any().emit(KIND, |object, cell| {
                    let default = cell.value_iter().find_map(|value| {
                        value
                            .get_pretty_name()
                            .eq_ignore_ascii_case("(default)")
                            .then(|| value_text(&value))
                    });
                    if default.as_deref() != Some("exefile") {
                        return Outcome::Skip;
                    }
                    object.text = format!("Executable file association: {}", cell.key_name);
                    object.data.insert("file_extension".into(), json!(cell.key_name));
                    object.data.insert("file_handler".into(), json!(default));
                    Outcome::Keep
                }),
                associations(),
                T::lit("Software").sub(vec![associations()]),
                usrclass_handler(),
            ]
        },
    }
}
