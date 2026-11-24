use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("persistence.file_type_commands");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let command = || {
                T::lit("shell").sub(vec![T::lit("open").sub(vec![T::lit("command").emit(
                    KIND,
                    |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = format!("File-type open command: {}", cell.path);
                        object
                            .data
                            .insert("file_type_command_values".into(), json!(values));
                        Outcome::Keep
                    },
                )])])
            };
            let file_type = |name| T::lit(name).sub(vec![command()]);
            let classes = || {
                T::lit("Classes").sub(vec![
                    file_type("exefile"),
                    file_type("cmdfile"),
                    file_type("batfile"),
                    file_type("csfile"),
                    file_type("htafile"),
                    file_type("piffile"),
                    file_type("mscfile"),
                ])
            };
            let iexplore = || {
                T::lit("Clients").sub(vec![T::lit("StartMenuInternet").sub(vec![
                    T::lit("IExplore.exe").sub(vec![command()]),
                ])])
            };
            vec![
                classes(),
                iexplore(),
                T::lit("Software").sub(vec![classes(), iexplore()]),
            ]
        },
    }
}
