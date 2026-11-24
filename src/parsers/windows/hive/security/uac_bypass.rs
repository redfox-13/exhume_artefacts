use serde_json::json;

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, registry_value_map};

pub const KIND: &str = hive_kind_prefix!("security.file_handler_overrides");

pub(in crate::parsers::windows::hive) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            let open_command = || {
                T::lit("shell").sub(vec![T::lit("open").sub(vec![T::lit("command").emit(
                    KIND,
                    |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = format!("File-handler command: {}", cell.path);
                        object
                            .data
                            .insert("handler_open_command".into(), json!(values));
                        Outcome::Keep
                    }),
                ])])
            };
            let runas_command = || {
                T::lit("shell").sub(vec![T::lit("runas").sub(vec![T::lit("command").emit(
                    KIND,
                    |object, cell| {
                        let values = registry_value_map(cell);
                        object.text = "Executable run-as handler".into();
                        object
                            .data
                            .insert("handler_runas_command".into(), json!(values));
                        Outcome::Keep
                    },
                )])])
            };
            let app = |name| T::lit(name).sub(vec![open_command()]);
            let apps = || {
                vec![
                    app("exefile"),
                    app("Folder"),
                    app("mscfile"),
                    app("ms-settings"),
                    app("AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2"),
                    app("Launcher.SystemSettings"),
                ]
            };
            let handlers = || {
                let mut handlers = apps();
                handlers.push(T::lit("exefile").sub(vec![runas_command()]));
                handlers
            };
            vec![
                T::lit("Classes").sub(handlers()),
                T::lit("Software").sub(vec![T::lit("Classes").sub(handlers())]),
                T::any().sub(vec![open_command()]),
                T::lit("exefile").sub(vec![runas_command()]),
            ]
        },
    }
}
