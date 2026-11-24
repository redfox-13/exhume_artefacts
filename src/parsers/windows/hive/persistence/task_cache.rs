use serde_json::json;

use super::super::{hive_kind_prefix, registry_value_map, Artefact, Outcome, TrieNode as T};

pub const KIND: &str = hive_kind_prefix!("persistence.task_cache");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Microsoft").sub(vec![T::lit("Windows NT").sub(vec![
                T::lit("CurrentVersion").sub(vec![T::lit("Schedule").sub(vec![
                    T::lit("TaskCache").sub(vec![
                        T::lit("Tasks").sub(vec![T::any().emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = format!("Scheduled task: {}", cell.key_name);
                            object.data.insert("task_id".into(), json!(cell.key_name));
                            object
                                .data
                                .insert("scheduled_task_properties".into(), json!(values));
                            Outcome::Keep
                        })]),
                        T::lit("Tree").sub(vec![T::any().emit(KIND, |object, cell| {
                            let values = registry_value_map(cell);
                            object.text = format!("Scheduled task tree entry: {}", cell.key_name);
                            object
                                .data
                                .insert("task_name".into(), json!(cell.key_name));
                            object.data.insert(
                                "task_id".into(),
                                values
                                    .iter()
                                    .find(|(name, _)| name.eq_ignore_ascii_case("Id"))
                                    .map(|(_, value)| value.clone())
                                    .unwrap_or(serde_json::Value::Null),
                            );
                            object
                                .data
                                .insert("scheduled_task_properties".into(), json!(values));
                            Outcome::Keep
                        })]),
                    ]),
                ])]),
            ])])]
        },
    }
}
