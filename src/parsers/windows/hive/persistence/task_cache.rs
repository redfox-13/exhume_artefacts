use serde_json::{json, Value};

use super::super::{hive_kind_prefix, parse_values, Artefact, Outcome, TrieNode as T};

const KIND: &str = hive_kind_prefix!("persistence.task_cache");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Microsoft").sub(vec![T::lit("Windows NT").sub(vec![
                T::lit("CurrentVersion").sub(vec![T::lit("Schedule").sub(vec![
                    T::lit("TaskCache").sub(vec![T::lit("Tasks").sub(vec![T::any().emit(
                        KIND,
                        |object, cell| {
                            let values: Vec<Value> = parse_values(cell, |value| {
                                Some(json!({
                                    "name": value.get_pretty_name(),
                                    "value": super::super::value_text(value),
                                }))
                            });
                            object.text = format!("Scheduled task: {}", cell.key_name);
                            object.data.insert("task_id".into(), json!(cell.key_name));
                            object
                                .data
                                .insert("scheduled_task_properties".into(), json!(values));
                            Outcome::Keep
                        },
                    )])]),
                ])]),
            ])])]
        },
    }
}
