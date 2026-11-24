use notatin::cell_key_node::CellKeyNode;
use serde_json::{Value, json};

use super::super::{
    Artefact, ObjectOutput, Outcome, TrieNode as T, hive_kind_prefix, value_text,
};

pub const KIND: &str = hive_kind_prefix!("user_behavior.wordwheel_query");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("Software").sub(vec![T::lit("Microsoft").sub(vec![
                T::lit("Windows").sub(vec![T::lit("CurrentVersion").sub(vec![
                    T::lit("Explorer").sub(vec![T::lit("WordWheelQuery")
                        .emit(KIND, search_queries)]),
                ])]),
            ])])]
        },
    }
}

fn search_queries(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let mru_order = cell
        .value_iter()
        .find(|value| value.get_pretty_name().eq_ignore_ascii_case("MRUListEx"))
        .map(|value| {
            value
                .detail
                .value_bytes()
                .unwrap_or_default()
                .chunks_exact(4)
                .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                .take_while(|index| *index != u32::MAX)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let queries: Vec<Value> = cell.value_iter().filter_map(|value| {
        let value_name = value.get_pretty_name();
        if value_name.eq_ignore_ascii_case("MRUListEx") {
            return None;
        }

        let entry_index = value_name.parse::<u32>().ok();
        let mru_rank = entry_index.and_then(|index| {
            mru_order
                .iter()
                .position(|candidate| *candidate == index)
                .map(|position| position + 1)
        });
        Some(json!({
            "entry_index": entry_index,
            "mru_rank": mru_rank,
            "search_query": value_text(&value),
        }))
    }).collect();

    object.text = format!("Windows search queries: {} entries", queries.len());
    object
        .data
        .insert("wordwheel_search_queries".into(), json!(queries));
    object.data.insert("mru_order".into(), json!(mru_order));
    Outcome::Keep
}
