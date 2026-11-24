use notatin::cell_key_node::CellKeyNode;
use serde_json::{Value, json};

use super::super::{Artefact, ObjectOutput, Outcome, TrieNode as T, hive_kind_prefix};

pub const KIND: &str = hive_kind_prefix!("security.sam_aliases");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("SAM").sub(vec![T::lit("Domains").sub(vec![
                T::lit("Account").sub(vec![T::lit("Aliases")
                    .combine(KIND, |object, _| {
                        object.text = "SAM local aliases and membership".into();
                        object.data.insert("alias_scope".into(), json!("account"));
                        object
                            .data
                            .insert("sam_aliases".into(), Value::Array(Vec::new()));
                        Outcome::Keep
                    })
                    .sub(vec![T::pre("0000").combine(KIND, add_alias)])]),
                T::lit("Builtin").sub(vec![T::lit("Aliases")
                    .combine(KIND, |object, _| {
                        object.text = "SAM built-in aliases and membership".into();
                        object.data.insert("alias_scope".into(), json!("builtin"));
                        object
                            .data
                            .insert("sam_aliases".into(), Value::Array(Vec::new()));
                        Outcome::Keep
                    })
                    .sub(vec![T::pre("0000").combine(KIND, add_alias)])]),
            ])])]
        },
    }
}

fn add_alias(object: &mut ObjectOutput, cell: &CellKeyNode) -> Outcome {
    let parsed = super::sam::value_bytes(cell, "C").and_then(|data| super::sam::alias_c(&data));
    let (group_name, comment, member_sids, member_count) = parsed
        .map(|(name, comment, members, count)| (Some(name), Some(comment), members, Some(count)))
        .unwrap_or((None, None, Vec::new(), None));
    let alias = json!({
        "rid": u32::from_str_radix(&cell.key_name, 16).ok(),
        "scope": object.data.get("alias_scope"),
        "name": group_name,
        "comment": comment,
        "member_count": member_count,
        "member_sids": member_sids,
        "record_status": if member_count.is_some() {
            "alias_data_parsed"
        } else {
            "missing_or_malformed_c_value"
        },
        "last_write_timestamp_rfc3339": cell
            .last_key_written_date_and_time()
            .to_rfc3339(),
    });
    if let Some(aliases) = object
        .data
        .get_mut("sam_aliases")
        .and_then(Value::as_array_mut)
    {
        aliases.push(alias);
    }
    Outcome::Keep
}
