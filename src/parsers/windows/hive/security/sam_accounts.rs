use serde_json::{Value, json};

use super::super::{Artefact, Outcome, TrieNode as T, hive_kind_prefix, parse_time};

pub const KIND: &str = hive_kind_prefix!("security.sam_accounts");

pub(super) fn artefact() -> Artefact {
    Artefact {
        kind: KIND,
        build: || {
            vec![T::lit("SAM").sub(vec![T::lit("Domains").sub(vec![
                T::lit("Account")
                    .combine(KIND, |object, cell| {
                        object.omit_raw_value_sources();
                        object.text = "SAM local account database".into();
                        object.data.insert(
                            "domain_sid".into(),
                            json!(super::sam::domain_sid(cell)),
                        );
                        object
                            .data
                            .insert("sam_local_users".into(), Value::Array(Vec::new()));
                        object.data.insert(
                            "sam_account_name_keys".into(),
                            Value::Array(Vec::new()),
                        );
                        Outcome::Keep
                    })
                    .sub(vec![T::lit("Users").sub(vec![
                        T::pre("0000").combine(KIND, |object, cell| {
                            let user_v = super::sam::value_bytes(cell, "V")
                                .and_then(|data| super::sam::user_v(&data));
                            let user_f = super::sam::value_bytes(cell, "F")
                                .and_then(|data| super::sam::user_f(&data));
                            let given_name = super::sam::utf16_value(cell, "GivenName");
                            let surname = super::sam::utf16_value(cell, "SurName");
                            let internet_username =
                                super::sam::utf16_value(cell, "InternetUserName");
                            let rid = u32::from_str_radix(&cell.key_name, 16).ok();
                            let username = user_v
                                .as_ref()
                                .and_then(|user| user.get("username"))
                                .and_then(Value::as_str);
                            let domain_sid = object
                                .data
                                .get("domain_sid")
                                .and_then(Value::as_str);
                            let sid = domain_sid
                                .zip(rid)
                                .map(|(domain_sid, rid)| format!("{domain_sid}-{rid}"));
                            let status = match (user_v.is_some(), user_f.is_some()) {
                                (true, true) => "account_data_parsed",
                                (false, false) => "missing_or_malformed_v_and_f_values",
                                (false, true) => "missing_or_malformed_v_value",
                                (true, false) => "missing_or_malformed_f_value",
                            };
                            let account = json!({
                                "username": username,
                                "rid": rid,
                                "sid": sid,
                                "given_name": given_name,
                                "surname": surname,
                                "internet_username": internet_username,
                                "account_information": user_v,
                                "logon_information": user_f,
                                "record_status": status,
                            });
                            if let Some(users) = object
                                .data
                                .get_mut("sam_local_users")
                                .and_then(Value::as_array_mut)
                            {
                                users.push(account);
                            }
                            Outcome::Keep
                        }),
                        T::lit("Names").sub(vec![T::any().combine(
                            KIND,
                            |object, cell| {
                                let (last_write_unix, last_write_unix_ms, last_write_rfc3339) =
                                    parse_time(cell);
                                let name_key = json!({
                                    "username": cell.key_name,
                                    "last_write_timestamp_rfc3339": last_write_rfc3339,
                                    "last_write_timestamp_unix": last_write_unix,
                                    "last_write_timestamp_unix_ms": last_write_unix_ms,
                                });
                                if let Some(name_keys) = object
                                    .data
                                    .get_mut("sam_account_name_keys")
                                    .and_then(Value::as_array_mut)
                                {
                                    name_keys.push(name_key);
                                }
                                Outcome::Keep
                            },
                        )]),
                    ])]),
            ])])]
        },
    }
}
