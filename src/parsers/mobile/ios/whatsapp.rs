use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput, TimelineEvent};
use crate::parsers::mobile::common::records::{
    AppInfo, ChatMessage, Conversation, Direction, MessageState, Party,
};
use crate::parsers::mobile::common::timestamps::apple_absolute_to_json;
use crate::parsers::mobile::sqlite::{
    SqliteConnection, SqliteEvidence, SqliteSchema, SqliteStatement, select_column,
};
use anyhow::{Context, Result, bail};
use base64::Engine;
use serde_json::{Value, json};

const PARSER_NAME: &str = "mobile_ios_whatsapp";
const APP: AppInfo = AppInfo {
    bundle_id: "net.whatsapp.WhatsApp",
    label: "WhatsApp",
};
const SCHEMA_VARIANT: &str = "ios_whatsapp_chatstorage_coredata_v1";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

/// Per-platform differences between the iOS and macOS WhatsApp parsers. Both
/// read `ChatStorage.sqlite` with the identical Core Data schema, so the macOS
/// parser reuses this whole engine with only these fields changed.
pub(crate) struct WhatsAppConfig {
    pub parser_name: &'static str,
    /// `"ios"` or `"macos"` — recorded on every emitted object.
    pub platform: &'static str,
    /// Short app label used in the app-specific JSON blocks.
    pub app_label: &'static str,
    pub app: AppInfo,
    pub schema_variant: &'static str,
}

const IOS_CONFIG: WhatsAppConfig = WhatsAppConfig {
    parser_name: PARSER_NAME,
    platform: "ios",
    app_label: "whatsapp",
    app: APP,
    schema_variant: SCHEMA_VARIANT,
};

/// Run the WhatsApp ChatStorage engine end-to-end for either platform.
pub(crate) fn run_whatsapp(
    cfg: &WhatsAppConfig,
    input: ParserInput,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let evidence = SqliteEvidence::from_input(input, "ChatStorage.sqlite")?;
    let conn = SqliteConnection::open(evidence.path())?;
    let schema = conn.schema()?;
    validate_schema(&schema)?;

    emit_chats(cfg, &conn, &schema, &evidence, sink)?;
    emit_messages(cfg, &conn, &schema, &evidence, sink)?;

    Ok(())
}

/// Timeline extraction is identical for both platforms.
pub(crate) fn extract_whatsapp_timeline(obj: &ObjectParsed) -> Vec<TimelineEvent> {
    match obj.kind {
        "mobile.communication.message" => {
            let Some(ts_unix_ms) = obj.json["timestamps"]["message"]["unix_ms"].as_i64() else {
                return Vec::new();
            };
            let description = obj.json["details"]["message"]["display_text"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            let actor = obj.json["sender"]["id"].as_str().map(str::to_owned);
            vec![TimelineEvent {
                ts_unix_ms,
                event_type: "mobile.communication.message",
                description,
                actor,
            }]
        }
        "mobile.communication.attachment" => {
            let Some(ts_unix_ms) = obj.json["timestamps"]["message"]["unix_ms"].as_i64() else {
                return Vec::new();
            };
            let description = obj.json["attachment"]["file_name"]
                .as_str()
                .filter(|s| !s.is_empty())
                .or_else(|| obj.json["attachment"]["kind"].as_str())
                .map(str::to_owned);
            vec![TimelineEvent {
                ts_unix_ms,
                event_type: "mobile.communication.attachment",
                description,
                actor: None,
            }]
        }
        _ => Vec::new(),
    }
}

#[derive(Default)]
pub struct IosWhatsAppParser;

impl Parser for IosWhatsAppParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse WhatsApp for iOS ChatStorage.sqlite chats, messages, and media references."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        extract_whatsapp_timeline(obj)
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        run_whatsapp(&IOS_CONFIG, input, sink)
    }
}

fn validate_schema(schema: &SqliteSchema) -> Result<()> {
    if !schema.has_table("ZWAMESSAGE") {
        bail!("not a supported WhatsApp iOS ChatStorage database: missing ZWAMESSAGE table");
    }

    let missing = schema.missing_columns(
        "ZWAMESSAGE",
        &[
            "Z_PK",
            "ZISFROMME",
            "ZMESSAGETYPE",
            "ZMESSAGESTATUS",
            "ZCHATSESSION",
            "ZMESSAGEDATE",
        ],
    );

    if !missing.is_empty() {
        bail!(
            "not a supported WhatsApp iOS ChatStorage database: missing required columns: {}",
            missing.join(", ")
        );
    }

    Ok(())
}

fn emit_chats(
    cfg: &WhatsAppConfig,
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    if !schema.has_table("ZWACHATSESSION") || !schema.has_column("ZWACHATSESSION", "Z_PK") {
        return Ok(());
    }

    let sql = format!(
        r#"
        SELECT
            c.Z_PK AS chat_pk,
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {}
        FROM ZWACHATSESSION c
        ORDER BY c.Z_PK;
        "#,
        select_column(schema, "ZWACHATSESSION", "c", "ZCONTACTJID", "chat_jid"),
        select_column(
            schema,
            "ZWACHATSESSION",
            "c",
            "ZCONTACTIDENTIFIER",
            "contact_identifier"
        ),
        select_column(
            schema,
            "ZWACHATSESSION",
            "c",
            "ZPARTNERNAME",
            "partner_name"
        ),
        select_column(
            schema,
            "ZWACHATSESSION",
            "c",
            "ZSESSIONTYPE",
            "session_type"
        ),
        select_column(
            schema,
            "ZWACHATSESSION",
            "c",
            "ZMESSAGECOUNTER",
            "message_counter"
        ),
        select_column(
            schema,
            "ZWACHATSESSION",
            "c",
            "ZUNREADCOUNT",
            "unread_count"
        ),
        select_column(schema, "ZWACHATSESSION", "c", "ZARCHIVED", "archived"),
        select_column(schema, "ZWACHATSESSION", "c", "ZREMOVED", "removed"),
        select_column(
            schema,
            "ZWACHATSESSION",
            "c",
            "ZLASTMESSAGEDATE",
            "last_message_date"
        ),
        select_column(
            schema,
            "ZWACHATSESSION",
            "c",
            "ZLASTMESSAGETEXT",
            "last_message_text"
        ),
    );

    conn.query_rows(&sql, |row| {
        let chat_pk = row.i64(0).context("chat row missing Z_PK")?;
        let last_message_text = row.text(10);
        let json = json!({
            "platform": cfg.platform,
            "app": cfg.app_label,
            "record_type": "chat",
            "source": source_json(cfg, evidence, "ZWACHATSESSION", chat_pk),
            "chat": {
                "rowid": chat_pk,
                "jid": row.text(1),
                "contact_identifier": row.text(2),
                "name": row.text(3),
                "session_type_code": row.i64(4),
                "message_counter": row.i64(5),
                "unread_count": row.i64(6),
                "archived": row.bool(7),
                "removed": row.bool(8),
                "last_message_text": last_message_text,
            },
            "timestamps": {
                "last_message": apple_absolute_to_json(row.f64(9)),
            },
        });

        sink(ObjectParsed {
            parser: cfg.parser_name,
            kind: "mobile.communication.chat",
            text: row.text(3).unwrap_or_default(),
            json,
        })
    })
}

fn emit_messages(
    cfg: &WhatsAppConfig,
    conn: &SqliteConnection,
    schema: &SqliteSchema,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let has_chat_join = schema.has_table("ZWACHATSESSION")
        && schema.has_column("ZWACHATSESSION", "Z_PK")
        && schema.has_column("ZWAMESSAGE", "ZCHATSESSION");
    let chat_join = if has_chat_join {
        "LEFT JOIN ZWACHATSESSION c ON c.Z_PK = m.ZCHATSESSION"
    } else {
        ""
    };

    let has_group_join = schema.has_table("ZWAGROUPMEMBER")
        && schema.has_column("ZWAGROUPMEMBER", "Z_PK")
        && schema.has_column("ZWAMESSAGE", "ZGROUPMEMBER");
    let group_join = if has_group_join {
        "LEFT JOIN ZWAGROUPMEMBER gm ON gm.Z_PK = m.ZGROUPMEMBER"
    } else {
        ""
    };

    let (media_join, has_media_join) = media_join(schema);

    let sql = format!(
        r#"
        SELECT
            m.Z_PK AS message_pk,
            {},
            {},
            m.ZISFROMME AS is_from_me,
            m.ZMESSAGETYPE AS message_type,
            m.ZMESSAGESTATUS AS message_status,
            {},
            {},
            m.ZMESSAGEDATE AS message_date,
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {}
        FROM ZWAMESSAGE m
        {chat_join}
        {group_join}
        {media_join}
        ORDER BY m.ZMESSAGEDATE, m.Z_PK;
        "#,
        select_column(schema, "ZWAMESSAGE", "m", "ZSTANZAID", "stanza_id"),
        select_column(schema, "ZWAMESSAGE", "m", "ZTEXT", "message_text"),
        select_column(
            schema,
            "ZWAMESSAGE",
            "m",
            "ZMESSAGEERRORSTATUS",
            "message_error_status"
        ),
        select_column(schema, "ZWAMESSAGE", "m", "ZSTARRED", "starred"),
        select_column(schema, "ZWAMESSAGE", "m", "ZSENTDATE", "sent_date"),
        select_column(schema, "ZWAMESSAGE", "m", "ZFROMJID", "from_jid"),
        select_column(schema, "ZWAMESSAGE", "m", "ZTOJID", "to_jid"),
        select_column(schema, "ZWAMESSAGE", "m", "ZPUSHNAME", "push_name"),
        select_column(schema, "ZWAMESSAGE", "m", "ZCHATSESSION", "chat_session_pk"),
        select_joined_column(
            has_chat_join,
            schema,
            "ZWACHATSESSION",
            "c",
            "ZCONTACTJID",
            "chat_jid",
        ),
        select_joined_column(
            has_chat_join,
            schema,
            "ZWACHATSESSION",
            "c",
            "ZPARTNERNAME",
            "chat_name",
        ),
        select_joined_column(
            has_chat_join,
            schema,
            "ZWACHATSESSION",
            "c",
            "ZSESSIONTYPE",
            "chat_session_type"
        ),
        select_joined_column(
            has_group_join,
            schema,
            "ZWAGROUPMEMBER",
            "gm",
            "ZMEMBERJID",
            "group_member_jid"
        ),
        select_joined_column(
            has_group_join,
            schema,
            "ZWAGROUPMEMBER",
            "gm",
            "ZCONTACTNAME",
            "group_member_name"
        ),
        select_joined_column(
            has_media_join,
            schema,
            "ZWAMEDIAITEM",
            "media",
            "Z_PK",
            "media_pk",
        ),
        select_joined_column(
            has_media_join,
            schema,
            "ZWAMEDIAITEM",
            "media",
            "ZMEDIALOCALPATH",
            "media_local_path"
        ),
        select_joined_column(
            has_media_join,
            schema,
            "ZWAMEDIAITEM",
            "media",
            "ZMEDIAURL",
            "media_url",
        ),
        select_joined_column(
            has_media_join,
            schema,
            "ZWAMEDIAITEM",
            "media",
            "ZTHUMBNAILLOCALPATH",
            "thumbnail_local_path"
        ),
        select_joined_column(
            has_media_join,
            schema,
            "ZWAMEDIAITEM",
            "media",
            "ZTITLE",
            "media_title",
        ),
        select_joined_column(
            has_media_join,
            schema,
            "ZWAMEDIAITEM",
            "media",
            "ZVCARDNAME",
            "vcard_name",
        ),
        select_joined_column(
            has_media_join,
            schema,
            "ZWAMEDIAITEM",
            "media",
            "ZVCARDSTRING",
            "vcard_string"
        ),
        select_joined_column(
            has_media_join,
            schema,
            "ZWAMEDIAITEM",
            "media",
            "ZLATITUDE",
            "latitude",
        ),
        select_joined_column(
            has_media_join,
            schema,
            "ZWAMEDIAITEM",
            "media",
            "ZLONGITUDE",
            "longitude",
        ),
        select_joined_column(
            has_media_join,
            schema,
            "ZWAMEDIAITEM",
            "media",
            "ZFILESIZE",
            "file_size",
        ),
        select_joined_column(
            has_media_join,
            schema,
            "ZWAMEDIAITEM",
            "media",
            "ZMOVIEDURATION",
            "movie_duration"
        ),
        select_joined_column(
            has_media_join,
            schema,
            "ZWAMEDIAITEM",
            "media",
            "ZMEDIAORIGIN",
            "media_origin"
        ),
        select_joined_column(
            has_media_join,
            schema,
            "ZWAMEDIAITEM",
            "media",
            "ZCLOUDSTATUS",
            "cloud_status"
        ),
        blob_length_column(
            has_media_join,
            schema,
            "ZWAMEDIAITEM",
            "media",
            "ZMEDIAKEY",
            "media_key_length"
        ),
        blob_length_column(
            has_media_join,
            schema,
            "ZWAMEDIAITEM",
            "media",
            "ZMETADATA",
            "metadata_length"
        ),
        select_column(schema, "ZWAMESSAGE", "m", "ZFLAGS", "flags"),
        select_column(schema, "ZWAMESSAGE", "m", "ZSORT", "sort"),
        select_column(schema, "ZWAMESSAGE", "m", "ZDOCID", "doc_id"),
        select_joined_column(
            has_media_join,
            schema,
            "ZWAMEDIAITEM",
            "media",
            "ZMETADATA",
            "metadata_blob"
        ),
    );

    conn.query_rows(&sql, |row| emit_message(cfg, row, evidence, sink))
}

fn media_join(schema: &SqliteSchema) -> (&'static str, bool) {
    if !schema.has_table("ZWAMEDIAITEM") {
        return ("", false);
    }

    if schema.has_column("ZWAMEDIAITEM", "Z_PK") && schema.has_column("ZWAMESSAGE", "ZMEDIAITEM") {
        (
            "LEFT JOIN ZWAMEDIAITEM media ON media.Z_PK = m.ZMEDIAITEM",
            true,
        )
    } else if schema.has_column("ZWAMEDIAITEM", "ZMESSAGE") {
        (
            "LEFT JOIN ZWAMEDIAITEM media ON media.ZMESSAGE = m.Z_PK",
            true,
        )
    } else {
        ("", false)
    }
}

fn emit_message(
    cfg: &WhatsAppConfig,
    row: &SqliteStatement<'_>,
    evidence: &SqliteEvidence,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let message_pk = row.i64(0).context("message row missing Z_PK")?;
    let text = row.text(2);
    let is_from_me = row.bool(3);
    let media = media_json(row);
    let classification = classify_message(row, text.as_deref(), media.is_object());

    let chat_id = row
        .i64(13)
        .map(|id| id.to_string())
        .or_else(|| row.text(14))
        .unwrap_or_else(|| "unknown".to_string());
    let counterpart_jid = row.text(10).or_else(|| row.text(17));

    let message = ChatMessage {
        parser: cfg.parser_name,
        platform: cfg.platform,
        app: cfg.app,
        conversation: Conversation {
            id: chat_id,
            display_name: row.text(15).or_else(|| row.text(14)),
            participants: counterpart_jid
                .clone()
                .map(|jid| {
                    vec![Party {
                        id: Some(jid),
                        display_name: row.text(12).or_else(|| row.text(18)),
                        is_self: false,
                    }]
                })
                .unwrap_or_default(),
        },
        direction: Direction::from_is_from_me(is_from_me),
        sender: if is_from_me == Some(true) {
            Party {
                id: None,
                display_name: None,
                is_self: true,
            }
        } else {
            Party {
                id: counterpart_jid,
                display_name: row.text(12).or_else(|| row.text(18)),
                is_self: false,
            }
        },
        timestamp: apple_absolute_to_json(row.f64(8)),
        sent: apple_absolute_to_json(row.f64(9)),
        received: Value::Null,
        body: text.clone(),
        // WhatsApp media is emitted as its own attachment record; the inline
        // list stays empty so the two never double-count.
        attachments: Vec::new(),
        state: MessageState::default(),
        source: source_json(cfg, evidence, "ZWAMESSAGE", message_pk),
        details: json!({
            "message": {
                "rowid": message_pk,
                "stanza_id": row.text(1),
                "display_text": classification.display_text.clone(),
                "type_code": row.i64(4),
                "type_family": classification.type_family,
                "status_code": row.i64(5),
                "error_status_code": row.i64(6),
                "starred": row.bool(7),
                "has_media": media.is_object(),
            },
            "chat": {
                "rowid": row.i64(13),
                "jid": row.text(14),
                "name": row.text(15),
                "session_type_code": row.i64(16),
            },
            "sender": {
                "push_name": row.text(12),
                "group_member_jid": row.text(17),
                "group_member_name": row.text(18),
            },
            "recipient": { "jid": row.text(11) },
            "media": media,
            "raw": {
                "flags": row.i64(34),
                "sort": row.i64(35),
                "doc_id": row.i64(36),
            },
        }),
    };

    sink(message.into())?;

    if classification.emit_attachment {
        emit_attachment(
            cfg,
            row,
            evidence,
            message_pk,
            text,
            classification.type_family,
            media,
            sink,
        )?;
    }

    Ok(())
}

fn emit_attachment(
    cfg: &WhatsAppConfig,
    row: &SqliteStatement<'_>,
    evidence: &SqliteEvidence,
    message_pk: i64,
    message_text: Option<String>,
    type_family: &'static str,
    media: Value,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let media_pk = row.i64(19).context("media row missing Z_PK")?;
    let local_path = row.text(20);
    let remote_url = row.text(21);
    let thumbnail_path = row.text(22);
    let title = non_empty(row.text(23));
    let vcard_name = non_empty(row.text(24));
    let vcard_string = non_empty(row.text(25));
    let file_name = attachment_file_name(title.as_deref(), local_path.as_deref(), row.i64(4));
    let kind = attachment_kind(
        row.i64(4),
        type_family,
        file_name.as_deref(),
        local_path.as_deref(),
        remote_url.as_deref(),
        has_non_zero_location(row.i64(4), row.f64(26), row.f64(27)),
    );
    let mime = mime_hint(
        kind,
        file_name.as_deref(),
        local_path.as_deref(),
        remote_url.as_deref(),
    );
    let preview = embedded_preview_json(row, 37);
    let text = file_name
        .clone()
        .or_else(|| local_path.clone())
        .or_else(|| remote_url.clone())
        .or(message_text.clone())
        .unwrap_or_default();

    let json = json!({
        "platform": cfg.platform,
        "app": cfg.app_label,
        "record_type": "attachment",
        "source": source_json(cfg, evidence, "ZWAMEDIAITEM", media_pk),
        "timestamps": {
            "message": apple_absolute_to_json(row.f64(8)),
            "sent": apple_absolute_to_json(row.f64(9)),
        },
        "direction": direction_label(row.bool(3)),
        "message": {
            "rowid": message_pk,
            "stanza_id": row.text(1),
            "text": message_text,
            "type_code": row.i64(4),
            "type_family": type_family,
            "status_code": row.i64(5),
        },
        "chat": {
            "rowid": row.i64(13),
            "jid": row.text(14),
            "name": row.text(15),
            "session_type_code": row.i64(16),
        },
        "sender": {
            "jid": row.text(10).or_else(|| row.text(17)),
            "push_name": row.text(12),
            "group_member_jid": row.text(17),
            "group_member_name": row.text(18),
        },
        "media": media,
        "attachment": {
            "kind": kind,
            "mime": mime,
            "file_name": file_name,
            "local_path": local_path,
            "remote_url": remote_url,
            "thumbnail_path": thumbnail_path,
            "caption": title,
            "has_vcard": vcard_name.is_some() || vcard_string.is_some(),
        },
        "preview": preview,
    });

    sink(ObjectParsed {
        parser: cfg.parser_name,
        kind: "mobile.communication.attachment",
        text,
        json,
    })
}

struct MessageClassification {
    type_family: &'static str,
    display_text: Option<String>,
    emit_attachment: bool,
}

fn classify_message(
    row: &SqliteStatement<'_>,
    text: Option<&str>,
    has_media: bool,
) -> MessageClassification {
    let type_code = row.i64(4);
    let text = text.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    });
    let media_title = non_empty(row.text(23)).filter(|title| !looks_like_identifier(title));
    let display_text = text.clone().or_else(|| {
        if type_code == Some(14) || is_service_message_type(type_code) {
            None
        } else {
            media_title
        }
    });

    let type_family = match type_code {
        Some(0) if display_text.is_some() => "text",
        Some(0) => "empty_text",
        Some(14) => "reaction",
        Some(7) => "link_preview",
        Some(code) if is_service_message_type(Some(code)) => "service_or_system",
        _ if has_meaningful_attachment(row) => "media",
        _ if display_text.is_some() => "text",
        _ if has_media => "media_reference",
        _ => "service_or_system",
    };

    MessageClassification {
        type_family,
        display_text,
        emit_attachment: has_meaningful_attachment(row),
    }
}

fn media_json(row: &SqliteStatement<'_>) -> Value {
    if row.i64(19).is_none() {
        return Value::Null;
    }

    json!({
        "rowid": row.i64(19),
        "local_path": row.text(20),
        "url": row.text(21),
        "thumbnail_local_path": row.text(22),
        "title": row.text(23),
        "vcard_name": row.text(24),
        "vcard_string": row.text(25),
        "location": {
            "latitude": row.f64(26),
            "longitude": row.f64(27),
        },
        "file_size": row.i64(28),
        "movie_duration": row.i64(29),
        "media_origin_code": row.i64(30),
        "cloud_status_code": row.i64(31),
        "media_key_length": row.i64(32),
        "metadata_length": row.i64(33),
    })
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(value)
        }
    })
}

fn basename(path: Option<&str>) -> Option<String> {
    let value = path?.split(['/', '\\']).next_back()?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn attachment_file_name(
    title: Option<&str>,
    local_path: Option<&str>,
    type_code: Option<i64>,
) -> Option<String> {
    basename(local_path).or_else(|| {
        let title = title?.trim();
        if title.is_empty() || looks_like_identifier(title) {
            return None;
        }

        let title_is_filename = title.len() <= 255
            && has_extension(
                &[Some(title)],
                &[
                    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".txt",
                    ".vcf",
                ],
            );
        if title_is_filename || type_code == Some(9) {
            Some(title.to_string())
        } else {
            None
        }
    })
}

fn looks_like_identifier(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 12 || value.contains(char::is_whitespace) {
        return false;
    }

    let hex_like = value
        .chars()
        .all(|ch| ch.is_ascii_hexdigit() || ch == '-' || ch == '_');
    let base64_like = value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '-' | '_'));

    hex_like || (base64_like && value.len() >= 16)
}

fn has_extension(values: &[Option<&str>], extensions: &[&str]) -> bool {
    values.iter().any(|value| {
        let Some(value) = value else {
            return false;
        };
        let lower = value
            .split(['?', '#'])
            .next()
            .unwrap_or(value)
            .to_ascii_lowercase();
        extensions
            .iter()
            .any(|extension| lower.ends_with(extension))
    })
}

fn attachment_kind(
    type_code: Option<i64>,
    type_family: &str,
    file_name: Option<&str>,
    local_path: Option<&str>,
    remote_url: Option<&str>,
    has_location: bool,
) -> &'static str {
    let hints = [file_name, local_path, remote_url];

    if type_code == Some(4) || has_location || type_family.contains("location") {
        return "location";
    }
    if has_extension(
        &hints,
        &[
            ".jpg", ".jpeg", ".png", ".gif", ".heic", ".heif", ".webp", ".tif", ".tiff", ".bmp",
        ],
    ) || type_code == Some(1)
    {
        return "image";
    }
    if has_extension(
        &hints,
        &[".mp4", ".mov", ".m4v", ".3gp", ".avi", ".mkv", ".webm"],
    ) || type_code == Some(2)
    {
        return "video";
    }
    if has_extension(
        &hints,
        &[".aac", ".amr", ".m4a", ".mp3", ".ogg", ".opus", ".wav"],
    ) || type_code == Some(11)
    {
        return "audio";
    }
    if has_extension(&hints, &[".vcf"]) {
        return "contact";
    }
    if file_name.is_some() || local_path.is_some() || remote_url.is_some() {
        return "document";
    }

    "unknown"
}

fn mime_hint(
    kind: &str,
    file_name: Option<&str>,
    local_path: Option<&str>,
    remote_url: Option<&str>,
) -> Option<&'static str> {
    let hints = [file_name, local_path, remote_url];
    if has_extension(&hints, &[".jpg", ".jpeg"]) {
        return Some("image/jpeg");
    }
    if has_extension(&hints, &[".png"]) {
        return Some("image/png");
    }
    if has_extension(&hints, &[".gif"]) {
        return Some("image/gif");
    }
    if has_extension(&hints, &[".webp"]) {
        return Some("image/webp");
    }
    if has_extension(&hints, &[".mp4", ".m4v"]) {
        return Some("video/mp4");
    }
    if has_extension(&hints, &[".mov"]) {
        return Some("video/quicktime");
    }
    if has_extension(&hints, &[".m4a"]) {
        return Some("audio/mp4");
    }
    if has_extension(&hints, &[".mp3"]) {
        return Some("audio/mpeg");
    }
    if has_extension(&hints, &[".vcf"]) || kind == "contact" {
        return Some("text/vcard");
    }

    None
}

fn has_meaningful_attachment(row: &SqliteStatement<'_>) -> bool {
    let type_code = row.i64(4);
    if matches!(
        type_code,
        Some(0) | Some(7) | Some(14) | Some(46) | Some(55) | Some(59) | Some(66)
    ) {
        return false;
    }

    let local_path = non_empty(row.text(20));
    let remote_url = non_empty(row.text(21));
    let thumbnail_path = non_empty(row.text(22));
    let file_size = row.i64(28).unwrap_or(0);

    local_path.is_some() || remote_url.is_some() || thumbnail_path.is_some() || file_size > 0
}

fn is_service_message_type(type_code: Option<i64>) -> bool {
    matches!(
        type_code,
        Some(10) | Some(46) | Some(55) | Some(59) | Some(66)
    )
}

fn has_non_zero_location(
    type_code: Option<i64>,
    latitude: Option<f64>,
    longitude: Option<f64>,
) -> bool {
    if type_code != Some(4) {
        return false;
    }

    latitude
        .zip(longitude)
        .map(|(latitude, longitude)| latitude != 0.0 || longitude != 0.0)
        .unwrap_or(false)
}

fn embedded_preview_json(row: &SqliteStatement<'_>, index: i32) -> Value {
    const MAX_PREVIEW_BYTES: usize = 256 * 1024;

    let Some(blob) = row.blob(index) else {
        return Value::Null;
    };

    let Some((mime, offset, end)) = embedded_image_range(&blob) else {
        return Value::Null;
    };

    let preview = &blob[offset..end];
    if preview.is_empty() || preview.len() > MAX_PREVIEW_BYTES {
        return Value::Null;
    }

    json!({
        "mime": mime,
        "encoding": "base64",
        "data": base64::engine::general_purpose::STANDARD.encode(preview),
        "source": "ZWAMEDIAITEM.ZMETADATA",
        "offset": offset,
        "length": preview.len(),
    })
}

fn embedded_image_range(blob: &[u8]) -> Option<(&'static str, usize, usize)> {
    if let Some(start) = find_bytes(blob, &[0xff, 0xd8, 0xff]) {
        if let Some(relative_end) = find_bytes(&blob[start + 2..], &[0xff, 0xd9]) {
            return Some(("image/jpeg", start, start + 2 + relative_end + 2));
        }
    }

    if let Some(start) = find_bytes(blob, b"\x89PNG\r\n\x1a\n") {
        if let Some(relative_iend) = find_bytes(&blob[start..], b"IEND") {
            return Some(("image/png", start, start + relative_iend + 8));
        }
    }

    if let Some(start) = find_bytes(blob, b"RIFF") {
        if blob.len() >= start + 12 && &blob[start + 8..start + 12] == b"WEBP" {
            let size = u32::from_le_bytes([
                blob[start + 4],
                blob[start + 5],
                blob[start + 6],
                blob[start + 7],
            ]) as usize;
            let end = start.saturating_add(8).saturating_add(size);
            if end <= blob.len() {
                return Some(("image/webp", start, end));
            }
        }
    }

    None
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }

    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn source_json(cfg: &WhatsAppConfig, evidence: &SqliteEvidence, table: &str, rowid: i64) -> Value {
    json!({
        "path": evidence.source_label(),
        "table": table,
        "rowid": rowid,
        "schema_variant": cfg.schema_variant,
        "parser_confidence": "compatible_schema",
        "copied_sidecars": evidence.copied_sidecars(),
        "files": evidence
            .source_files()
            .iter()
            .map(|file| {
                json!({
                    "role": &file.role,
                    "path": &file.path,
                    "artifact_id": file.artifact_id,
                    "system_file_id": file.system_file_id,
                    "fs_identifier": file.fs_identifier,
                })
            })
            .collect::<Vec<_>>(),
    })
}

fn blob_length_column(
    joined: bool,
    schema: &SqliteSchema,
    table: &str,
    alias: &str,
    column: &str,
    output_alias: &str,
) -> String {
    if joined && schema.has_column(table, column) {
        format!("length({alias}.{column}) AS {output_alias}")
    } else {
        format!("NULL AS {output_alias}")
    }
}

fn select_joined_column(
    joined: bool,
    schema: &SqliteSchema,
    table: &str,
    alias: &str,
    column: &str,
    output_alias: &str,
) -> String {
    if joined {
        select_column(schema, table, alias, column, output_alias)
    } else {
        format!("NULL AS {output_alias}")
    }
}

fn direction_label(is_from_me: Option<bool>) -> &'static str {
    match is_from_me {
        Some(true) => "outgoing",
        Some(false) => "incoming",
        None => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::IosWhatsAppParser;
    use crate::Parser;
    use crate::core::ParserInput;
    use crate::parsers::mobile::sqlite::SqliteConnection;
    use anyhow::Result;

    #[test]
    fn parses_synthetic_chatstorage() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let db_path = tempdir.path().join("ChatStorage.sqlite");

        {
            let conn = SqliteConnection::create_for_test(&db_path)?;
            conn.execute_batch(
                r#"
                CREATE TABLE ZWACHATSESSION (
                    Z_PK INTEGER PRIMARY KEY,
                    ZCONTACTJID VARCHAR,
                    ZPARTNERNAME VARCHAR,
                    ZSESSIONTYPE INTEGER,
                    ZLASTMESSAGEDATE TIMESTAMP
                );

                CREATE TABLE ZWAMESSAGE (
                    Z_PK INTEGER PRIMARY KEY,
                    ZISFROMME INTEGER,
                    ZMESSAGETYPE INTEGER,
                    ZMESSAGESTATUS INTEGER,
                    ZCHATSESSION INTEGER,
                    ZMEDIAITEM INTEGER,
                    ZMESSAGEDATE TIMESTAMP,
                    ZSENTDATE TIMESTAMP,
                    ZSTANZAID VARCHAR,
                    ZTEXT VARCHAR
                );

                CREATE TABLE ZWAMEDIAITEM (
                    Z_PK INTEGER PRIMARY KEY,
                    ZMESSAGE INTEGER,
                    ZMEDIALOCALPATH VARCHAR,
                    ZFILESIZE INTEGER
                );

                INSERT INTO ZWACHATSESSION (
                    Z_PK,
                    ZCONTACTJID,
                    ZPARTNERNAME,
                    ZSESSIONTYPE,
                    ZLASTMESSAGEDATE
                ) VALUES (1, '15551234567@s.whatsapp.net', 'Example Chat', 0, 0);

                INSERT INTO ZWAMEDIAITEM (
                    Z_PK,
                    ZMESSAGE,
                    ZMEDIALOCALPATH,
                    ZFILESIZE
                ) VALUES (2, 10, 'Message/Media/example.jpg', 1234);

                INSERT INTO ZWAMEDIAITEM (
                    Z_PK,
                    ZMESSAGE,
                    ZMEDIALOCALPATH,
                    ZFILESIZE
                ) VALUES (3, 11, 'Message/Media/not-an-attachment.jpg', 0);

                INSERT INTO ZWAMESSAGE (
                    Z_PK,
                    ZISFROMME,
                    ZMESSAGETYPE,
                    ZMESSAGESTATUS,
                    ZCHATSESSION,
                    ZMEDIAITEM,
                    ZMESSAGEDATE,
                    ZSENTDATE,
                    ZSTANZAID,
                    ZTEXT
                ) VALUES (10, 1, 1, 8, 1, 2, 0, 1, 'ABC123', 'hello');

                INSERT INTO ZWAMESSAGE (
                    Z_PK,
                    ZISFROMME,
                    ZMESSAGETYPE,
                    ZMESSAGESTATUS,
                    ZCHATSESSION,
                    ZMEDIAITEM,
                    ZMESSAGEDATE,
                    ZSENTDATE,
                    ZSTANZAID,
                    ZTEXT
                ) VALUES (11, 0, 0, 8, 1, 3, 2, 3, 'TEXT123', 'plain text');
                "#,
            )?;
        }

        let parser = IosWhatsAppParser;
        let mut objects = Vec::new();
        parser.run_into(ParserInput::Path(db_path), &mut |object| {
            objects.push(object);
            Ok(())
        })?;

        assert_eq!(objects.len(), 4);
        assert_eq!(objects[0].kind, "mobile.communication.chat");
        assert_eq!(objects[1].kind, "mobile.communication.message");
        assert_eq!(objects[2].kind, "mobile.communication.attachment");
        assert_eq!(objects[3].kind, "mobile.communication.message");
        assert_eq!(objects[1].json["direction"], "outgoing");
        assert_eq!(objects[1].json["schema"], "chat.v1");
        assert_eq!(objects[1].json["app"]["label"], "WhatsApp");
        assert_eq!(objects[1].json["body"], "hello");
        assert_eq!(objects[1].json["details"]["message"]["stanza_id"], "ABC123");
        assert_eq!(
            objects[1].json["timestamps"]["message"]["rfc3339"],
            "2001-01-01T00:00:00+00:00"
        );
        assert_eq!(objects[1].json["details"]["media"]["file_size"], 1234);
        assert_eq!(objects[2].json["attachment"]["kind"], "image");
        assert_eq!(
            objects[2].json["attachment"]["local_path"],
            "Message/Media/example.jpg"
        );
        assert_eq!(objects[2].json["message"]["rowid"], 10);
        assert_eq!(objects[3].json["details"]["message"]["type_family"], "text");
        assert_eq!(objects[3].json["body"], "plain text");

        Ok(())
    }
}
