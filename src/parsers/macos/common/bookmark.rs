//! Decoder for Apple "bookmark data" blobs (magic `book`).
//!
//! Bookmarks embed a durable reference to a file: a TOC of typed, length-tagged
//! values keyed by well-known constants. We extract the forensically useful
//! subset — the target path components, volume path/name and target flags —
//! without pulling in an external crate. Layout references: Apple `CFURL`
//! bookmark data / the `mac_alias` project.

use std::collections::HashMap;

// Well-known bookmark key constants.
const KEY_PATH: u32 = 0x1004; // array of path component strings
const KEY_CNID_PATH: u32 = 0x1005; // array of CNIDs (parallel to KEY_PATH)
const KEY_FILE_PROPERTIES: u32 = 0x1010; // data: target flags bitfield
const KEY_VOLUME_PATH: u32 = 0x2002;
const KEY_VOLUME_NAME: u32 = 0x2010;
const KEY_VOLUME_URL: u32 = 0x2005;

// Type tags (high two bytes select the family; low byte a subtype).
const TYPE_STRING: u32 = 0x0101;
const TYPE_ARRAY: u32 = 0x0601;

/// The decoded, forensically useful fields of a bookmark.
#[derive(Debug, Clone, Default)]
pub(crate) struct BookmarkTarget {
    /// Absolute POSIX path reconstructed from the path-component array.
    pub path: Option<String>,
    pub components: Vec<String>,
    /// Last path component, when present.
    pub file_name: Option<String>,
    pub volume_path: Option<String>,
    pub volume_name: Option<String>,
    pub volume_url: Option<String>,
    /// Number of CNIDs in the parallel inode-path array, if present.
    pub cnid_count: Option<usize>,
}

/// Decode a bookmark blob. Returns `None` if the magic/header is not a bookmark.
pub(crate) fn decode_bookmark(data: &[u8]) -> Option<BookmarkTarget> {
    if data.len() < 16 || &data[0..4] != b"book" {
        return None;
    }
    // data[4..8] = total size, data[8..12] = version, data[12..16] = header size.
    let hdrsize = read_u32(data, 12)? as usize;
    if hdrsize < 16 || hdrsize > data.len() {
        return None;
    }
    let body = data.get(hdrsize..)?;
    // The first TOC offset (relative to the body start) is the first u32 of body.
    let first_toc = read_u32(body, 0)? as usize;

    let mut values: HashMap<u32, usize> = HashMap::new();
    let mut toc_offset = first_toc;
    let mut guard = 0;
    while toc_offset != 0 && guard < 64 {
        guard += 1;
        let toc = body.get(toc_offset..)?;
        if toc.len() < 20 {
            break;
        }
        // toc[0..4] size, toc[4..8] magic 0xfffffffe, toc[8..12] id,
        // toc[12..16] next TOC, toc[16..20] entry count.
        if read_u32(toc, 4)? != 0xffff_fffe {
            break;
        }
        let next_toc = read_u32(toc, 12)? as usize;
        let count = read_u32(toc, 16)? as usize;
        for i in 0..count {
            let base = 20 + i * 12;
            let key = read_u32(toc, base)?;
            let offset = read_u32(toc, base + 4)? as usize;
            // Keys with the high bit set are string-keyed extension records; skip.
            if key & 0x8000_0000 != 0 {
                continue;
            }
            values.insert(key, offset);
        }
        toc_offset = next_toc;
    }

    let mut target = BookmarkTarget::default();

    if let Some(&off) = values.get(&KEY_PATH) {
        if let Some(offsets) = read_array_offsets(body, off) {
            let components: Vec<String> = offsets
                .iter()
                .filter_map(|&o| read_string(body, o))
                .collect();
            if !components.is_empty() {
                target.file_name = components.last().cloned();
                target.path = Some(format!("/{}", components.join("/")));
                target.components = components;
            }
        }
    }
    if let Some(&off) = values.get(&KEY_CNID_PATH) {
        if let Some(offsets) = read_array_offsets(body, off) {
            target.cnid_count = Some(offsets.len());
        }
    }
    target.volume_path = values
        .get(&KEY_VOLUME_PATH)
        .and_then(|&o| read_string(body, o));
    target.volume_name = values
        .get(&KEY_VOLUME_NAME)
        .and_then(|&o| read_string(body, o));
    target.volume_url = values
        .get(&KEY_VOLUME_URL)
        .and_then(|&o| read_string(body, o));
    let _ = KEY_FILE_PROPERTIES; // reserved for future flag decoding

    Some(target)
}

/// Read a TLV string value at `offset` within the bookmark body.
fn read_string(body: &[u8], offset: usize) -> Option<String> {
    let (typ, data) = read_tlv(body, offset)?;
    if typ == TYPE_STRING {
        Some(String::from_utf8_lossy(data).into_owned())
    } else {
        None
    }
}

/// Read a TLV array-of-offsets value at `offset` within the bookmark body.
fn read_array_offsets(body: &[u8], offset: usize) -> Option<Vec<usize>> {
    let (typ, data) = read_tlv(body, offset)?;
    if typ != TYPE_ARRAY {
        return None;
    }
    Some(
        data.chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as usize)
            .collect(),
    )
}

/// Read a length-tagged TLV record: `[len: u32][type: u32][bytes; len]`.
fn read_tlv(body: &[u8], offset: usize) -> Option<(u32, &[u8])> {
    let len = read_u32(body, offset)? as usize;
    let typ = read_u32(body, offset + 4)?;
    let start = offset + 8;
    let data = body.get(start..start.checked_add(len)?)?;
    Some((typ, data))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let b = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Test helpers shared with other parser modules' unit tests.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::{KEY_PATH, TYPE_ARRAY, TYPE_STRING};

    /// Build a minimal bookmark blob with a single path-component array
    /// (`Users`, `alice`, `Report.pdf`) so the decoder — and any parser that
    /// consumes bookmarks — can be exercised without a real macOS fixture.
    pub(crate) fn synthetic_bookmark() -> Vec<u8> {
        let header_size = 48usize;
        let mut body: Vec<u8> = Vec::new();

        // Placeholder for the first-TOC offset; filled in once we know it.
        body.extend_from_slice(&0u32.to_le_bytes());

        // Emit the three component strings as TLV records, remembering offsets.
        let mut comp_offsets = Vec::new();
        for comp in ["Users", "alice", "Report.pdf"] {
            comp_offsets.push(body.len() as u32);
            let bytes = comp.as_bytes();
            body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            body.extend_from_slice(&TYPE_STRING.to_le_bytes());
            body.extend_from_slice(bytes);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }

        // The path array TLV: payload is the three component offsets.
        let array_offset = body.len() as u32;
        let mut array_payload = Vec::new();
        for off in &comp_offsets {
            array_payload.extend_from_slice(&off.to_le_bytes());
        }
        body.extend_from_slice(&(array_payload.len() as u32).to_le_bytes());
        body.extend_from_slice(&TYPE_ARRAY.to_le_bytes());
        body.extend_from_slice(&array_payload);

        // The TOC: one entry mapping KEY_PATH -> array_offset.
        let toc_offset = body.len() as u32;
        body.extend_from_slice(&0u32.to_le_bytes()); // size (unused by decoder)
        body.extend_from_slice(&0xffff_fffeu32.to_le_bytes()); // magic
        body.extend_from_slice(&0u32.to_le_bytes()); // id
        body.extend_from_slice(&0u32.to_le_bytes()); // next TOC
        body.extend_from_slice(&1u32.to_le_bytes()); // count
        body.extend_from_slice(&KEY_PATH.to_le_bytes());
        body.extend_from_slice(&array_offset.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes()); // reserved

        // Backpatch the first-TOC offset.
        body[0..4].copy_from_slice(&toc_offset.to_le_bytes());

        // Prepend the 48-byte header: magic, total size, version, header size.
        let total = (header_size + body.len()) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(b"book");
        out.extend_from_slice(&total.to_le_bytes());
        out.extend_from_slice(&0x1004_0000u32.to_le_bytes());
        out.extend_from_slice(&(header_size as u32).to_le_bytes());
        out.resize(header_size, 0);
        out.extend_from_slice(&body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tests_support::synthetic_bookmark;

    #[test]
    fn decodes_path_components() {
        let blob = synthetic_bookmark();
        let target = decode_bookmark(&blob).expect("decodes");
        assert_eq!(target.path.as_deref(), Some("/Users/alice/Report.pdf"));
        assert_eq!(target.file_name.as_deref(), Some("Report.pdf"));
        assert_eq!(target.components.len(), 3);
    }

    #[test]
    fn rejects_non_bookmark() {
        assert!(decode_bookmark(b"not a bookmark").is_none());
    }
}
