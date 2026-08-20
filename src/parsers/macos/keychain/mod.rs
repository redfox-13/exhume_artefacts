//! macOS Keychain parser (metadata-only).
//!
//! Handles both keychain formats found on macOS:
//! - **Legacy** `login.keychain-db` / `System.keychain` — the CSSM
//!   `AppleDatabase` binary format (magic `kych`). See [`legacy`].
//! - **Modern** `keychain-2.db` — a SQLite database used by `securityd`
//!   (`genp`/`inet`/`cert`/`keys` tables). See [`modern`].
//!
//! Secrets (`data` blobs, SEP-wrapped keys) are never decrypted; we extract
//! only item metadata (classes, accounts, services, servers, access groups,
//! timestamps, tombstone/sync flags).

pub(crate) mod legacy;
pub(crate) mod modern;

use crate::core::{CompanionSpec, ObjectParsed, Parser, ParserInput};
use crate::parsers::mobile::sqlite::SqliteEvidence;
use anyhow::{Result, bail};
use std::fs;

const PARSER_NAME: &str = "macos_keychain";
const SQLITE_COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

/// Emitted object kind for every keychain item, both formats.
pub(crate) const KEYCHAIN_ITEM_KIND: &str = "macos.keychain.item";

#[derive(Default)]
pub struct MacosKeychainParser;

impl Parser for MacosKeychainParser {
    fn name(&self) -> &'static str {
        PARSER_NAME
    }

    fn description(&self) -> &'static str {
        "Parse macOS keychains (legacy CSSM .keychain-db and modern SQLite keychain-2.db) for item metadata; secrets are left encrypted."
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        SQLITE_COMPANIONS
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        // Materialize the primary (and any -wal/-shm sidecars) to a temp file so
        // both the binary-format and SQLite paths can read it uniformly.
        let evidence = SqliteEvidence::from_input(input, "keychain")?;
        let header = read_header(evidence.path())?;

        if header.starts_with(b"kych") {
            let bytes = fs::read(evidence.path())?;
            legacy::parse(&bytes, &evidence, sink)
        } else if header.starts_with(b"SQLite format 3\0") {
            modern::parse(&evidence, sink)
        } else {
            bail!("not a supported macOS keychain (unknown magic)");
        }
    }
}

fn read_header(path: &std::path::Path) -> Result<[u8; 16]> {
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut header = [0u8; 16];
    // A keychain is always larger than 16 bytes; a short read means it is not one.
    file.read_exact(&mut header)?;
    Ok(header)
}
