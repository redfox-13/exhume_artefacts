//! SQLCipher access using an already recovered database key.
//!
//! Enable the `sqlcipher` Cargo feature to build the encrypted database backend.
//! Keys are raw 256-bit database keys, not passwords or DPAPI master keys.
//! The inspection helper operates on a temporary evidence copy; it neither
//! migrates the database nor exports a plaintext copy. Later artefact parsers
//! can use the same internal SQLite connection and evidence helpers.

use crate::ParserInput;
use crate::formats::sqlite::{SqliteConnection, SqliteEvidence};
use serde::Serialize;
use std::fmt;
use zeroize::Zeroizing;

/// A raw 256-bit SQLCipher key, erased on drop and redacted in debug output.
/// Deliberately neither `Clone` nor `Serialize`.
pub struct SqlCipherKey(Zeroizing<[u8; 32]>);

impl SqlCipherKey {
    /// Decode exactly 64 ASCII hexadecimal characters. Prefixes, whitespace,
    /// passphrases and SQL expressions are not accepted.
    pub fn from_hex(encoded: &[u8]) -> Result<Self, SqlCipherError> {
        let mut bytes = Zeroizing::new([0; 32]);
        hex::decode_to_slice(encoded, bytes.as_mut()).map_err(|_| SqlCipherError::InvalidKey)?;
        Ok(Self(bytes))
    }

    /// Accept a recovered raw key, for example from a future DPAPI resolver.
    /// The caller is responsible for erasing any other copies it holds.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    // sqlite3_key interprets arbitrary bytes as a passphrase. Its raw-key
    // protocol instead requires x'<64 hex digits>', even through the C API.
    #[cfg(feature = "sqlcipher")]
    pub(crate) fn raw_key_literal(&self) -> Zeroizing<[u8; 67]> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut literal = Zeroizing::new([0; 67]);
        literal[..2].copy_from_slice(b"x'");
        for (index, byte) in self.0.iter().enumerate() {
            literal[2 + index * 2] = HEX[usize::from(byte >> 4)];
            literal[3 + index * 2] = HEX[usize::from(byte & 15)];
        }
        literal[66] = b'\'';
        literal
    }
}

impl fmt::Debug for SqlCipherKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SqlCipherKey")
            .field(&format_args!("[REDACTED; {} bytes]", self.0.len()))
            .finish()
    }
}

/// Supported standard SQLCipher settings. Applied per connection; no global
/// defaults or automatic migrations. Custom cipher settings are not supported.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SqlCipherProfile {
    #[serde(rename = "3")]
    SqlCipher3,
    #[default]
    #[serde(rename = "4")]
    SqlCipher4,
}

impl SqlCipherProfile {
    #[cfg(feature = "sqlcipher")]
    pub(crate) fn settings(self) -> &'static str {
        match self {
            Self::SqlCipher3 => "PRAGMA cipher_compatibility = 3;",
            Self::SqlCipher4 => "PRAGMA cipher_compatibility = 4;",
        }
    }
}

/// Errors never contain submitted key material. A read failure cannot reliably
/// distinguish an incorrect key from incompatible settings or damaged evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlCipherError {
    InvalidKey,
    Unavailable,
    KeySetupFailed,
    UnreadableDatabase,
}

impl fmt::Display for SqlCipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidKey => "database key must contain exactly 64 hexadecimal characters",
            Self::Unavailable => "SQLCipher is unavailable; rebuild with the 'sqlcipher' Cargo feature and a SQLCipher backend",
            Self::KeySetupFailed => "failed to configure the SQLCipher database key",
            Self::UnreadableDatabase => "cannot read encrypted database: the key or cipher profile may be incorrect, or the evidence may be damaged",
        })
    }
}

impl std::error::Error for SqlCipherError {}

/// A schema-access check, not a full integrity check or message extraction.
#[derive(Debug, Serialize)]
pub struct SqlCipherInspection {
    pub source: String,
    pub cipher_profile: SqlCipherProfile,
    pub copied_sidecars: Vec<String>,
    pub tables: Vec<String>,
}

/// Verify schema access on a working copy and list tables without loading
/// application-specific virtual-table modules. Source files are never opened
/// for writing. The temporary copy and connection are released before return.
pub fn inspect_database(
    input: ParserInput<'_>,
    key: &SqlCipherKey,
    profile: SqlCipherProfile,
) -> anyhow::Result<SqlCipherInspection> {
    if !cfg!(feature = "sqlcipher") {
        return Err(SqlCipherError::Unavailable.into());
    }
    let evidence = SqliteEvidence::from_input(input, "database.sqlite")?;
    let connection = SqliteConnection::open_encrypted(evidence.path(), key, profile)?;
    let mut tables = Vec::new();
    connection.query_rows(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name;",
        |row| {
            if let Some(name) = row.text(0) {
                tables.push(name);
            }
            Ok(())
        },
    )?;
    Ok(SqlCipherInspection {
        source: evidence.source_label(),
        cipher_profile: profile,
        copied_sidecars: evidence.copied_sidecars().to_vec(),
        tables,
    })
}

#[cfg(test)]
mod tests;
