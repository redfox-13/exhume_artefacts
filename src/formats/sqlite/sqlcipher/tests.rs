use super::*;

const KEY_HEX: &[u8; 64] = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

#[test]
fn keys_accept_exact_hex_or_recovered_bytes_and_redact_debug() {
    let lower = SqlCipherKey::from_hex(KEY_HEX).unwrap();
    let upper = SqlCipherKey::from_hex(&KEY_HEX.to_ascii_uppercase()).unwrap();
    let recovered = SqlCipherKey::from_bytes(*lower.0);
    assert_eq!(*lower.0, *upper.0);
    assert_eq!(*lower.0, *recovered.0);
    let debug = format!("{lower:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains(std::str::from_utf8(KEY_HEX).unwrap()));
}

#[test]
fn malformed_keys_are_rejected_without_disclosing_values() {
    for encoded in [
        vec![],
        vec![b'0'; 63],
        vec![b'0'; 65],
        vec![b'z'; 64],
        [b"0x".as_slice(), KEY_HEX].concat(),
        [KEY_HEX.as_slice(), b"\n"].concat(),
        [b"x'".as_slice(), KEY_HEX, b"'"].concat(),
        [vec![b'0'; 63], vec![0]].concat(),
    ] {
        let error = SqlCipherKey::from_hex(&encoded).unwrap_err();
        assert_eq!(error, SqlCipherError::InvalidKey);
        assert_eq!(
            error.to_string(),
            "database key must contain exactly 64 hexadecimal characters"
        );
    }
}

#[cfg(not(feature = "sqlcipher"))]
#[test]
fn missing_backend_is_explicit_and_does_not_access_evidence() {
    let key = SqlCipherKey::from_hex(KEY_HEX).unwrap();
    let error = inspect_database(
        ParserInput::Path("/nonexistent/sqlcipher-test.db".into()),
        &key,
        SqlCipherProfile::default(),
    )
    .unwrap_err();
    assert_eq!(error.downcast_ref(), Some(&SqlCipherError::Unavailable));
    let error = SqliteConnection::open_encrypted(
        std::path::Path::new("/nonexistent/sqlcipher-test.db"),
        &key,
        SqlCipherProfile::default(),
    )
    .err()
    .unwrap();
    assert_eq!(error.downcast_ref(), Some(&SqlCipherError::Unavailable));
}

#[cfg(feature = "sqlcipher")]
mod encrypted {
    use super::*;
    use crate::{CompoundParserInput, ParserFileProvider, ParserSource};
    use anyhow::Result;
    use std::{
        collections::BTreeMap,
        fs,
        io::{Cursor, Write},
        path::Path,
    };

    // Build fixtures using the documented SQL interface, independently of the
    // production sqlite3_key wrapper. This catches raw-key/passphrase mistakes.
    fn fixture(path: &Path, profile: SqlCipherProfile) -> Result<SqliteConnection> {
        let connection = SqliteConnection::create_for_test(path)?;
        connection.execute_batch(
            "PRAGMA key = \"x'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'\";",
        )?;
        connection.execute_batch(match profile {
            SqlCipherProfile::SqlCipher3 => "PRAGMA cipher_compatibility = 3;",
            SqlCipherProfile::SqlCipher4 => "PRAGMA cipher_compatibility = 4;",
        })?;
        connection.execute_batch(
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT);
             INSERT INTO messages VALUES (1, 'first test message');",
        )?;
        Ok(connection)
    }

    fn messages(connection: &SqliteConnection) -> Result<Vec<String>> {
        let mut rows = Vec::new();
        connection.query_rows("SELECT body FROM messages ORDER BY id;", |row| {
            rows.push(row.text(0).unwrap());
            Ok(())
        })?;
        Ok(rows)
    }

    #[test]
    fn opens_both_profiles_with_raw_keys_and_queries_only_working_copies() -> Result<()> {
        let key = SqlCipherKey::from_hex(KEY_HEX)?;
        for profile in [SqlCipherProfile::SqlCipher3, SqlCipherProfile::SqlCipher4] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("db.sqlite");
            drop(fixture(&path, profile)?);
            let original = fs::read(&path)?;
            assert!(!original.starts_with(b"SQLite format 3"));
            assert!(
                !original
                    .windows(b"first test message".len())
                    .any(|w| w == b"first test message")
            );

            {
                let evidence =
                    SqliteEvidence::from_input(ParserInput::Path(path.clone()), "db.sqlite")?;
                assert_ne!(evidence.path(), path);
                let connection = SqliteConnection::open_encrypted(evidence.path(), &key, profile)?;
                assert_eq!(messages(&connection)?, ["first test message"]);
                assert!(connection.execute_batch("DELETE FROM messages;").is_err());
                assert_eq!(messages(&connection)?, ["first test message"]);
            }
            let inspection = inspect_database(ParserInput::Path(path.clone()), &key, profile)?;
            assert_eq!(inspection.tables, ["messages"]);
            assert_eq!(inspection.cipher_profile, profile);
            assert_eq!(inspection.source, path.to_string_lossy());
            assert_eq!(fs::read(&path)?, original);
        }
        Ok(())
    }

    #[test]
    fn wrong_key_profile_and_damage_are_read_errors_without_key_disclosure() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("db.sqlite");
        drop(fixture(&path, SqlCipherProfile::SqlCipher4)?);
        let bytes = fs::read(&path)?;
        let key = SqlCipherKey::from_hex(KEY_HEX)?;
        let wrong = SqlCipherKey::from_bytes([0xff; 32]);
        for (input, key, profile) in [
            (bytes.clone(), &wrong, SqlCipherProfile::SqlCipher4),
            (bytes.clone(), &key, SqlCipherProfile::SqlCipher3),
            (bytes[..32].to_vec(), &key, SqlCipherProfile::SqlCipher4),
            (vec![], &key, SqlCipherProfile::SqlCipher4),
        ] {
            let error = inspect_database(ParserInput::Bytes(input), key, profile).unwrap_err();
            assert_eq!(
                error.downcast_ref(),
                Some(&SqlCipherError::UnreadableDatabase)
            );
            assert!(error.downcast_ref::<crate::ParserInputError>().is_none());
            assert!(!format!("{error:?}").contains(std::str::from_utf8(KEY_HEX)?));
            assert!(!format!("{error:?}").contains(&"ff".repeat(32)));
        }
        let error = inspect_database(
            ParserInput::Path(path.clone()),
            &wrong,
            SqlCipherProfile::SqlCipher4,
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref(),
            Some(&SqlCipherError::UnreadableDatabase)
        );
        assert_eq!(fs::read(path)?, bytes);
        Ok(())
    }

    #[test]
    fn key_is_required_to_read_encrypted_data_and_plain_databases_still_work() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let encrypted = directory.path().join("encrypted.sqlite");
        drop(fixture(&encrypted, SqlCipherProfile::SqlCipher4)?);
        let evidence = SqliteEvidence::from_input(ParserInput::Path(encrypted), "db.sqlite")?;
        assert!(SqliteConnection::open(evidence.path())?.schema().is_err());

        let plain = directory.path().join("plain.sqlite");
        let connection = SqliteConnection::create_for_test(&plain)?;
        connection.execute_batch("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT); INSERT INTO messages VALUES (1, 'plain');")?;
        drop(connection);
        let evidence = SqliteEvidence::from_input(ParserInput::Path(plain.clone()), "db.sqlite")?;
        assert_eq!(
            messages(&SqliteConnection::open(evidence.path())?)?,
            ["plain"]
        );
        let error = inspect_database(
            ParserInput::Path(plain),
            &SqlCipherKey::from_hex(KEY_HEX)?,
            SqlCipherProfile::SqlCipher4,
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref(),
            Some(&SqlCipherError::UnreadableDatabase)
        );
        Ok(())
    }

    #[test]
    fn supports_bytes_and_seekable_inputs_without_creating_missing_databases() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("db.sqlite");
        drop(fixture(&path, SqlCipherProfile::SqlCipher4)?);
        let bytes = fs::read(path)?;
        let key = SqlCipherKey::from_hex(KEY_HEX)?;
        for input in [
            ParserInput::Bytes(bytes.clone()),
            ParserInput::ReadSeek(Box::new(Cursor::new(bytes))),
        ] {
            assert_eq!(
                inspect_database(input, &key, SqlCipherProfile::default())?.tables,
                ["messages"]
            );
        }
        let absent = directory.path().join("absent.sqlite");
        assert!(
            SqliteConnection::open_encrypted(&absent, &key, SqlCipherProfile::default()).is_err()
        );
        assert!(!absent.exists());
        Ok(())
    }

    struct MemoryProvider(BTreeMap<String, Vec<u8>>);
    impl ParserFileProvider for MemoryProvider {
        fn copy_to(&mut self, source: &ParserSource, output: &mut dyn Write) -> Result<()> {
            output.write_all(self.0.get(&source.original_path).unwrap())?;
            Ok(())
        }
    }

    #[test]
    fn committed_wal_records_survive_local_and_compound_inputs_without_shm() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("db.sqlite");
        let wal_path = directory.path().join("db.sqlite-wal");
        let shm_path = directory.path().join("db.sqlite-shm");
        let writer = fixture(&path, SqlCipherProfile::SqlCipher4)?;
        writer.execute_batch("PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0; INSERT INTO messages VALUES (2, 'only in WAL');")?;
        // Keep the writer open to prevent its close from checkpointing the WAL.
        let original = fs::read(&path)?;
        let wal = fs::read(&wal_path)?;
        let shm = fs::read(&shm_path)?;
        assert!(!wal.is_empty());
        let key = SqlCipherKey::from_hex(KEY_HEX)?;

        let base = SqliteEvidence::from_input(ParserInput::Bytes(original.clone()), "db.sqlite")?;
        assert_eq!(
            messages(&SqliteConnection::open_encrypted(
                base.path(),
                &key,
                SqlCipherProfile::default()
            )?)?,
            ["first test message"]
        );

        let primary = ParserSource::new(
            "primary",
            "/Signal/sql/db.sqlite",
            Some(7),
            Some(11),
            Some(13),
        );
        let sidecar = ParserSource::new(
            "sqlite_wal",
            "/Signal/sql/db.sqlite-wal",
            Some(8),
            Some(12),
            Some(14),
        );
        let provider = MemoryProvider(BTreeMap::from([
            (primary.original_path.clone(), original.clone()),
            (sidecar.original_path.clone(), wal.clone()),
        ]));
        let compound = ParserInput::Compound(CompoundParserInput {
            primary,
            companions: vec![sidecar],
            provider: Box::new(provider),
        });
        for input in [ParserInput::Path(path.clone()), compound] {
            let evidence = SqliteEvidence::from_input(input, "db.sqlite")?;
            assert!(evidence.copied_sidecars().iter().any(|s| s == "wal"));
            if evidence.source_label().starts_with("/Signal/") {
                assert_eq!(evidence.source_files().len(), 2);
                assert_eq!(evidence.source_files()[0].artifact_id, Some(7));
                assert_eq!(evidence.source_files()[1].fs_identifier, Some(14));
            }
            let connection = SqliteConnection::open_encrypted(
                evidence.path(),
                &key,
                SqlCipherProfile::default(),
            )?;
            assert_eq!(
                messages(&connection)?,
                ["first test message", "only in WAL"]
            );
        }
        assert_eq!(fs::read(&path)?, original);
        assert_eq!(fs::read(wal_path)?, wal);
        assert_eq!(fs::read(shm_path)?, shm);
        drop(writer);
        Ok(())
    }
}
