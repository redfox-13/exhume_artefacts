//! SQLite connections and row access, including optional SQLCipher keying.

use super::schema::SqliteSchema;
use super::sqlcipher::{SqlCipherError, SqlCipherKey, SqlCipherProfile};
use anyhow::{Context, Result, bail};
use libsqlite3_sys as ffi;
use std::ffi::{CStr, CString};
#[cfg(feature = "sqlcipher")]
use std::fs;
use std::path::Path;
use std::ptr;

pub(crate) struct SqliteConnection {
    handle: *mut ffi::sqlite3,
}

impl SqliteConnection {
    /// Open a staged evidence copy using raw-key semantics. The caller must
    /// keep its SqliteEvidence alive until the connection has been dropped.
    pub(crate) fn open_encrypted(
        path: &Path,
        key: &SqlCipherKey,
        profile: SqlCipherProfile,
    ) -> Result<Self> {
        #[cfg(not(feature = "sqlcipher"))]
        {
            let _ = (path, key, profile);
            Err(SqlCipherError::Unavailable.into())
        }
        #[cfg(feature = "sqlcipher")]
        {
            // SQLite accepts a zero-byte file as a new database even without
            // CREATE. It cannot establish that a supplied key is correct.
            if fs::metadata(path)?.len() == 0 {
                return Err(SqlCipherError::UnreadableDatabase.into());
            }
            // No CREATE: a missing input must never become an empty database.
            // Read/write access is confined to the temporary copy so SQLite
            // can rebuild the WAL index when an SHM companion is absent.
            let conn =
                Self::open_with_flags(path, ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_NOMUTEX)?;
            conn.configure_cipher(key, profile)?;
            conn.execute_batch("PRAGMA query_only = ON; PRAGMA temp_store = MEMORY;")?;
            // Key setup is lazy. Force an actual page read before returning a
            // usable connection; SQLITE_NOTADB does not prove the key is wrong.
            conn.query_rows("SELECT count(*) FROM sqlite_master;", |_| Ok(()))
                .map_err(|_| SqlCipherError::UnreadableDatabase)?;
            Ok(conn)
        }
    }

    #[cfg(feature = "sqlcipher")]
    fn configure_cipher(&self, key: &SqlCipherKey, profile: SqlCipherProfile) -> Result<()> {
        let mut available = false;
        self.query_rows("PRAGMA cipher_version;", |row| {
            available = row.text(0).is_some_and(|version| !version.is_empty());
            Ok(())
        })?;
        if !available {
            return Err(SqlCipherError::Unavailable.into());
        }
        let literal = key.raw_key_literal();
        // SAFETY: self owns a live SQLite connection. The literal buffer is
        // valid for all 67 bytes during this call; sqlite3_key copies the key.
        // Calling the C API avoids embedding the secret in logged SQL text.
        let rc = unsafe { ffi::sqlite3_key(self.handle, literal.as_ptr().cast(), 67) };
        if rc != ffi::SQLITE_OK {
            return Err(SqlCipherError::KeySetupFailed.into());
        }
        self.execute_batch(profile.settings())?;
        Ok(())
    }

    pub(crate) fn open(path: &Path) -> Result<Self> {
        let conn =
            Self::open_with_flags(path, ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_NOMUTEX)?;
        conn.execute_batch("PRAGMA query_only = ON;")?;
        Ok(conn)
    }

    #[cfg(test)]
    pub(crate) fn create_for_test(path: &Path) -> Result<Self> {
        Self::open_with_flags(
            path,
            ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE | ffi::SQLITE_OPEN_NOMUTEX,
        )
    }

    fn open_with_flags(path: &Path, flags: i32) -> Result<Self> {
        let path = path.to_string_lossy();
        let path = CString::new(path.as_bytes()).context("SQLite path contains NUL byte")?;
        let mut handle = ptr::null_mut();
        let rc = unsafe { ffi::sqlite3_open_v2(path.as_ptr(), &mut handle, flags, ptr::null()) };

        if rc != ffi::SQLITE_OK {
            let message = if handle.is_null() {
                "failed to allocate SQLite handle".to_string()
            } else {
                sqlite_error(handle)
            };
            if !handle.is_null() {
                unsafe {
                    ffi::sqlite3_close(handle);
                }
            }
            bail!("failed to open SQLite database: {message}");
        }

        Ok(Self { handle })
    }

    pub(crate) fn execute_batch(&self, sql: &str) -> Result<()> {
        let sql = CString::new(sql).context("SQLite SQL contains NUL byte")?;
        let mut errmsg = ptr::null_mut();
        let rc = unsafe {
            ffi::sqlite3_exec(
                self.handle,
                sql.as_ptr(),
                None,
                ptr::null_mut(),
                &mut errmsg,
            )
        };

        if rc != ffi::SQLITE_OK {
            let message = if errmsg.is_null() {
                sqlite_error(self.handle)
            } else {
                let message = unsafe { CStr::from_ptr(errmsg).to_string_lossy().into_owned() };
                unsafe {
                    ffi::sqlite3_free(errmsg.cast());
                }
                message
            };
            bail!("SQLite execution failed: {message}");
        }

        Ok(())
    }

    pub(crate) fn query_rows(
        &self,
        sql: &str,
        mut row_fn: impl FnMut(&SqliteStatement<'_>) -> Result<()>,
    ) -> Result<()> {
        let mut statement = SqliteStatement::prepare(self, sql)?;
        while statement.step()? {
            row_fn(&statement)?;
        }
        Ok(())
    }

    pub(crate) fn schema(&self) -> Result<SqliteSchema> {
        SqliteSchema::load(self)
    }
}

impl Drop for SqliteConnection {
    fn drop(&mut self) {
        unsafe {
            ffi::sqlite3_close(self.handle);
        }
    }
}

pub(crate) struct SqliteStatement<'conn> {
    conn: &'conn SqliteConnection,
    stmt: *mut ffi::sqlite3_stmt,
}

impl<'conn> SqliteStatement<'conn> {
    fn prepare(conn: &'conn SqliteConnection, sql: &str) -> Result<Self> {
        let sql = CString::new(sql).context("SQLite SQL contains NUL byte")?;
        let mut stmt = ptr::null_mut();
        let rc = unsafe {
            ffi::sqlite3_prepare_v2(conn.handle, sql.as_ptr(), -1, &mut stmt, ptr::null_mut())
        };

        if rc != ffi::SQLITE_OK {
            bail!(
                "failed to prepare SQLite statement: {}",
                sqlite_error(conn.handle)
            );
        }

        Ok(Self { conn, stmt })
    }

    fn step(&mut self) -> Result<bool> {
        let rc = unsafe { ffi::sqlite3_step(self.stmt) };
        match rc {
            ffi::SQLITE_ROW => Ok(true),
            ffi::SQLITE_DONE => Ok(false),
            _ => bail!(
                "SQLite statement failed: {}",
                sqlite_error(self.conn.handle)
            ),
        }
    }

    pub(crate) fn i64(&self, index: i32) -> Option<i64> {
        if self.column_is_null(index) {
            None
        } else {
            Some(unsafe { ffi::sqlite3_column_int64(self.stmt, index) })
        }
    }

    pub(crate) fn f64(&self, index: i32) -> Option<f64> {
        if self.column_is_null(index) {
            None
        } else {
            Some(unsafe { ffi::sqlite3_column_double(self.stmt, index) })
        }
    }

    pub(crate) fn bool(&self, index: i32) -> Option<bool> {
        self.i64(index).map(|value| value != 0)
    }

    pub(crate) fn text(&self, index: i32) -> Option<String> {
        if self.column_is_null(index) {
            return None;
        }

        let ptr = unsafe { ffi::sqlite3_column_text(self.stmt, index) };
        if ptr.is_null() {
            return None;
        }

        let len = unsafe { ffi::sqlite3_column_bytes(self.stmt, index) };
        if len <= 0 {
            return Some(String::new());
        }

        let bytes = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    pub(crate) fn blob(&self, index: i32) -> Option<Vec<u8>> {
        if self.column_is_null(index) {
            return None;
        }

        let len = unsafe { ffi::sqlite3_column_bytes(self.stmt, index) };
        if len <= 0 {
            return Some(Vec::new());
        }

        let ptr = unsafe { ffi::sqlite3_column_blob(self.stmt, index) };
        if ptr.is_null() {
            return None;
        }

        let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len as usize) };
        Some(bytes.to_vec())
    }

    fn column_is_null(&self, index: i32) -> bool {
        unsafe { ffi::sqlite3_column_type(self.stmt, index) == ffi::SQLITE_NULL }
    }
}

impl Drop for SqliteStatement<'_> {
    fn drop(&mut self) {
        unsafe {
            ffi::sqlite3_finalize(self.stmt);
        }
    }
}

fn sqlite_error(handle: *mut ffi::sqlite3) -> String {
    unsafe {
        CStr::from_ptr(ffi::sqlite3_errmsg(handle))
            .to_string_lossy()
            .into_owned()
    }
}
