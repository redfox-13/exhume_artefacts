//! Verify a recovered raw database key and list readable tables.
//!
//! ```text
//! cargo run --features sqlcipher --example inspect_sqlcipher -- \
//!   --file /evidence/Signal/sql/db.sqlite \
//!   --option 'database_key=<64-hex-characters>' \
//!   --option cipher_version=4 \
//!   --companion sqlite_wal=/evidence/Signal/sql/db.sqlite-wal
//! ```
//!
//! Sibling WAL/SHM files are discovered automatically for local inputs. Explicit
//! companion arguments override discovery. Key values use the existing secret
//! option machinery; shell history and process arguments remain outside its
//! memory-erasure guarantees. This example reports schema access only, not
//! Signal messages or full database integrity. It performs no key recovery.
//!
//! The `sqlcipher` feature bundles SQLCipher. On macOS it uses CommonCrypto;
//! Linux/Windows builds need OpenSSL development files discoverable by the
//! libsqlite3-sys build (OPENSSL_DIR or OPENSSL_LIB_DIR/OPENSSL_INCLUDE_DIR).
//! Cargo unifies this native library with SQLx in embedding applications.

use anyhow::{Context, Result, bail};
use clap::{Arg, ArgMatches, Command};
use exhume_artefacts::sqlcipher::{SqlCipherKey, SqlCipherProfile, inspect_database};
use exhume_artefacts::{
    CompanionSpec, ObjectParsed, Parser, ParserContext, ParserInput, ParserInputError, ParserIssue,
    ParserOptionDefault, ParserOptionSpec, ParserOptionType, ParserOptionValue, ParserOptions, cli,
    input, run_parser_with_options,
};
use std::path::Path;

const OPTIONS: &[ParserOptionSpec] = &[
    ParserOptionSpec {
        name: "database_key",
        label: "Database key",
        description: "Raw SQLCipher database key: exactly 64 hexadecimal characters",
        value_type: ParserOptionType::Secret,
        // Conditional so a future parser can try a key resolver before asking.
        required: false,
        default: None,
    },
    ParserOptionSpec {
        name: "cipher_version",
        label: "SQLCipher compatibility version",
        description: "Standard SQLCipher settings: 3 or 4 (no migration)",
        value_type: ParserOptionType::Integer,
        required: false,
        default: Some(ParserOptionDefault::Integer(4)),
    },
];

const COMPANIONS: &[CompanionSpec] = &[
    CompanionSpec::optional_suffix("sqlite_wal", "-wal"),
    CompanionSpec::optional_suffix("sqlite_shm", "-shm"),
];

struct DatabaseInspector;

impl Parser for DatabaseInspector {
    fn name(&self) -> &'static str {
        "sqlcipher_inspect"
    }

    fn description(&self) -> &'static str {
        "Verify schema access with a recovered database key and list tables."
    }

    fn option_specs(&self) -> &'static [ParserOptionSpec] {
        OPTIONS
    }

    fn companion_specs(&self) -> &'static [CompanionSpec] {
        COMPANIONS
    }

    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        run_parser_with_options(self, input, ParserOptions::default(), sink, &mut |_| Ok(()))
    }

    fn run_into_with_context(
        &self,
        input: ParserInput,
        context: &ParserContext,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
        _diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
    ) -> Result<()> {
        let (key, profile) = settings(context)?;
        let inspection = inspect_database(input, &key, profile)?;
        sink(ObjectParsed {
            parser: self.name(),
            kind: "sqlite.schema",
            text: String::new(),
            json: serde_json::to_value(inspection)?,
        })
    }
}

fn settings(context: &ParserContext) -> Result<(SqlCipherKey, SqlCipherProfile)> {
    if context.parser_name() != DatabaseInspector.name() {
        return Err(ParserInputError::invalid("context", "parser context mismatch").into());
    }
    let key = SqlCipherKey::from_hex(context.require_secret("database_key")?)
        .map_err(|error| ParserInputError::invalid("database_key", error.to_string()))?;
    let profile = match context.option("cipher_version") {
        Some(ParserOptionValue::Integer(3)) => SqlCipherProfile::SqlCipher3,
        Some(ParserOptionValue::Integer(4)) => SqlCipherProfile::SqlCipher4,
        _ => return Err(ParserInputError::invalid("cipher_version", "expected 3 or 4").into()),
    };
    Ok((key, profile))
}

fn command() -> Command {
    cli::configuration_arguments(
        Command::new("inspect_sqlcipher")
            .about(DatabaseInspector.description())
            .arg(
                Arg::new("file")
                    .long("file")
                    .value_name("PATH")
                    .required_unless_present("describe_parser"),
            ),
    )
}

fn run(mut matches: ArgMatches) -> Result<()> {
    if let Some(name) = matches.get_one::<String>("describe_parser") {
        if name != DatabaseInspector.name() {
            bail!("unknown parser");
        }
        return cli::print_description(&DatabaseInspector);
    }
    let options = cli::parser_options(&mut matches, OPTIONS)?;
    let context = ParserContext::new(DatabaseInspector.name(), OPTIONS, options)?;
    // Validate/request the key before accessing evidence, as a UI caller would.
    let (key, profile) = settings(&context)?;
    let source = matches.get_one::<String>("file").context("missing file")?;
    let input = input::local_input(
        &DatabaseInspector,
        Path::new(source),
        &cli::companion_overrides(&matches)?,
    )?;
    let inspection = inspect_database(input, &key, profile)?;
    println!("{}", serde_json::to_string(&inspection)?);
    Ok(())
}

fn main() -> std::process::ExitCode {
    cli::finish(run(command().get_matches()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use exhume_artefacts::ParserInputReason;

    #[test]
    fn cli_requests_a_missing_key_before_accessing_evidence() {
        let matches = command()
            .try_get_matches_from(["inspect_sqlcipher", "--file", "/nonexistent"])
            .unwrap();
        let error = run(matches).unwrap_err();
        let Some(ParserInputError::NeedsInput { requests }) = error.downcast_ref() else {
            panic!("expected a structured input request: {error}");
        };
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].name, "database_key");
        assert_eq!(requests[0].reason, ParserInputReason::Missing);
    }

    #[test]
    fn cli_rejects_invalid_keys_without_echoing_them() {
        let matches = command()
            .try_get_matches_from([
                "inspect_sqlcipher",
                "--file",
                "/nonexistent",
                "--option",
                "database_key=do-not-echo-this-key",
            ])
            .unwrap();
        let error = run(matches).unwrap_err();
        assert!(
            matches!(error.downcast_ref(), Some(ParserInputError::InvalidConfiguration { option, .. }) if option == "database_key")
        );
        assert!(!format!("{error:?}").contains("do-not-echo-this-key"));
    }

    #[test]
    fn cli_validates_the_profile_before_accessing_evidence() {
        let matches = command()
            .try_get_matches_from([
                "inspect_sqlcipher",
                "--file",
                "/nonexistent",
                "--option",
                "database_key=0000000000000000000000000000000000000000000000000000000000000000",
                "--option",
                "cipher_version=2",
            ])
            .unwrap();
        let error = run(matches).unwrap_err();
        assert!(
            matches!(error.downcast_ref(), Some(ParserInputError::InvalidConfiguration { option, .. }) if option == "cipher_version")
        );
    }
}
