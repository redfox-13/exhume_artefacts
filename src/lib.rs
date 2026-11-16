//! Artefact parsing with reusable input, format and record support.
//!
//! - [`core`] defines parser contracts, invocation settings and output types.
//! - [`input`] assembles evidence sources and provides their contents.
//! - [`formats`] handles storage formats independently of concrete parsers.
//! - [`parsers`] contains platform entry points and the parser registry.
//!
//! Internal application engines are shared by platform entry points. Public
//! compatibility exports keep existing parser and SQLCipher import paths valid.

pub mod cli;
/// Core parsing traits, types, and shared functionality.
pub mod core;
/// Storage-format support shared by artefact parsers.
pub mod formats;
pub mod input;
/// Concrete parser implementations and the parser registry.
pub mod parsers;
/// Open SQLCipher evidence using an already recovered raw database key.
pub use formats::sqlite::sqlcipher;

use crate::parsers::ParserRegistry;
use anyhow::Result;
pub use core::{
    CompanionPathRule, CompanionSpec, CompoundParserInput, ObjectParsed, Parser,
    ParserFileProvider, ParserInfo, ParserInput, ParserIssue, ParserIssueCode, ParserSource,
    TimelineEvent,
};
pub use core::{
    ParserContext, ParserInputError, ParserInputReason, ParserInputRequest, ParserOptionDefault,
    ParserOptionSpec, ParserOptionType, ParserOptionValue, ParserOptions, ParserSecret,
};

/// Validate all settings before executing the parser. Downcast errors to
/// `ParserInputError` to distinguish missing/rejected input from parse failures.
pub fn run_parser_with_options(
    parser: &dyn Parser,
    input: ParserInput,
    options: ParserOptions,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
) -> Result<()> {
    let context = ParserContext::new(parser.name(), parser.option_specs(), options)?;
    parser.run_into_with_context(input, &context, sink, diagnostic)
}

/// Look up a parser and execute it with validated per-invocation settings.
/// Preserves output-sink, diagnostic and typed input-request errors.
pub fn run_parser_by_name_with_options(
    registry: &ParserRegistry,
    name: &str,
    input: ParserInput,
    options: ParserOptions,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
) -> Result<()> {
    let parser = registry
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("unknown parser: {name}"))?;
    run_parser_with_options(&**parser, input, options, sink, diagnostic)
}

/// Return a sorted list of metadata describing all registered parsers.
///
/// The returned vector is sorted in ascending order by parser name.
///
/// # Arguments
///
/// * `registry` - The registry containing all available parsers.
pub fn list_parsers(registry: &ParserRegistry) -> Vec<ParserInfo> {
    let mut out: Vec<ParserInfo> = registry
        .values()
        .map(|p| ParserInfo {
            name: p.name(),
            description: p.description(),
        })
        .collect();

    out.sort_by(|a, b| a.name.cmp(b.name));
    out
}

/// Run a parser selected by name and stream its parsed objects to a sink.
///
/// # Arguments
///
/// * `registry` - The registry used to look up the parser by name.
/// * `name` - The name of the parser to run.
/// * `input` - The input data that will be provided to the parser.
/// * `sink` - A callback that will be invoked for each parsed object.
///
/// # Errors
///
/// Returns an error if:
/// * No parser with the given `name` exists in the registry.
/// * The selected parser fails during execution.
pub fn run_parser_by_name(
    registry: &ParserRegistry,
    name: &str,
    input: ParserInput,
    sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
) -> Result<()> {
    let p = registry
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("unknown parser: {name}"))?;

    p.run_into(input, sink)
}
