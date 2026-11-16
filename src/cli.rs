//! Shared CLI adapters. Parser implementations never depend on ArgMatches.

use crate::input::CompanionOverride;
use crate::{
    Parser, ParserInputError, ParserOptionSpec, ParserOptionType, ParserOptionValue, ParserOptions,
    ParserSecret,
};
use anyhow::{Context, Result, bail};
use clap::{Arg, ArgAction, ArgMatches, Command};
use std::{collections::BTreeSet, process::ExitCode};
use zeroize::Zeroizing;

/// Shared implementation of the main CLI and positional `parse_file` example.
pub fn run_local(positional: bool) -> Result<()> {
    let exemptions = ["list_parsers", "describe_parser"];
    let mut file = Arg::new("file").required_unless_present_any(exemptions);
    let mut parser = Arg::new("parser").required_unless_present_any(exemptions);
    if !positional {
        file = file.long("file").short('f');
        parser = parser.long("parser").short('p');
    }
    let command = Command::new(if positional {
        "parse_file"
    } else {
        "exhume_artefacts"
    })
    .version(env!("CARGO_PKG_VERSION"))
    .about("Run a named artefact parser and output JSONL.")
    .arg(file)
    .arg(parser)
    .arg(
        Arg::new("list_parsers")
            .long("list-parsers")
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("log_level")
            .long("log-level")
            .short('l')
            .default_value("info")
            .value_parser(["error", "warn", "info", "debug", "trace"]),
    );
    let mut matches = configuration_arguments(command).get_matches();
    let level = matches
        .get_one::<String>("log_level")
        .context("missing log level")?
        .parse::<log::LevelFilter>()?;
    env_logger::Builder::new().filter_level(level).try_init()?;
    let registry = crate::parsers::build_registry();
    if let Some(name) = matches.get_one::<String>("describe_parser") {
        let parser = registry.get(name.as_str()).context("unknown parser")?;
        return print_description(&**parser);
    }
    if matches.get_flag("list_parsers") {
        for parser in crate::list_parsers(&registry) {
            println!("{:<24} {}", parser.name, parser.description);
        }
        return Ok(());
    }
    let parser_name = matches
        .get_one::<String>("parser")
        .context("missing parser name")?;
    let parser = registry
        .get(parser_name.as_str())
        .context("unknown parser")?;
    let options = parser_options(&mut matches, parser.option_specs())?;
    let context = crate::ParserContext::new(parser.name(), parser.option_specs(), options)?;
    let file = matches
        .get_one::<String>("file")
        .context("missing file path")?;
    let input = crate::input::local_input(
        &**parser,
        std::path::Path::new(file),
        &companion_overrides(&matches)?,
    )?;
    let mut count = 0usize;
    parser.run_into_with_context(
        input,
        &context,
        &mut |object| {
            println!("{}", object.json);
            count += 1;
            Ok(())
        },
        &mut |issue| {
            eprintln!("{}", serde_json::to_string(&issue)?);
            Ok(())
        },
    )?;
    if !positional {
        eprintln!("done: emitted {count} objects");
    }
    Ok(())
}

pub fn configuration_arguments(command: Command) -> Command {
    command
        .arg(
            Arg::new("option")
                .long("option")
                .value_name("NAME=VALUE")
                .action(ArgAction::Append)
                .help("Set a declared parser option, including passwords or keys; repeat for additional options."),
        )
        .arg(
            Arg::new("companion")
                .long("companion")
                .value_name("ROLE=PATH")
                .action(ArgAction::Append)
                .help("Override a declared companion role; repeat for additional roles."),
        )
        .arg(
            Arg::new("describe_parser")
                .long("describe-parser")
                .value_name("NAME")
                .help("Print parser option and companion declarations as JSON and exit."),
        )
}

pub fn print_description(parser: &dyn Parser) -> Result<()> {
    crate::ParserContext::validate_specs(parser.option_specs())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "name": parser.name(), "description": parser.description(),
            "options": parser.option_specs(), "companions": parser.companion_specs(),
        }))?
    );
    Ok(())
}

fn assignments<'a>(matches: &'a ArgMatches, id: &str) -> impl Iterator<Item = &'a str> {
    matches
        .get_many::<String>(id)
        .into_iter()
        .flatten()
        .map(String::as_str)
}

fn assignment(value: &str) -> Result<(&str, &str)> {
    // Never echo a malformed assignment: it may accidentally contain a secret.
    let (name, value) = value.split_once('=').context("expected NAME=VALUE")?;
    if name.is_empty() {
        bail!("assignment name cannot be empty");
    }
    Ok((name, value))
}

pub fn companion_overrides(matches: &ArgMatches) -> Result<Vec<CompanionOverride>> {
    assignments(matches, "companion")
        .map(|value| {
            let (role, path) = assignment(value)?;
            if path.is_empty() {
                bail!("companion path cannot be empty");
            }
            Ok(CompanionOverride {
                role: role.into(),
                path: path.into(),
            })
        })
        .collect()
}

/// Consume `--option` assignments and validate names/types/duplicates. The
/// declaration determines whether a value goes into ordinary or secret storage.
/// Owned assignment strings are zeroized on success and on error; process
/// arguments and shell history are outside this guarantee.
pub fn parser_options(
    matches: &mut ArgMatches,
    specs: &[ParserOptionSpec],
) -> Result<ParserOptions> {
    let raw_options: Vec<_> = matches
        .remove_many::<String>("option")
        .into_iter()
        .flatten()
        .map(Zeroizing::new)
        .collect();
    crate::ParserContext::validate_specs(specs)?;
    let mut options = ParserOptions::default();
    let mut seen = BTreeSet::new();
    for raw in &raw_options {
        let (name, value) = assignment(raw)?;
        if !seen.insert(name) {
            return Err(ParserInputError::invalid(name, "specified more than once").into());
        }
        let spec = specs
            .iter()
            .find(|spec| spec.name == name)
            .ok_or_else(|| ParserInputError::invalid(name, "unknown option"))?;
        let parsed = match spec.value_type {
            ParserOptionType::String => ParserOptionValue::String(value.into()),
            ParserOptionType::Boolean => ParserOptionValue::Boolean(
                value
                    .parse()
                    .map_err(|_| ParserInputError::invalid(name, "expected true or false"))?,
            ),
            ParserOptionType::Integer => {
                ParserOptionValue::Integer(value.parse().map_err(|_| {
                    ParserInputError::invalid(name, "expected a signed 64-bit integer")
                })?)
            }
            ParserOptionType::Secret => {
                options.insert_secret(name, ParserSecret::new(value.as_bytes().to_vec()))?;
                continue;
            }
        };
        options.insert(name, parsed)?;
    }
    Ok(options)
}

/// Machine-readable configuration errors on stderr. Exit 3 means user input is
/// needed; exit 1 means configuration, IO or parsing failed. Clap reserves exit
/// 2 for command-line usage errors. No interactive wait.
pub fn finish(result: Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if let Some(input_error) = error.downcast_ref::<ParserInputError>() {
                match serde_json::to_string(input_error) {
                    Ok(json) => eprintln!("{json}"),
                    Err(_) => eprintln!("{input_error}"),
                }
                if matches!(input_error, ParserInputError::NeedsInput { .. }) {
                    return ExitCode::from(3);
                }
            } else {
                eprintln!("{error:#}");
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_input_requests_have_a_distinct_exit_status() {
        assert_eq!(finish(Ok(())), ExitCode::SUCCESS);
        assert_eq!(
            finish(Err(ParserInputError::NeedsInput { requests: vec![] }.into())),
            ExitCode::from(3)
        );
        assert_eq!(
            finish(Err(
                ParserInputError::invalid("option", "unknown option").into()
            )),
            ExitCode::FAILURE
        );
    }
}
