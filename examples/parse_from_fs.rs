use anyhow::{Context, Result};
use clap::*;
use clap_num::maybe_hex;
use exhume_artefacts::parsers::build_registry;
use exhume_artefacts::{ObjectParsed, ParserContext, ParserSource, core::ParserInput};
use exhume_artefacts::{cli, input};
use exhume_body::credentials;
use exhume_filesystem::Filesystem;
use exhume_filesystem::detected_fs::detect_filesystem;
use exhume_filesystem::filesystem::{FileCommon, FsFileReadSeek};
use log::{LevelFilter, error};

/// Entry point for the `parse_from_fs` binary.
///
/// This program:
/// - Opens a disk image (or forensic container) as a "body".
/// - Detects the filesystem at the given offset and size.
/// - Locates a file by its filesystem record identifier.
/// - Runs a named artefact parser against that file.
/// - Emits parsed objects as JSON Lines (JSONL) to stdout.
fn main() -> std::process::ExitCode {
    cli::finish(run())
}

fn run() -> anyhow::Result<()> {
    // Define and parse command‑line arguments.
    let command = Command::new("parse_from_fs")
        .about("Parse a file (by filesystem record ID) inside a disk image and output JSONL.")
        .arg(
            Arg::new("list_parsers")
                .long("list-parsers")
                .help("List available parsers (name + description) and exit.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("body")
                .short('b')
                .long("body")
                .value_parser(value_parser!(String))
                .required_unless_present_any(["list_parsers", "describe_parser"]),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_parser(value_parser!(String))
                .required(false)
                .help("raw | ewf | vmdk | auto"),
        )
        .arg(
            Arg::new("offset")
                .short('o')
                .long("offset")
                .value_parser(maybe_hex::<u64>)
                .required_unless_present_any(["list_parsers", "describe_parser"])
                .help("Filesystem start (bytes, dec or hex)"),
        )
        .arg(
            Arg::new("size")
                .short('s')
                .long("size")
                .value_parser(maybe_hex::<u64>)
                .required_unless_present_any(["list_parsers", "describe_parser"])
                .help("Filesystem size (in sectors, dec or hex)"),
        )
        .arg(
            Arg::new("file_id")
                .short('r')
                .long("record")
                .value_parser(maybe_hex::<usize>)
                .required_unless_present_any(["list_parsers", "describe_parser"])
                .help("File record identifier"),
        )
        .arg(
            Arg::new("parser")
                .short('p')
                .long("parser")
                .value_parser(value_parser!(String))
                .required_unless_present_any(["list_parsers", "describe_parser"]),
        )
        .arg(
            Arg::new("log_level")
                .short('l')
                .long("log-level")
                .value_parser(["error", "warn", "info", "debug", "trace"])
                .default_value("info"),
        )
        .arg(Arg::new("source_path").long("source-path").help(
            "Primary path inside the evidence, required by parsers that interpret source paths.",
        ));
    let mut matches = cli::configuration_arguments(password_args(command)).get_matches();

    // Configure and initialize the logger based on the requested log level.
    let log_level_str = matches.get_one::<String>("log_level").unwrap();
    let level_filter = match log_level_str.as_str() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    };
    env_logger::Builder::new().filter_level(level_filter).init();

    // Build the global parser registry (mapping parser names to implementations).
    let registry = build_registry();

    if let Some(name) = matches.get_one::<String>("describe_parser") {
        let parser = registry.get(name.as_str()).context("unknown parser")?;
        return cli::print_description(&**parser);
    }

    // If requested, list all available parsers and exit without doing any parsing.
    if matches.get_flag("list_parsers") {
        println!("Available parsers:");
        for p in exhume_artefacts::list_parsers(&registry) {
            println!("  {:<20} {}", p.name, p.description);
        }
        return Ok(());
    }

    // Extract and normalize the remaining CLI arguments.
    let parser_name = matches
        .get_one::<String>("parser")
        .context("missing parser name")?
        .clone();
    let parser = registry
        .get(parser_name.as_str())
        .ok_or_else(|| anyhow::anyhow!("unknown parser: {parser_name}"))?;
    let options = cli::parser_options(&mut matches, parser.option_specs())?;
    let context = ParserContext::new(parser.name(), parser.option_specs(), options)?;
    let body_path = matches.get_one::<String>("body").unwrap();
    let auto = String::from("auto");
    let format = matches.get_one::<String>("format").unwrap_or(&auto);
    let fs_offset = *matches.get_one::<u64>("offset").unwrap();
    let fs_size_sectors = *matches.get_one::<u64>("size").unwrap();
    let file_id = *matches.get_one::<usize>("file_id").unwrap();
    let companions = cli::companion_overrides(&matches)?;
    let source_path = matches.get_one::<String>("source_path");
    if parser.requires_source_metadata() && source_path.is_none() {
        anyhow::bail!("this parser requires --source-path for its evidence path");
    }

    // Open the disk image / body and detect the filesystem within the given region.
    let body = credentials::open_body(
        body_path,
        format,
        matches
            .get_one::<String>("password_file")
            .map(String::as_str),
        matches.get_flag("password_stdin"),
    )
    .map_err(anyhow::Error::msg)?;
    let partition_size_bytes = fs_size_sectors * body.get_sector_size() as u64;

    let mut fs = detect_filesystem(&body, fs_offset, partition_size_bytes, None)
        .map_err(|e| anyhow::anyhow!("filesystem detection failed: {e:?}"))?;

    // Fetch the target file record from the filesystem.
    let file = fs
        .get_file(file_id as u64)
        .map_err(|e| anyhow::anyhow!("could not fetch file_id {file_id}: {e:?}"))?;

    // The example expects a regular file, not a directory.
    if file.is_dir() {
        error!(
            "file_id {} is a directory; this example expects a file",
            file_id
        );
        std::process::exit(1);
    }

    // Count of parsed objects emitted by the parser.
    let mut count = 0usize;

    // Sink closure that receives each parsed object and prints it as JSON.
    let mut sink = |obj: ObjectParsed| -> Result<()> {
        count += 1;
        println!("{}", obj.json);
        Ok(())
    };

    // Wrap the filesystem file in a Read+Seek adapter expected by parsers.
    let input = if !parser.companion_specs().is_empty()
        || !companions.is_empty()
        || parser.requires_source_metadata()
    {
        input::filesystem_input(
            &**parser,
            &mut fs,
            ParserSource::new(
                "primary",
                source_path
                    .cloned()
                    .unwrap_or_else(|| format!("<record:{file_id}>")),
                None,
                None,
                Some(file_id as u64),
            ),
            &companions,
        )?
    } else {
        ParserInput::ReadSeek(Box::new(FsFileReadSeek::new(&mut fs, file)))
    };

    parser
        .run_into_with_context(input, &context, &mut sink, &mut |issue| {
            eprintln!("{}", serde_json::to_string(&issue)?);
            Ok(())
        })
        .with_context(|| format!("parser '{parser_name}' failed"))?;

    Ok(())
}

/// Register this executable's mutually exclusive container-password sources.
fn password_args(command: clap::Command) -> clap::Command {
    command
        .arg(
            clap::Arg::new("password_file")
                .long("password-file")
                .global(true)
                .value_name("PATH")
                .conflicts_with("password_stdin")
                .help("Read the image container password from a file; remove one trailing line ending."),
        )
        .arg(
            clap::Arg::new("password_stdin")
                .long("password-stdin")
                .global(true)
                .action(clap::ArgAction::SetTrue)
                .help("Read the image container password from stdin; remove one trailing line ending."),
        )
}
