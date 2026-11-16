//! Standalone-file runner with positional FILE PARSER arguments.
fn main() -> std::process::ExitCode {
    exhume_artefacts::cli::finish(exhume_artefacts::cli::run_local(true))
}
