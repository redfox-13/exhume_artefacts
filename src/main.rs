fn main() -> std::process::ExitCode {
    exhume_artefacts::cli::finish(exhume_artefacts::cli::run_local(false))
}
