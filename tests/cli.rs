use std::process::Command;

#[test]
fn help_exposes_one_value_option() {
    let output = Command::new(env!("CARGO_BIN_EXE_exhume_artefacts"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--option <NAME=VALUE>"));
    assert!(!help.contains("--secret-file"));
    assert!(!help.contains("--secret-stdin"));
}

#[test]
fn description_is_available_without_a_file_and_lists_companions() {
    let output = Command::new(env!("CARGO_BIN_EXE_exhume_artefacts"))
        .args(["--describe-parser", "macos_chromium"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let description: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(description["name"], "macos_chromium");
    assert_eq!(description["options"], serde_json::json!([]));
    assert!(
        description["companions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source["role"] == "sqlite_wal")
    );
}

#[test]
fn unsupported_option_fails_before_opening_input_and_does_not_echo_value() {
    let output = Command::new(env!("CARGO_BIN_EXE_exhume_artefacts"))
        .args([
            "--parser",
            "windows_evtx",
            "--file",
            "/nonexistent",
            "--option",
            "password=never-echo-me",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["code"], "invalid_configuration");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("never-echo-me"));
}
