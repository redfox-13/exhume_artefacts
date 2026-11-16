use anyhow::Result;
use exhume_artefacts::{
    ObjectParsed, Parser, ParserContext, ParserInput, ParserInputError, ParserInputReason,
    ParserIssue, ParserIssueCode, ParserOptionDefault, ParserOptionSpec, ParserOptionType,
    ParserOptionValue, ParserOptions, ParserSecret, run_parser_with_options,
};

const SPECS: &[ParserOptionSpec] = &[
    ParserOptionSpec {
        name: "locked",
        label: "Locked",
        description: "Test a conditional credential",
        value_type: ParserOptionType::Boolean,
        required: false,
        default: Some(ParserOptionDefault::Boolean(false)),
    },
    ParserOptionSpec {
        name: "password",
        label: "Password",
        description: "Database password",
        value_type: ParserOptionType::Secret,
        required: false,
        default: None,
    },
];

struct ConfiguredParser;
impl Parser for ConfiguredParser {
    fn name(&self) -> &'static str {
        "configured"
    }
    fn option_specs(&self) -> &'static [ParserOptionSpec] {
        SPECS
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
        _input: ParserInput,
        context: &ParserContext,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
        _diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
    ) -> Result<()> {
        if context.option("locked") == Some(&ParserOptionValue::Boolean(true)) {
            let password = context.require_secret("password")?;
            if password != b" correct password\n" {
                return Err(context
                    .request_input("password", ParserInputReason::Rejected)
                    .into());
            }
        }
        sink(ObjectParsed {
            parser: self.name(),
            kind: "test",
            text: String::new(),
            json: serde_json::json!({"parsed": true}),
        })
    }
}

fn locked_options() -> ParserOptions {
    let mut options = ParserOptions::default();
    options
        .insert("locked", ParserOptionValue::Boolean(true))
        .unwrap();
    options
}

#[test]
fn conditional_missing_rejected_and_retry_preserve_secret_bytes() {
    for reason in [ParserInputReason::Missing, ParserInputReason::Rejected] {
        let mut options = locked_options();
        if reason == ParserInputReason::Rejected {
            options
                .insert_secret("password", ParserSecret::new(b"wrong-secret".to_vec()))
                .unwrap();
        }
        let mut emitted = 0;
        let error = run_parser_with_options(
            &ConfiguredParser,
            ParserInput::Bytes(vec![]),
            options,
            &mut |_| {
                emitted += 1;
                Ok(())
            },
            &mut |_| Ok(()),
        )
        .unwrap_err();
        let typed = error.downcast_ref::<ParserInputError>().unwrap();
        let ParserInputError::NeedsInput { requests } = typed else {
            panic!("expected input request")
        };
        assert_eq!(requests[0].reason, reason);
        assert_eq!(requests[0].name, "password");
        assert_eq!(emitted, 0);
        assert!(!format!("{error:?}").contains("wrong-secret"));
        assert!(
            !serde_json::to_string(typed)
                .unwrap()
                .contains("wrong-secret")
        );
    }
    let mut options = locked_options();
    options
        .insert_secret(
            "password",
            ParserSecret::new(b" correct password\n".to_vec()),
        )
        .unwrap();
    assert!(!format!("{options:?}").contains("correct password"));
    let mut emitted = 0;
    run_parser_with_options(
        &ConfiguredParser,
        ParserInput::Bytes(vec![]),
        options,
        &mut |_| {
            emitted += 1;
            Ok(())
        },
        &mut |_| Ok(()),
    )
    .unwrap();
    assert_eq!(emitted, 1);
    // A subsequent invocation has its own default and no inherited secret.
    let context = ParserContext::new("configured", SPECS, ParserOptions::default()).unwrap();
    assert_eq!(
        context.option("locked"),
        Some(&ParserOptionValue::Boolean(false))
    );
    assert!(context.secret("password").is_none());
}

#[test]
fn missing_required_inputs_are_collected_before_execution() {
    static REQUIRED: &[ParserOptionSpec] = &[
        ParserOptionSpec {
            name: "password",
            label: "Password",
            description: "",
            value_type: ParserOptionType::Secret,
            required: true,
            default: None,
        },
        ParserOptionSpec {
            name: "timezone",
            label: "Timezone",
            description: "",
            value_type: ParserOptionType::String,
            required: true,
            default: None,
        },
    ];
    let error = ParserContext::new("test", REQUIRED, ParserOptions::default()).unwrap_err();
    let ParserInputError::NeedsInput { requests } = error else {
        panic!("expected input request")
    };
    assert_eq!(
        requests.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
        ["password", "timezone"]
    );
}

#[test]
fn unknown_names_and_wrong_library_value_types_are_rejected_without_values() {
    for (name, value) in [
        ("unknown", ParserOptionValue::Boolean(true)),
        ("locked", ParserOptionValue::Integer(1)),
        (
            "password",
            ParserOptionValue::String("sensitive-value".into()),
        ),
    ] {
        let mut options = ParserOptions::default();
        options.insert(name, value).unwrap();
        let error = ParserContext::new("configured", SPECS, options).unwrap_err();
        assert!(matches!(
            error,
            ParserInputError::InvalidConfiguration { .. }
        ));
        assert!(!format!("{error:?}").contains("sensitive-value"));
    }
    let mut options = ParserOptions::default();
    options
        .insert_secret("unknown", ParserSecret::new(vec![]))
        .unwrap();
    assert!(ParserContext::new("configured", SPECS, options).is_err());
    let mut options = ParserOptions::default();
    options
        .insert_secret("password", ParserSecret::new(vec![]))
        .unwrap();
    assert!(
        options
            .insert(
                "password",
                ParserOptionValue::String("another-value".into())
            )
            .is_err()
    );
}

#[test]
fn invalid_declarations_do_not_become_user_requests() {
    static INVALID: &[ParserOptionSpec] = &[ParserOptionSpec {
        name: "password",
        label: "Password",
        description: "",
        value_type: ParserOptionType::Secret,
        required: false,
        default: Some(ParserOptionDefault::String("do-not-echo-this")),
    }];
    let error = ParserContext::new("test", INVALID, ParserOptions::default()).unwrap_err();
    assert!(matches!(
        error,
        ParserInputError::InvalidConfiguration { .. }
    ));
    assert!(!error.to_string().contains("do-not-echo-this"));
    struct InvalidParser;
    impl Parser for InvalidParser {
        fn name(&self) -> &'static str {
            "invalid"
        }
        fn option_specs(&self) -> &'static [ParserOptionSpec] {
            INVALID
        }
        fn run_into(
            &self,
            _: ParserInput,
            _: &mut dyn FnMut(ObjectParsed) -> Result<()>,
        ) -> Result<()> {
            Ok(())
        }
    }
    assert!(exhume_artefacts::cli::print_description(&InvalidParser).is_err());
    static DUPLICATE: &[ParserOptionSpec] = &[SPECS[0], SPECS[0]];
    assert!(ParserContext::new("test", DUPLICATE, ParserOptions::default()).is_err());
}

#[test]
fn cli_string_assignments_and_integer_boundaries_are_preserved() {
    static OPTIONS: &[ParserOptionSpec] = &[
        ParserOptionSpec {
            name: "label",
            label: "Label",
            description: "",
            value_type: ParserOptionType::String,
            required: false,
            default: Some(ParserOptionDefault::String("default")),
        },
        ParserOptionSpec {
            name: "count",
            label: "Count",
            description: "",
            value_type: ParserOptionType::Integer,
            required: false,
            default: Some(ParserOptionDefault::Integer(7)),
        },
    ];
    let defaults = ParserContext::new("test", OPTIONS, ParserOptions::default()).unwrap();
    assert_eq!(
        defaults.option("count"),
        Some(&ParserOptionValue::Integer(7))
    );
    for number in [i64::MIN, i64::MAX] {
        let assignment = format!("count={number}");
        let mut matches =
            exhume_artefacts::cli::configuration_arguments(clap::Command::new("test"))
                .try_get_matches_from(["test", "--option", "label=a=b", "--option", &assignment])
                .unwrap();
        let options = exhume_artefacts::cli::parser_options(&mut matches, OPTIONS).unwrap();
        let context = ParserContext::new("test", OPTIONS, options).unwrap();
        assert_eq!(
            context.option("count"),
            Some(&ParserOptionValue::Integer(number))
        );
        assert_eq!(
            context.option("label"),
            Some(&ParserOptionValue::String("a=b".into()))
        );
    }
    let mut matches = exhume_artefacts::cli::configuration_arguments(clap::Command::new("test"))
        .try_get_matches_from(["test", "--option", "count=9223372036854775808"])
        .unwrap();
    assert!(exhume_artefacts::cli::parser_options(&mut matches, OPTIONS).is_err());
}

struct LegacyParser;
impl Parser for LegacyParser {
    fn name(&self) -> &'static str {
        "legacy"
    }
    fn run_into(
        &self,
        _: ParserInput,
        _: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        Ok(())
    }
    fn run_into_with_diagnostics(
        &self,
        _: ParserInput,
        _: &mut dyn FnMut(ObjectParsed) -> Result<()>,
        diagnostic: &mut dyn FnMut(ParserIssue) -> Result<()>,
    ) -> Result<()> {
        diagnostic(ParserIssue {
            code: ParserIssueCode::RecordParse,
            unit: Some(7),
            message: "recoverable record gap".into(),
        })
    }
}

#[test]
fn legacy_diagnostics_and_sink_errors_survive_context_dispatch() {
    let mut issues = Vec::new();
    run_parser_with_options(
        &LegacyParser,
        ParserInput::Bytes(vec![]),
        ParserOptions::default(),
        &mut |_| Ok(()),
        &mut |issue| {
            issues.push(issue);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(issues[0].unit, Some(7));
    let error = run_parser_with_options(
        &ConfiguredParser,
        ParserInput::Bytes(vec![]),
        ParserOptions::default(),
        &mut |_| anyhow::bail!("sink stopped"),
        &mut |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "sink stopped");
    let error = run_parser_with_options(
        &LegacyParser,
        ParserInput::Bytes(vec![]),
        ParserOptions::default(),
        &mut |_| Ok(()),
        &mut |_| anyhow::bail!("diagnostic stopped"),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "diagnostic stopped");
}

#[test]
fn default_hook_cannot_silently_ignore_configuration() {
    struct Unimplemented;
    impl Parser for Unimplemented {
        fn name(&self) -> &'static str {
            "unimplemented"
        }
        fn option_specs(&self) -> &'static [ParserOptionSpec] {
            SPECS
        }
        fn run_into(
            &self,
            _: ParserInput,
            _: &mut dyn FnMut(ObjectParsed) -> Result<()>,
        ) -> Result<()> {
            panic!("must not run")
        }
    }
    assert!(
        run_parser_with_options(
            &Unimplemented,
            ParserInput::Bytes(vec![]),
            ParserOptions::default(),
            &mut |_| Ok(()),
            &mut |_| Ok(())
        )
        .is_err()
    );
}

#[test]
fn cli_options_route_secrets_using_the_declaration() {
    use exhume_artefacts::cli::{configuration_arguments, parser_options};
    for password in [" key=é\r\n", ""] {
        let assignment = format!("password={password}");
        let mut matches = configuration_arguments(clap::Command::new("test"))
            .try_get_matches_from(["test", "--option", "locked=true", "--option", &assignment])
            .unwrap();
        let options = parser_options(&mut matches, SPECS).unwrap();
        assert!(matches.get_many::<String>("option").is_none());
        if !password.is_empty() {
            assert!(!format!("{options:?}").contains("key="));
            assert!(!format!("{matches:?}").contains("key="));
        }
        let context = ParserContext::new("configured", SPECS, options).unwrap();
        assert_eq!(
            context.require_secret("password").unwrap(),
            password.as_bytes()
        );
        assert!(context.option("password").is_none());
        assert_eq!(
            context.option("locked"),
            Some(&ParserOptionValue::Boolean(true))
        );
        assert!(!format!("{context:?}").contains("key="));
    }
}

#[test]
fn cli_secret_option_reaches_the_parser() {
    use exhume_artefacts::cli::{configuration_arguments, parser_options};
    let mut matches = configuration_arguments(clap::Command::new("test"))
        .try_get_matches_from([
            "test",
            "--option",
            "locked=true",
            "--option",
            "password= correct password\n",
        ])
        .unwrap();
    let options = parser_options(&mut matches, SPECS).unwrap();
    let mut emitted = 0;
    run_parser_with_options(
        &ConfiguredParser,
        ParserInput::Bytes(vec![]),
        options,
        &mut |_| {
            emitted += 1;
            Ok(())
        },
        &mut |_| Ok(()),
    )
    .unwrap();
    assert_eq!(emitted, 1);
}

#[test]
fn cli_option_errors_do_not_echo_values() {
    use exhume_artefacts::cli::{configuration_arguments, parser_options};
    for arguments in [
        vec!["test", "--option", "unknown=secret-value"],
        vec!["test", "--option", "locked=secret-value"],
        vec![
            "test",
            "--option",
            "password=secret-value",
            "--option",
            "password=second-secret-value",
        ],
        vec!["test", "--option", "secret-value"],
        vec!["test", "--option", "=secret-value"],
    ] {
        let mut matches = configuration_arguments(clap::Command::new("test"))
            .try_get_matches_from(arguments)
            .unwrap();
        let error = parser_options(&mut matches, SPECS).unwrap_err();
        assert!(!format!("{error:?}").contains("secret-value"));
        assert!(matches.get_many::<String>("option").is_none());
    }
}
