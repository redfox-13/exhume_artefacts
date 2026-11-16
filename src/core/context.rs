//! Per-invocation parser settings. Secret contents are never serialized.

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserOptionType {
    String,
    Boolean,
    Integer,
    Secret,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ParserOptionValue {
    String(String),
    Boolean(bool),
    Integer(i64),
}

impl ParserOptionValue {
    fn value_type(&self) -> ParserOptionType {
        match self {
            Self::String(_) => ParserOptionType::String,
            Self::Boolean(_) => ParserOptionType::Boolean,
            Self::Integer(_) => ParserOptionType::Integer,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(untagged)]
pub enum ParserOptionDefault {
    String(&'static str),
    Boolean(bool),
    Integer(i64),
}

impl ParserOptionDefault {
    fn value(self) -> ParserOptionValue {
        match self {
            Self::String(value) => ParserOptionValue::String(value.into()),
            Self::Boolean(value) => ParserOptionValue::Boolean(value),
            Self::Integer(value) => ParserOptionValue::Integer(value),
        }
    }
}

/// The single declaration used for library validation, CLI help and UI forms.
/// Conditional requirements use `required: false` and request input at runtime.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ParserOptionSpec {
    pub name: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub value_type: ParserOptionType,
    pub required: bool,
    pub default: Option<ParserOptionDefault>,
}

/// Exact bytes (including whitespace), erased on drop. Deliberately not Clone
/// or Serialize; access must be explicit.
pub struct ParserSecret(Zeroizing<Vec<u8>>);

impl ParserSecret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ParserSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserInputReason {
    Missing,
    Rejected,
}

/// Safe to persist or send to a UI; carries no submitted values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserInputRequest {
    pub name: String,
    pub label: String,
    pub description: String,
    pub value_type: ParserOptionType,
    pub reason: ParserInputReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum ParserInputError {
    InvalidConfiguration { option: String, message: String },
    NeedsInput { requests: Vec<ParserInputRequest> },
}

impl ParserInputError {
    pub fn invalid(option: impl Into<String>, message: impl Into<String>) -> Self {
        Self::InvalidConfiguration {
            option: option.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ParserInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration { option, message } => {
                write!(f, "invalid parser option '{option}': {message}")
            }
            Self::NeedsInput { requests } => {
                f.write_str("parser needs input")?;
                for request in requests {
                    write!(f, "; {} ({:?})", request.name, request.reason)?;
                }
                Ok(())
            }
        }
    }
}
impl std::error::Error for ParserInputError {}

/// Caller-supplied values for one invocation. Debug output redacts secrets.
#[derive(Debug, Default)]
pub struct ParserOptions {
    values: BTreeMap<String, ParserOptionValue>,
    secrets: BTreeMap<String, ParserSecret>,
}

impl ParserOptions {
    fn check_duplicate(&self, name: &str) -> Result<(), ParserInputError> {
        if self.values.contains_key(name) || self.secrets.contains_key(name) {
            return Err(ParserInputError::invalid(name, "specified more than once"));
        }
        Ok(())
    }
    pub fn insert(
        &mut self,
        name: impl Into<String>,
        value: ParserOptionValue,
    ) -> Result<(), ParserInputError> {
        let name = name.into();
        self.check_duplicate(&name)?;
        self.values.insert(name, value);
        Ok(())
    }
    pub fn insert_secret(
        &mut self,
        name: impl Into<String>,
        value: ParserSecret,
    ) -> Result<(), ParserInputError> {
        let name = name.into();
        self.check_duplicate(&name)?;
        self.secrets.insert(name, value);
        Ok(())
    }
}

/// Validated settings, including defaults, bound to a particular parser.
#[derive(Debug)]
pub struct ParserContext {
    parser: &'static str,
    specs: &'static [ParserOptionSpec],
    options: ParserOptions,
}

impl ParserContext {
    /// Check metadata before exposing it in CLI help or UI descriptions.
    pub fn validate_specs(specs: &[ParserOptionSpec]) -> Result<(), ParserInputError> {
        let mut declared = BTreeMap::new();
        for spec in specs {
            if spec.name.is_empty() || declared.insert(spec.name, spec).is_some() {
                return Err(ParserInputError::invalid(
                    spec.name,
                    "empty or duplicate declaration",
                ));
            }
            if let Some(default) = spec.default
                && default.value().value_type() != spec.value_type
            {
                return Err(ParserInputError::invalid(
                    spec.name,
                    "default has the wrong type; secrets cannot have defaults",
                ));
            }
        }
        Ok(())
    }

    pub fn new(
        parser: &'static str,
        specs: &'static [ParserOptionSpec],
        mut options: ParserOptions,
    ) -> Result<Self, ParserInputError> {
        Self::validate_specs(specs)?;
        let declared: BTreeMap<_, _> = specs.iter().map(|spec| (spec.name, spec)).collect();
        for (name, value) in &options.values {
            let spec = declared
                .get(name.as_str())
                .ok_or_else(|| ParserInputError::invalid(name, "unknown option"))?;
            if value.value_type() != spec.value_type {
                return Err(ParserInputError::invalid(
                    name,
                    "wrong value type; use ParserOptions::insert_secret for secret options",
                ));
            }
        }
        for name in options.secrets.keys() {
            if !declared
                .get(name.as_str())
                .is_some_and(|spec| spec.value_type == ParserOptionType::Secret)
            {
                return Err(ParserInputError::invalid(name, "unknown secret option"));
            }
        }
        for spec in specs {
            if let Some(default) = spec.default {
                options
                    .values
                    .entry(spec.name.into())
                    .or_insert_with(|| default.value());
            }
        }
        let missing = specs
            .iter()
            .filter(|spec| {
                spec.required
                    && !options.values.contains_key(spec.name)
                    && !options.secrets.contains_key(spec.name)
            })
            .map(|spec| request(spec, ParserInputReason::Missing))
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(ParserInputError::NeedsInput { requests: missing });
        }
        Ok(Self {
            parser,
            specs,
            options,
        })
    }

    pub fn parser_name(&self) -> &'static str {
        self.parser
    }
    pub fn is_empty(&self) -> bool {
        self.options.values.is_empty() && self.options.secrets.is_empty()
    }
    pub fn option(&self, name: &str) -> Option<&ParserOptionValue> {
        self.options.values.get(name)
    }
    pub fn secret(&self, name: &str) -> Option<&[u8]> {
        self.options.secrets.get(name).map(ParserSecret::expose)
    }

    /// Request a conditional value, or report a rejected credential, without
    /// formatting the supplied value into an error. Return this error before
    /// emitting objects so that a caller can retry the invocation safely.
    pub fn request_input(&self, name: &str, reason: ParserInputReason) -> ParserInputError {
        match self.specs.iter().find(|spec| spec.name == name) {
            Some(spec) => ParserInputError::NeedsInput {
                requests: vec![request(spec, reason)],
            },
            None => ParserInputError::invalid(name, "undeclared input request"),
        }
    }

    pub fn require_secret(&self, name: &str) -> Result<&[u8], ParserInputError> {
        if !self
            .specs
            .iter()
            .any(|spec| spec.name == name && spec.value_type == ParserOptionType::Secret)
        {
            return Err(ParserInputError::invalid(name, "undeclared secret"));
        }
        self.secret(name)
            .ok_or_else(|| self.request_input(name, ParserInputReason::Missing))
    }
}

fn request(spec: &ParserOptionSpec, reason: ParserInputReason) -> ParserInputRequest {
    ParserInputRequest {
        name: spec.name.into(),
        label: spec.label.into(),
        description: spec.description.into(),
        value_type: spec.value_type,
        reason,
    }
}
