use serde_json::Value;
use std::io::{Read, Seek, Write};
use std::path::PathBuf;

/// Represents the result of parsing an object.
///
/// This struct contains metadata about the parser and the kind of object,
/// as well as both the raw text and a parsed JSON representation.
#[derive(Debug, Clone)]
pub struct ObjectParsed {
    /// Name of the parser that produced this result.
    pub parser: &'static str,
    /// Logical kind or type of the parsed object (e.g., "config", "schema").
    pub kind: &'static str,
    /// Original textual representation of the parsed object.
    pub text: String,
    /// Parsed JSON representation of the object.
    pub json: Value,
}

/// Basic information about an available parser.
///
/// This is typically used for discovery and documentation of parsers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParserInfo {
    /// Unique name of the parser.
    pub name: &'static str,
    /// Human-readable description of what the parser does.
    pub description: &'static str,
}

/// Convenience trait alias for types that implement both `Read` and `Seek`.
///
/// This allows trait objects or generics to be expressed in a more concise way.
pub trait ReadSeek: Read + Seek {}

/// Blanket implementation of `ReadSeek` for any type that implements `Read` and `Seek`.
impl<T: Read + Seek> ReadSeek for T {}

/// Path resolution rule for files that must be provided alongside a primary
/// parser input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum CompanionPathRule {
    /// Resolve a companion by appending a suffix to the primary evidence path.
    Suffix(&'static str),
    /// Resolve a companion by replacing the primary path's final component with
    /// this filename (a sibling in the same directory). Used e.g. to pair Apple
    /// Mail's "Envelope Index" with its sibling "Protected Index".
    Sibling(&'static str),
}

/// Description of a companion file a parser can consume with a primary input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct CompanionSpec {
    pub role: &'static str,
    pub path_rule: CompanionPathRule,
    pub required: bool,
}

impl CompanionSpec {
    pub const fn optional_suffix(role: &'static str, suffix: &'static str) -> Self {
        Self {
            role,
            path_rule: CompanionPathRule::Suffix(suffix),
            required: false,
        }
    }

    pub const fn required_suffix(role: &'static str, suffix: &'static str) -> Self {
        Self {
            role,
            path_rule: CompanionPathRule::Suffix(suffix),
            required: true,
        }
    }

    pub const fn optional_sibling(role: &'static str, filename: &'static str) -> Self {
        Self {
            role,
            path_rule: CompanionPathRule::Sibling(filename),
            required: false,
        }
    }
}

/// Metadata for a concrete source file passed to a parser.
#[derive(Debug, Clone)]
pub struct ParserSource {
    pub role: String,
    pub original_path: String,
    pub artifact_id: Option<i64>,
    pub system_file_id: Option<i64>,
    pub fs_identifier: Option<u64>,
}

impl ParserSource {
    pub fn new(
        role: impl Into<String>,
        original_path: impl Into<String>,
        artifact_id: Option<i64>,
        system_file_id: Option<i64>,
        fs_identifier: Option<u64>,
    ) -> Self {
        Self {
            role: role.into(),
            original_path: original_path.into(),
            artifact_id,
            system_file_id,
            fs_identifier,
        }
    }
}

/// Provides parser source bytes without tying parser crates to a concrete
/// filesystem implementation.
pub trait ParserFileProvider {
    fn copy_to(&mut self, source: &ParserSource, writer: &mut dyn Write) -> anyhow::Result<()>;
}

/// A primary parser input plus companion files resolved from the same evidence.
pub struct CompoundParserInput<'a> {
    pub primary: ParserSource,
    pub companions: Vec<ParserSource>,
    pub provider: Box<dyn ParserFileProvider + 'a>,
}

/// Different ways to provide input to a parser.
///
/// This enum abstracts over several common input sources so that parsers
/// can operate over paths, in-memory data, or generic `Read + Seek` streams.
pub enum ParserInput<'a> {
    /// Read input from a file system path.
    Path(PathBuf),
    /// Read input from an in-memory byte buffer.
    Bytes(Vec<u8>),
    /// Read input from a generic reader that also supports seeking.
    ReadSeek(Box<dyn ReadSeek + 'a>),
    /// Read a primary input and resolved companion files from a provider.
    Compound(CompoundParserInput<'a>),
}
