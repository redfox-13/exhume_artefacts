use anyhow::Result;

use super::{CompanionSpec, ObjectParsed, ParserInput, TimelineEvent};

/// A trait representing a generic parser that can process input into parsed objects.
///
/// Implementors of this trait must be `Send` and `Sync` so they can be safely
/// shared and used across threads.
pub trait Parser: Send + Sync {
    /// Returns the unique, static name of this parser implementation.
    fn name(&self) -> &'static str;

    /// Returns a human-readable description of this parser.
    ///
    /// By default, this returns `"No description provided."`, but implementors
    /// are encouraged to override it with a more detailed description.
    fn description(&self) -> &'static str {
        "No description provided."
    }

    /// Companion files this parser can consume when launched from an indexed
    /// evidence source.
    fn companion_specs(&self) -> &'static [CompanionSpec] {
        &[]
    }

    /// Whether this parser needs provenance for its primary source even when it
    /// has no companion files.
    ///
    /// The indexer normally streams standalone files through
    /// `ParserInput::ReadSeek`. Parsers that infer meaning from the indexed
    /// path (for example LaunchAgent vs LaunchDaemon, or the SharedFileList
    /// name) opt in here so the indexer supplies an empty
    /// `ParserInput::Compound` carrying the primary source metadata.
    fn requires_source_metadata(&self) -> bool {
        false
    }

    /// Extract zero or more timeline events from a parsed object for the supertimeline.
    ///
    /// The default implementation returns an empty vector. Parsers with temporal
    /// data should override this method to feed the unified `timeline_events` table.
    fn extract_timeline_events(&self, _obj: &ObjectParsed) -> Vec<TimelineEvent> {
        Vec::new()
    }

    /// Runs the parser on the given `input`, sending each parsed object to `sink`.
    ///
    /// # Arguments
    ///
    /// * `input` - The parser input to be processed.
    /// * `sink` - A callback that is invoked for each `ObjectParsed` produced
    ///   by the parser. It should return `Ok(())` on success or an error if
    ///   processing should be aborted.
    ///
    /// # Errors
    ///
    /// Returns an error if parsing fails or if the `sink` callback returns an error.
    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()>;
}
