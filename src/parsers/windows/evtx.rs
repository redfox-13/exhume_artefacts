// exhume/members/exhume_artefacts/src/parsers/evtx.rs
use anyhow::{Context, Result};
use evtx::{EvtxParser as EvtxCrateParser, ParserSettings};
use serde_json::json;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use crate::core::{ObjectParsed, Parser, ParserInput, TimelineEvent};

/// Parser for Windows EVTX event log files.
///
/// This type wraps the `evtx` crate and adapts it to the crate's
/// `Parser` trait, emitting one [`ObjectParsed`] per event record.
pub struct WindowsEvtxParser {
    /// EVTX parser settings used when reading and decoding the log.
    settings: ParserSettings,
    /// When `true`, non-fatal errors are logged and parsing continues.
    /// When `false`, the first such error aborts parsing.
    best_effort: bool,
}

impl Default for WindowsEvtxParser {
    /// Construct a parser with sane defaults:
    ///
    /// - single-threaded EVTX parsing
    /// - no pretty indentation in XML/JSON
    /// - EVTX checksums are validated
    /// - best-effort mode enabled
    fn default() -> Self {
        let settings = ParserSettings::default()
            .num_threads(1)
            .indent(false)
            .validate_checksums(true);

        Self {
            settings,
            best_effort: true,
        }
    }
}

impl WindowsEvtxParser {
    /// Enable or disable best-effort mode.
    ///
    /// In best-effort mode (`v == true`), chunk or record-level errors
    /// are reported to stderr and parsing continues with subsequent
    /// data. When disabled, the first such error is returned to the
    /// caller.
    pub fn best_effort(mut self, v: bool) -> Self {
        self.best_effort = v;
        self
    }

    /// Core parsing routine that runs the given `EvtxCrateParser` and
    /// forwards parsed events to the provided sink.
    ///
    /// The sink is called for every successfully decoded EVTX record.
    /// Errors in reading chunks, parsing chunks, or decoding individual
    /// records are either logged and skipped (when `best_effort` is
    /// enabled) or returned as a failure.
    fn run_with_parser<R>(
        &self,
        parser: EvtxCrateParser<R>,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()>
    where
        R: Read + Seek,
    {
        // Apply the configured parser settings.
        let parser = parser.with_configuration(self.settings.clone());
        let settings = Arc::new(self.settings.clone());

        // Iterate over all EVTX chunks produced by the parser.
        for chunk_data_res in parser.into_chunks() {
            let mut chunk_data = match chunk_data_res {
                Ok(c) => c,
                // If best-effort is enabled, log the error and skip the chunk.
                Err(e) if self.best_effort => {
                    eprintln!("EVTX: skipping chunk (read error): {e}");
                    continue;
                }
                // Otherwise, propagate the error.
                Err(e) => return Err(e.into()),
            };

            // Parse the raw chunk data into an iterable chunk.
            let mut chunk = match chunk_data.parse(settings.clone()) {
                Ok(ch) => ch,
                // Skip invalid chunks in best-effort mode.
                Err(e) if self.best_effort => {
                    eprintln!("EVTX: skipping chunk (parse error): {e}");
                    continue;
                }
                Err(e) => return Err(e.into()),
            };

            // Iterate over individual event records in the chunk.
            for record_res in chunk.iter() {
                let record = match record_res {
                    Ok(r) => r,
                    // Skip invalid records in best-effort mode.
                    Err(e) if self.best_effort => {
                        eprintln!("EVTX: skipping record (error): {e}");
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };

                // Serialize the record to XML for the `text` field.
                let xml = record
                    .clone()
                    .into_xml()
                    .context("EVTX: XML serialization failed")?;

                // Serialize the record to JSON for the structured `json` field.
                let js = record
                    .into_json_value()
                    .context("EVTX: JSON serialization failed")?;

                // Normalize timestamps:
                // - `timestamp` is RFC3339 (human-friendly)
                // - `timestamp_unix` is Unix epoch seconds
                // - `timestamp_unix_ms` is Unix epoch milliseconds
                let ts_rfc3339 = xml.timestamp.to_rfc3339();
                let ts_unix = xml.timestamp.timestamp();
                let ts_unix_ms = xml.timestamp.timestamp_millis();

                // Emit a normalized `ObjectParsed` representing the event.
                sink(ObjectParsed {
                    parser: self.name(),
                    kind: "windows.evtx.event",
                    text: xml.data,
                    json: json!({
                        "event_record_id": js.event_record_id,
                        "timestamp": ts_rfc3339,
                        "timestamp_unix": ts_unix,
                        "timestamp_unix_ms": ts_unix_ms,
                        "event": js.data
                    }),
                })?;
            }
        }

        Ok(())
    }
}

impl Parser for WindowsEvtxParser {
    fn name(&self) -> &'static str {
        "windows_evtx"
    }

    fn extract_timeline_events(&self, obj: &ObjectParsed) -> Vec<TimelineEvent> {
        let Some(ts_unix_ms) = obj.json["timestamp_unix_ms"].as_i64() else {
            return Vec::new();
        };
        let description = obj.json["event_record_id"]
            .as_i64()
            .map(|id| format!("EventRecordID={id}"));
        vec![TimelineEvent {
            ts_unix_ms,
            event_type: "windows.evtx.event",
            description,
            actor: None,
        }]
    }

    /// Human-readable description of what this parser does.
    fn description(&self) -> &'static str {
        "Parse Windows EVTX event log files and emit one JSON object per event record."
    }

    /// Dispatch parsing based on the input type and forward events into `sink`.
    ///
    /// Supported input kinds:
    /// - `ParserInput::Path`: filesystem path to an EVTX file
    /// - `ParserInput::Bytes`: in-memory buffer containing the entire file
    /// - `ParserInput::ReadSeek`: generic reader + seeker instance
    fn run_into(
        &self,
        input: ParserInput,
        sink: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        match input {
            ParserInput::Path(p) => {
                // Open EVTX from a filesystem path.
                let parser =
                    EvtxCrateParser::from_path(p).context("failed to open EVTX from path")?;
                self.run_with_parser(parser, sink)
            }
            ParserInput::Bytes(b) => {
                // Quickly validate the EVTX magic header before parsing.
                if b.len() < 8 || &b[..8] != b"ElfFile\0" {
                    anyhow::bail!("not an EVTX file (missing ElfFile\\0 signature)");
                }
                // Open EVTX from an in-memory buffer.
                let parser =
                    EvtxCrateParser::from_buffer(b).context("failed to open EVTX from buffer")?;
                self.run_with_parser(parser, sink)
            }
            ParserInput::ReadSeek(mut rs) => {
                // Ensure we start reading from the beginning of the stream.
                rs.seek(SeekFrom::Start(0))?;
                let parser = evtx::EvtxParser::from_read_seek(rs)?;
                self.run_with_parser(parser, sink)
            }
            ParserInput::Compound(_) => {
                anyhow::bail!("windows_evtx does not support compound parser input")
            }
        }
    }
}
