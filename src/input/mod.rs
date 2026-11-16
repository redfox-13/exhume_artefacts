//! Input assembly shared by local runners. Contents are copied on demand.

pub(crate) mod file;

use crate::{
    CompanionPathRule, CompoundParserInput, Parser, ParserFileProvider, ParserInput, ParserSource,
};
use anyhow::{Context, Result, bail};
use exhume_filesystem::{
    Filesystem,
    filesystem::{FileCommon, FsFileReadSeek},
};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
};

/// Explicit role/path assignments. Paths are host paths for `local_input` and
/// evidence paths for `filesystem_input`; callers must choose that scope.
#[derive(Debug, Clone)]
pub struct CompanionOverride {
    pub role: String,
    pub path: String,
}

fn overrides_by_role<'a>(
    parser: &dyn Parser,
    overrides: &'a [CompanionOverride],
) -> Result<BTreeMap<&'a str, &'a str>> {
    let mut result = BTreeMap::new();
    for source in overrides {
        if !parser
            .companion_specs()
            .iter()
            .any(|spec| spec.role == source.role)
        {
            bail!(
                "unknown companion role '{}' for {}",
                source.role,
                parser.name()
            );
        }
        if result
            .insert(source.role.as_str(), source.path.as_str())
            .is_some()
        {
            bail!("companion role '{}' specified more than once", source.role);
        }
    }
    Ok(result)
}

fn local_candidate(primary: &Path, rule: CompanionPathRule) -> PathBuf {
    match rule {
        CompanionPathRule::Suffix(suffix) => {
            let mut path = primary.as_os_str().to_os_string();
            path.push(suffix);
            path.into()
        }
        CompanionPathRule::Sibling(name) => primary.with_file_name(name),
    }
}

fn regular_file(path: &Path) -> io::Result<File> {
    // Reject FIFOs/devices before opening them, then verify the opened handle.
    if !std::fs::metadata(path)?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a regular file",
        ));
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a regular file",
        ));
    }
    Ok(file)
}

struct LocalFileProvider;
impl ParserFileProvider for LocalFileProvider {
    fn copy_to(&mut self, source: &ParserSource, writer: &mut dyn Write) -> Result<()> {
        let mut file = regular_file(Path::new(&source.original_path))
            .with_context(|| format!("cannot open companion source '{}'", source.original_path))?;
        io::copy(&mut file, writer)?;
        Ok(())
    }
}

/// Explicit companions override discovery by role. Unspecified companions use
/// the parser's suffix/sibling rules. Only NotFound is ignored for optional
/// discovered files; an explicit missing path or any other IO error fails.
pub fn local_input(
    parser: &dyn Parser,
    primary: &Path,
    overrides: &[CompanionOverride],
) -> Result<ParserInput<'static>> {
    let overrides = overrides_by_role(parser, overrides)?;
    regular_file(primary)
        .with_context(|| format!("cannot open primary source {}", primary.display()))?;
    if parser.companion_specs().is_empty() && !parser.requires_source_metadata() {
        return Ok(ParserInput::Path(primary.into()));
    }
    let primary_path = primary
        .to_str()
        .context("source path must be valid UTF-8")?;
    let mut companions = Vec::new();
    for spec in parser.companion_specs() {
        let explicit = overrides.get(spec.role);
        let path = explicit
            .map(PathBuf::from)
            .unwrap_or_else(|| local_candidate(primary, spec.path_rule));
        match regular_file(&path) {
            Ok(_) => companions.push(ParserSource::new(
                spec.role,
                path.to_str()
                    .context("companion path must be valid UTF-8")?,
                None,
                None,
                None,
            )),
            Err(error)
                if explicit.is_none()
                    && !spec.required
                    && error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "cannot open companion '{}' at {}",
                        spec.role,
                        path.display()
                    )
                });
            }
        }
    }
    Ok(ParserInput::Compound(CompoundParserInput {
        primary: ParserSource::new("primary", primary_path, None, None, None),
        companions,
        provider: Box::new(LocalFileProvider),
    }))
}

/// Provider for a single evidence filesystem, usable by embedded callers too.
pub struct FilesystemFileProvider<'a, F: Filesystem> {
    pub filesystem: &'a mut F,
}

impl<F: Filesystem> ParserFileProvider for FilesystemFileProvider<'_, F> {
    fn copy_to(&mut self, source: &ParserSource, writer: &mut dyn Write) -> Result<()> {
        let record = match source.fs_identifier {
            Some(id) => self
                .filesystem
                .get_file(id)
                .or_else(|_| self.filesystem.get_file_by_path(&source.original_path, id)),
            None => self.filesystem.get_file_by_path(&source.original_path, 0),
        }
        .map_err(|error| {
            anyhow::anyhow!("cannot resolve source '{}': {error}", source.original_path)
        })?;
        if record.is_dir() {
            bail!("source '{}' is a directory", source.original_path);
        }
        io::copy(&mut FsFileReadSeek::new(self.filesystem, record), writer)?;
        Ok(())
    }
}

/// Assemble explicit evidence companions. This helper does not discover
/// companions: the filesystem trait cannot reliably distinguish NotFound from
/// unreadable/corrupt paths. The indexer performs discovery using its inventory.
pub fn filesystem_input<'a, F: Filesystem>(
    parser: &dyn Parser,
    filesystem: &'a mut F,
    primary: ParserSource,
    overrides: &[CompanionOverride],
) -> Result<ParserInput<'a>> {
    let overrides = overrides_by_role(parser, overrides)?;
    let mut companions = Vec::new();
    for spec in parser.companion_specs() {
        match overrides.get(spec.role) {
            Some(path) => {
                let record = filesystem.get_file_by_path(path, 0).map_err(|error| {
                    anyhow::anyhow!("cannot resolve companion '{}': {error}", spec.role)
                })?;
                if record.is_dir() {
                    bail!("companion '{}' is a directory", spec.role);
                }
                companions.push(ParserSource::new(
                    spec.role,
                    *path,
                    None,
                    None,
                    Some(filesystem.file_identifier(&record)),
                ));
            }
            None if spec.required => bail!("required companion '{}' must be supplied", spec.role),
            None => {}
        }
    }
    Ok(ParserInput::Compound(CompoundParserInput {
        primary,
        companions,
        provider: Box::new(FilesystemFileProvider { filesystem }),
    }))
}
