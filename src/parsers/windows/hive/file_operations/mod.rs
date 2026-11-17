//! File-selection and navigation evidence from Windows registry hives.
use super::Artefact;

mod comdlg32;
mod recent_docs;
mod typed_paths;

pub(super) fn profile() -> Vec<Artefact> {
    vec![
        comdlg32::artefact(),
        recent_docs::artefact(),
        typed_paths::artefact(),
    ]
}
