//! File-selection and navigation evidence from Windows registry hives.

use super::Artefact;

pub(super) mod comdlg32;
pub(super) mod recent_docs;
pub(super) mod shellbags;
pub(super) mod typed_paths;
pub(super) mod mru_controls;

pub(super) fn artefacts() -> Vec<Artefact> {
    vec![
        comdlg32::artefact(),
        recent_docs::artefact(),
        shellbags::artefact(),
        typed_paths::artefact(),
        mru_controls::artefact(),
    ]
}
