//! Browser-related user activity recorded in Windows registry hives.
use super::Artefact;

mod typed_urls;

pub(super) fn profile() -> Vec<Artefact> {
    vec![typed_urls::artefact()]
}
