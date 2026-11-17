//! Security posture and protection configuration from Windows registry hives.
use super::Artefact;

mod defender;
mod lsa;
mod uac;

pub(super) fn profile() -> Vec<Artefact> {
    vec![defender::artefact(), lsa::artefact(), uac::artefact()]
}
