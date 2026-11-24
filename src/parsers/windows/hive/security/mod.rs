//! Security posture and protection configuration from Windows registry hives.

use super::Artefact;

pub(super) mod defender;
pub(super) mod lsa;
pub(super) mod sam;
pub(super) mod sam_accounts;
pub(super) mod sam_aliases;
pub(super) mod uac;
pub(super) mod security_center;
pub(super) mod execution_policy;
pub(super) mod uac_bypass;

pub(super) fn artefacts() -> Vec<Artefact> {
    vec![
        defender::artefact(),
        lsa::artefact(),
        sam_accounts::artefact(),
        sam_aliases::artefact(),
        uac::artefact(),
        security_center::artefact(),
        execution_policy::artefact(),
        uac_bypass::artefact(),
    ]
}
