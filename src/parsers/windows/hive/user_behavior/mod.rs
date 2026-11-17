//! User interaction evidence from Windows registry hives.
use super::Artefact;

mod feature_usage;
mod recent_apps;
mod run_mru;
mod userassist;

pub(super) fn profile() -> Vec<Artefact> {
    vec![
        feature_usage::artefact(),
        recent_apps::artefact(),
        run_mru::artefact(),
        userassist::artefact(),
    ]
}
