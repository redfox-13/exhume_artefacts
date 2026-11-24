//! User interaction evidence from Windows registry hives.

use super::Artefact;

pub(super) mod feature_usage;
pub(super) mod recent_apps;
pub(super) mod run_mru;
pub(super) mod userassist;
pub(super) mod wordwheel_query;
pub(super) mod last_logged_on;
pub(super) mod app_keys;
pub(super) mod this_pc_policy;

pub(super) fn artefacts() -> Vec<Artefact> {
    vec![
        feature_usage::artefact(),
        recent_apps::artefact(),
        run_mru::artefact(),
        userassist::artefact(),
        wordwheel_query::artefact(),
        last_logged_on::artefact(),
        app_keys::artefact(),
        this_pc_policy::artefact(),
    ]
}
