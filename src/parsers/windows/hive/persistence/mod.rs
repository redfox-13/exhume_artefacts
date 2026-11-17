//! Persistence artefacts found in Windows registry hives.
use super::Artefact;

pub(super) mod appinit;
pub(super) mod appcertdlls;
pub(super) mod cmd_autorun;
pub(super) mod ifeo;
pub(super) mod run;
pub(super) mod runonceex;
pub(super) mod services;
pub(super) mod session_manager;
pub(super) mod startup_approved;
pub(super) mod task_cache;
pub(super) mod winlogon;

pub(super) fn profile() -> Vec<Artefact> {
    vec![
        appinit::artefact(),
        appcertdlls::artefact(),
        cmd_autorun::artefact(),
        ifeo::artefact(),
        run::artefact(),
        runonceex::artefact(),
        services::artefact(),
        session_manager::artefact(),
        startup_approved::artefact(),
        task_cache::artefact(),
        winlogon::artefact(),
    ]
}
