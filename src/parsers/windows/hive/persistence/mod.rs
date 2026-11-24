//! Persistence artefacts found in Windows registry hives.

use super::Artefact;

pub(super) mod appcertdlls;
pub(super) mod appinit;
pub(super) mod cmd_autorun;
pub(super) mod com_registration;
pub(super) mod ifeo;
pub(super) mod print_components;
pub(super) mod run;
pub(super) mod runonceex;
pub(super) mod services;
pub(super) mod session_manager;
pub(super) mod startup_approved;
pub(super) mod task_cache;
pub(super) mod winlogon;
pub(super) mod netsh;
pub(super) mod shell_overlay;
pub(super) mod wsh_settings;
pub(super) mod wab;
pub(super) mod command_shell;
pub(super) mod file_associations;

pub(super) fn artefacts() -> Vec<Artefact> {
    vec![
        appinit::artefact(),
        appcertdlls::artefact(),
        cmd_autorun::artefact(),
        com_registration::artefact(),
        ifeo::artefact(),
        print_components::artefact(),
        run::artefact(),
        runonceex::artefact(),
        services::artefact(),
        session_manager::artefact(),
        startup_approved::artefact(),
        task_cache::artefact(),
        winlogon::artefact(),
        netsh::artefact(),
        shell_overlay::artefact(),
        wsh_settings::artefact(),
        wab::artefact(),
        command_shell::artefact(),
        file_associations::artefact(),
    ]
}
