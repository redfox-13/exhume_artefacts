//! Windows operating-system and user-profile configuration.

use super::Artefact;

pub(super) mod computer_name;
pub(super) mod profiles;
pub(super) mod windows_version;
pub(super) mod timezone;
pub(super) mod wbem;
pub(super) mod spp_clients;
pub(super) mod scheduling_agent;
pub(super) mod wow64;
pub(super) mod sus_client;
pub(super) mod calibration;

pub(super) fn artefacts() -> Vec<Artefact> {
    vec![
        computer_name::artefact(),
        profiles::artefact(),
        windows_version::artefact(),
        timezone::artefact(),
        wbem::artefact(),
        spp_clients::artefact(),
        scheduling_agent::artefact(),
        wow64::artefact(),
        sus_client::artefact(),
        calibration::artefact(),
    ]
}
