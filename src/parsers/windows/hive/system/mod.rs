//! Windows operating-system and user-profile configuration.
use super::Artefact;

mod computer_name;
mod profiles;
mod system_info;
mod timezone;

pub(super) fn profile() -> Vec<Artefact> {
    vec![
        computer_name::artefact(),
        profiles::artefact(),
        system_info::artefact(),
        timezone::artefact(),
    ]
}
