//! Network configuration and connection-profile evidence.

use super::Artefact;

pub(super) mod interfaces;
pub(super) mod mapped_drives;
pub(super) mod network_list;
pub(super) mod port_proxy;
pub(super) mod proxy_settings;
pub(super) mod routes;
pub(super) mod gpo_settings;

pub(super) fn artefacts() -> Vec<Artefact> {
    vec![
        network_list::artefact(),
        interfaces::artefact(),
        mapped_drives::artefact(),
        port_proxy::artefact(),
        proxy_settings::artefact(),
        routes::artefact(),
        gpo_settings::artefact(),
    ]
}
