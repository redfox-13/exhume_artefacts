//! Network configuration and connection-profile evidence.
use super::Artefact;

mod network_list;
mod port_proxy;
mod routes;

pub(super) fn profile() -> Vec<Artefact> {
    vec![
        network_list::artefact(),
        port_proxy::artefact(),
        routes::artefact(),
    ]
}
