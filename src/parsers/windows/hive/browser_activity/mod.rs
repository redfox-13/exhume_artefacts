//! Browser-related user activity recorded in Windows registry hives.

use super::Artefact;

pub(super) mod security_zones;
pub(super) mod typed_urls;
pub(super) mod outlook_homepage;

pub(super) fn artefacts() -> Vec<Artefact> {
    vec![
        typed_urls::artefact(),
        security_zones::artefact(),
        outlook_homepage::artefact(),
    ]
}
