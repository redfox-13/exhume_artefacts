//! Program-execution evidence from Windows registry hives.

use super::Artefact;

pub(super) mod amcache;
pub(super) mod app_paths;
pub(super) mod appcompat_cache;
pub(super) mod appcompat_flags;
pub(super) mod bam;
pub(super) mod dam;
pub(super) mod mui_cache;
pub(super) mod syscache;
pub(super) mod uninstall;
pub(super) mod heap;
pub(super) mod msi_products;
pub(super) mod drivers32;

pub(super) fn artefacts() -> Vec<Artefact> {
    vec![
        amcache::artefact(),
        app_paths::artefact(),
        appcompat_cache::artefact(),
        appcompat_flags::artefact(),
        bam::artefact(),
        dam::artefact(),
        mui_cache::artefact(),
        syscache::artefact(),
        uninstall::artefact(),
        heap::artefact(),
        msi_products::artefact(),
        drivers32::artefact(),
    ]
}
