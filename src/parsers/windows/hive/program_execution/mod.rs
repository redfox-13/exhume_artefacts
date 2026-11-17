//! Program-execution evidence from Windows registry hives.
use super::Artefact;

mod amcache;
mod appcompat_cache;
mod bam;
mod dam;
mod syscache;

pub(super) fn profile() -> Vec<Artefact> {
    vec![
        amcache::artefact(),
        appcompat_cache::artefact(),
        bam::artefact(),
        dam::artefact(),
        syscache::artefact(),
    ]
}
