//! Platform entry points, shared application engines, and parser registration.
//!
//! Put reusable storage-format support in `crate::formats`. Platform modules
//! supply artefact identity and configuration; `apps` owns application-specific
//! interpretation shared by more than one platform. Registry names remain
//! independent of these Rust module paths.

pub mod android;
pub(crate) mod apps;
pub mod ios;
pub mod macos;
pub mod mobile;
mod registry;
pub mod windows;

pub use registry::{ParserRegistry, build_registry};
// Preserve the original public Windows parser module paths.
pub use windows::{evtx, hive, pe, pml};