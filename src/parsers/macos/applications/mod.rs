//! macOS application inventory evidence.
//!
//! Each parser in this module represents one forensic assertion rather than a
//! pre-joined "installed applications" list:
//! - a bundle manifest proves that an application bundle was present,
//! - InstallHistory records an installation/update event,
//! - a package receipt records Installer state, and
//! - container-manager metadata associates an application or extension with a
//!   user/container.
//!
//! Joining and de-duplicating these observations is deliberately left to the
//! indexer. A file-local parser cannot decide whether a stale receipt or cache
//! registration still represents a present application.

mod bundle;
mod common;
mod container;
mod install_history;
mod package_receipt;

pub use bundle::MacosAppBundleParser;
pub use container::MacosContainerRegistrationParser;
pub use install_history::MacosInstallHistoryParser;
pub use package_receipt::MacosPackageReceiptParser;
