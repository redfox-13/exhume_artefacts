//! iOS application inventory and supporting observations.
//!
//! These parsers deliberately keep each evidence family separate. A direct
//! root application `Info.plist` is evidence that application code is present;
//! container metadata, FrontBoard state, SpringBoard placement, and
//! MobileInstallation logs are corroborating or historical observations, not
//! substitutes for that presence evidence.

mod container;
mod frontboard;
mod iconstate;
mod manifest;
mod mobile_installation;
mod support;

pub use container::IosAppContainerParser;
pub use frontboard::IosFrontboardParser;
pub use iconstate::IosIconStateParser;
pub use manifest::IosAppManifestParser;
pub use mobile_installation::IosMobileInstallationLogParser;

pub const INSTALLED_APPLICATION_KIND: &str = "mobile.application.installed";
pub const APPLICATION_CONTAINER_KIND: &str = "mobile.application.container";
pub const FRONTBOARD_STATE_KIND: &str = "mobile.application.frontboard_state";
pub const HOME_SCREEN_ITEM_KIND: &str = "mobile.application.home_screen_item";
pub const INSTALL_EVENT_KIND: &str = "mobile.application.install_event";
