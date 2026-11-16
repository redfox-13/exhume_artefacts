//! iOS artefact parser entry points.

pub(crate) mod applications;
pub(crate) mod calendar;
pub(crate) mod callhistory;
pub(crate) mod contacts;
pub(crate) mod datausage;
pub(crate) mod imessage;
pub(crate) mod interactionc;
pub(crate) mod knowledgec;
pub(crate) mod mail;
pub(crate) mod notes;
pub(crate) mod photos;
pub(crate) mod routined;
pub(crate) mod safari;
pub(crate) mod tcc;
pub(crate) mod whatsapp;

pub use applications::{
    IosAppContainerParser, IosAppManifestParser, IosFrontboardParser, IosIconStateParser,
    IosMobileInstallationLogParser,
};
pub use calendar::IosCalendarParser;
pub use callhistory::IosCallHistoryParser;
pub use contacts::IosContactsParser;
pub use datausage::IosDataUsageParser;
pub use imessage::IosIMessageParser;
pub use interactionc::IosInteractionCParser;
pub use knowledgec::IosKnowledgeCParser;
pub use mail::IosMailParser;
pub use notes::IosNotesParser;
pub use photos::IosPhotosParser;
pub use routined::IosRoutinedParser;
pub use safari::IosSafariParser;
pub use tcc::IosTccParser;
pub use whatsapp::IosWhatsAppParser;
