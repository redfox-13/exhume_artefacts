//! Parser registration. Identifiers are independent of Rust module paths.

use super::{android, ios, macos, windows};
use crate::core::Parser;
use std::{collections::HashMap, sync::Arc};

pub type ParserRegistry = HashMap<&'static str, Arc<dyn Parser>>;

pub fn build_registry() -> ParserRegistry {
    let mut m: ParserRegistry = HashMap::new();

    m.insert(
        "windows_evtx",
        Arc::new(windows::WindowsEvtxParser::default()) as Arc<dyn Parser>,
    );

    m.insert(
        "windows_pe",
        Arc::new(windows::WindowsPeParser::default()) as Arc<dyn Parser>,
    );

    m.insert(
        "windows_pml",
        Arc::new(windows::WindowsPmlParser) as Arc<dyn Parser>,
    );
    
    m.insert(
        "windows_hive",
        Arc::new(windows::WindowsHiveParser::default()) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_whatsapp",
        Arc::new(ios::IosWhatsAppParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_imessage",
        Arc::new(ios::IosIMessageParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_callhistory",
        Arc::new(ios::IosCallHistoryParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_contacts",
        Arc::new(ios::IosContactsParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_safari",
        Arc::new(ios::IosSafariParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_tcc",
        Arc::new(ios::IosTccParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_knowledgec",
        Arc::new(ios::IosKnowledgeCParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_routined",
        Arc::new(ios::IosRoutinedParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_interactionc",
        Arc::new(ios::IosInteractionCParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_datausage",
        Arc::new(ios::IosDataUsageParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_photos",
        Arc::new(ios::IosPhotosParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_calendar",
        Arc::new(ios::IosCalendarParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_mail",
        Arc::new(ios::IosMailParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_android_sms",
        Arc::new(android::AndroidSmsParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_notes",
        Arc::new(ios::IosNotesParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_app_manifest",
        Arc::new(ios::IosAppManifestParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_app_container",
        Arc::new(ios::IosAppContainerParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_frontboard",
        Arc::new(ios::IosFrontboardParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_iconstate",
        Arc::new(ios::IosIconStateParser) as Arc<dyn Parser>,
    );

    m.insert(
        "mobile_ios_mobileinstallation_log",
        Arc::new(ios::IosMobileInstallationLogParser) as Arc<dyn Parser>,
    );

    m.insert(
        "macos_safari",
        Arc::new(macos::MacosSafariParser) as Arc<dyn Parser>,
    );

    m.insert(
        "macos_chromium",
        Arc::new(macos::MacosChromiumParser) as Arc<dyn Parser>,
    );

    m.insert(
        "macos_firefox",
        Arc::new(macos::MacosFirefoxParser) as Arc<dyn Parser>,
    );

    m.insert(
        "macos_imessage",
        Arc::new(macos::MacosIMessageParser) as Arc<dyn Parser>,
    );

    m.insert(
        "macos_whatsapp",
        Arc::new(macos::MacosWhatsAppParser) as Arc<dyn Parser>,
    );

    m.insert(
        "macos_sharedfilelist",
        Arc::new(macos::MacosSharedFileListParser) as Arc<dyn Parser>,
    );

    m.insert(
        "macos_keychain",
        Arc::new(macos::MacosKeychainParser) as Arc<dyn Parser>,
    );

    m.insert(
        "macos_quarantine",
        Arc::new(macos::MacosQuarantineParser) as Arc<dyn Parser>,
    );

    m.insert(
        "macos_launchd",
        Arc::new(macos::MacosLaunchdParser) as Arc<dyn Parser>,
    );

    m.insert(
        "macos_loginwindow",
        Arc::new(macos::MacosLoginwindowParser) as Arc<dyn Parser>,
    );

    m.insert(
        "macos_network",
        Arc::new(macos::MacosNetworkParser) as Arc<dyn Parser>,
    );

    m.insert(
        "macos_spotlight",
        Arc::new(macos::MacosSpotlightParser) as Arc<dyn Parser>,
    );

    m.insert(
        "macos_app_bundle",
        Arc::new(macos::MacosAppBundleParser) as Arc<dyn Parser>,
    );

    m.insert(
        "macos_install_history",
        Arc::new(macos::MacosInstallHistoryParser) as Arc<dyn Parser>,
    );

    m.insert(
        "macos_package_receipt",
        Arc::new(macos::MacosPackageReceiptParser) as Arc<dyn Parser>,
    );

    m.insert(
        "macos_container_registration",
        Arc::new(macos::MacosContainerRegistrationParser) as Arc<dyn Parser>,
    );

    m
}
