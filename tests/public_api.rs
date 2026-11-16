//! Public import paths and parser identifiers survive internal module moves.

use exhume_artefacts::parsers::{self, android, ios, mobile, windows};
use std::any::TypeId;

fn same_type<Old: 'static, New: 'static>() {
    assert_eq!(TypeId::of::<Old>(), TypeId::of::<New>());
}

#[test]
fn existing_parser_paths_alias_the_platform_entry_points() {
    same_type::<mobile::AndroidSmsParser, android::AndroidSmsParser>();
    same_type::<mobile::IosAppContainerParser, ios::IosAppContainerParser>();
    same_type::<mobile::IosAppManifestParser, ios::IosAppManifestParser>();
    same_type::<mobile::IosCalendarParser, ios::IosCalendarParser>();
    same_type::<mobile::IosCallHistoryParser, ios::IosCallHistoryParser>();
    same_type::<mobile::IosContactsParser, ios::IosContactsParser>();
    same_type::<mobile::IosDataUsageParser, ios::IosDataUsageParser>();
    same_type::<mobile::IosFrontboardParser, ios::IosFrontboardParser>();
    same_type::<mobile::IosIMessageParser, ios::IosIMessageParser>();
    same_type::<mobile::IosIconStateParser, ios::IosIconStateParser>();
    same_type::<mobile::IosInteractionCParser, ios::IosInteractionCParser>();
    same_type::<mobile::IosKnowledgeCParser, ios::IosKnowledgeCParser>();
    same_type::<mobile::IosMailParser, ios::IosMailParser>();
    same_type::<mobile::IosMobileInstallationLogParser, ios::IosMobileInstallationLogParser>();
    same_type::<mobile::IosNotesParser, ios::IosNotesParser>();
    same_type::<mobile::IosPhotosParser, ios::IosPhotosParser>();
    same_type::<mobile::IosRoutinedParser, ios::IosRoutinedParser>();
    same_type::<mobile::IosSafariParser, ios::IosSafariParser>();
    same_type::<mobile::IosTccParser, ios::IosTccParser>();
    same_type::<mobile::IosWhatsAppParser, ios::IosWhatsAppParser>();
    same_type::<parsers::evtx::WindowsEvtxParser, windows::evtx::WindowsEvtxParser>();
    same_type::<parsers::pe::WindowsPeParser, windows::pe::WindowsPeParser>();
    same_type::<parsers::pml::WindowsPmlParser, windows::pml::WindowsPmlParser>();
    same_type::<parsers::pml::StringTable, windows::pml::StringTable>();
    same_type::<parsers::pml::ProcessInfo, windows::pml::ProcessInfo>();
    same_type::<parsers::pml::ProcessTable, windows::pml::ProcessTable>();
}

#[test]
fn sqlcipher_keeps_its_original_public_path() {
    use exhume_artefacts::{formats::sqlite::sqlcipher as formats, sqlcipher as original};
    same_type::<original::SqlCipherKey, formats::SqlCipherKey>();
    same_type::<original::SqlCipherProfile, formats::SqlCipherProfile>();
    same_type::<original::SqlCipherError, formats::SqlCipherError>();
    same_type::<original::SqlCipherInspection, formats::SqlCipherInspection>();
    // Both paths expose the inspection entry point as well as its types.
    let _: fn(_, &original::SqlCipherKey, original::SqlCipherProfile) -> _ =
        formats::inspect_database;
    let _: fn(_, &formats::SqlCipherKey, formats::SqlCipherProfile) -> _ =
        original::inspect_database;
}

#[test]
fn registry_retains_identifiers_used_by_cli_and_indexer_rules() {
    let registry: parsers::ParserRegistry = parsers::build_registry();
    let mut names: Vec<_> = registry.keys().copied().collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "macos_app_bundle",
            "macos_chromium",
            "macos_container_registration",
            "macos_firefox",
            "macos_imessage",
            "macos_install_history",
            "macos_keychain",
            "macos_launchd",
            "macos_loginwindow",
            "macos_network",
            "macos_package_receipt",
            "macos_quarantine",
            "macos_safari",
            "macos_sharedfilelist",
            "macos_spotlight",
            "macos_whatsapp",
            "mobile_android_sms",
            "mobile_ios_app_container",
            "mobile_ios_app_manifest",
            "mobile_ios_calendar",
            "mobile_ios_callhistory",
            "mobile_ios_contacts",
            "mobile_ios_datausage",
            "mobile_ios_frontboard",
            "mobile_ios_iconstate",
            "mobile_ios_imessage",
            "mobile_ios_interactionc",
            "mobile_ios_knowledgec",
            "mobile_ios_mail",
            "mobile_ios_mobileinstallation_log",
            "mobile_ios_notes",
            "mobile_ios_photos",
            "mobile_ios_routined",
            "mobile_ios_safari",
            "mobile_ios_tcc",
            "mobile_ios_whatsapp",
            "windows_evtx",
            "windows_pe",
            "windows_pml",
        ]
    );
    for (name, parser) in &registry {
        assert_eq!(*name, parser.name());
    }
}
