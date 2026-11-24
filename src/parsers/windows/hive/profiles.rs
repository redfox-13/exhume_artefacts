use super::{
    Artefact, browser_activity, devices, file_operations, network, persistence,
    program_execution, security, sysinfo, user_behavior,
};

pub(super) fn category_profiles() -> Vec<(&'static str, Vec<Artefact>)> {
    vec![
        ("devices", devices::artefacts()),
        ("persistence", persistence::artefacts()),
        ("program_execution", program_execution::artefacts()),
        ("browser_activity", browser_activity::artefacts()),
        ("file_operations", file_operations::artefacts()),
        ("user_behavior", user_behavior::artefacts()),
        ("sysinfo", sysinfo::artefacts()),
        ("network", network::artefacts()),
        ("security", security::artefacts()),
    ]
}

pub(super) fn all_artefacts() -> Vec<Artefact> {
    category_profiles()
        .into_iter()
        .flat_map(|(_, artefacts)| artefacts)
        .collect()
}

pub(super) fn profile(name: &str) -> Option<Vec<Artefact>> {
    let normalized = normalize(name);
    category_profiles()
        .into_iter()
        .chain(hive_profiles())
        .find(|(profile, _)| *profile == normalized)
        .map(|(_, artefacts)| artefacts)
}

fn hive_profiles() -> Vec<(&'static str, Vec<Artefact>)> {
    vec![
        ("system", select(&[
            devices::usb::KIND,
            devices::usbstor::KIND,
            devices::volume_mappings::KIND,
            persistence::appcertdlls::KIND,
            persistence::print_components::KIND,
            persistence::services::KIND,
            persistence::session_manager::KIND,
            program_execution::appcompat_cache::KIND,
            program_execution::bam::KIND,
            program_execution::dam::KIND,
            sysinfo::computer_name::KIND,
            sysinfo::timezone::KIND,
            network::interfaces::KIND,
            network::port_proxy::KIND,
            network::routes::KIND,
            security::lsa::KIND,
        ])),
        ("software", select(&[
            devices::emdmgmt::KIND,
            devices::audio_devices::KIND,
            devices::portable_devices::KIND,
            devices::print_devices::KIND,
            persistence::appinit::KIND,
            persistence::cmd_autorun::KIND,
            persistence::com_registration::KIND,
            persistence::ifeo::KIND,
            persistence::run::KIND,
            persistence::runonceex::KIND,
            persistence::startup_approved::KIND,
            persistence::task_cache::KIND,
            persistence::winlogon::KIND,
            persistence::netsh::KIND,
            persistence::shell_overlay::KIND,
            persistence::wsh_settings::KIND,
            persistence::wab::KIND,
            persistence::command_shell::KIND,
            persistence::file_associations::KIND,
            program_execution::app_paths::KIND,
            program_execution::appcompat_flags::KIND,
            program_execution::uninstall::KIND,
            program_execution::heap::KIND,
            program_execution::msi_products::KIND,
            program_execution::drivers32::KIND,
            browser_activity::security_zones::KIND,
            browser_activity::outlook_homepage::KIND,
            network::network_list::KIND,
            network::proxy_settings::KIND,
            network::gpo_settings::KIND,
            security::defender::KIND,
            security::uac::KIND,
            security::security_center::KIND,
            security::execution_policy::KIND,
            security::uac_bypass::KIND,
            sysinfo::profiles::KIND,
            sysinfo::windows_version::KIND,
            sysinfo::timezone::KIND,
            sysinfo::wbem::KIND,
            sysinfo::spp_clients::KIND,
            sysinfo::scheduling_agent::KIND,
            sysinfo::wow64::KIND,
            sysinfo::sus_client::KIND,
            sysinfo::calibration::KIND,
            user_behavior::last_logged_on::KIND,
            user_behavior::app_keys::KIND,
            user_behavior::this_pc_policy::KIND,
            file_operations::mru_controls::KIND,
        ])),
        ("sam", select(&[security::sam_accounts::KIND, security::sam_aliases::KIND])),
        ("ntuser", select(&[
            browser_activity::typed_urls::KIND,
            browser_activity::security_zones::KIND,
            browser_activity::outlook_homepage::KIND,
            file_operations::comdlg32::KIND,
            file_operations::recent_docs::KIND,
            file_operations::shellbags::KIND,
            file_operations::typed_paths::KIND,
            file_operations::mru_controls::KIND,
            network::mapped_drives::KIND,
            persistence::com_registration::KIND,
            persistence::file_associations::KIND,
            persistence::run::KIND,
            persistence::runonceex::KIND,
            persistence::startup_approved::KIND,
            persistence::winlogon::KIND,
            program_execution::app_paths::KIND,
            program_execution::appcompat_flags::KIND,
            program_execution::mui_cache::KIND,
            program_execution::drivers32::KIND,
            user_behavior::app_keys::KIND,
            user_behavior::last_logged_on::KIND,
            user_behavior::this_pc_policy::KIND,
            user_behavior::feature_usage::KIND,
            user_behavior::recent_apps::KIND,
            user_behavior::run_mru::KIND,
            user_behavior::userassist::KIND,
            user_behavior::wordwheel_query::KIND,
        ])),
        ("default", select(&[
            browser_activity::security_zones::KIND,
            browser_activity::outlook_homepage::KIND,
            file_operations::comdlg32::KIND,
            file_operations::recent_docs::KIND,
            file_operations::typed_paths::KIND,
            file_operations::mru_controls::KIND,
            network::mapped_drives::KIND,
            persistence::run::KIND,
            persistence::runonceex::KIND,
            program_execution::app_paths::KIND,
            program_execution::appcompat_flags::KIND,
            program_execution::mui_cache::KIND,
            program_execution::drivers32::KIND,
            user_behavior::feature_usage::KIND,
            user_behavior::recent_apps::KIND,
            user_behavior::run_mru::KIND,
            user_behavior::userassist::KIND,
            user_behavior::wordwheel_query::KIND,
            user_behavior::app_keys::KIND,
            user_behavior::last_logged_on::KIND,
            user_behavior::this_pc_policy::KIND,
        ])),
        ("usrclass", select(&[
            file_operations::shellbags::KIND,
            persistence::com_registration::KIND,
            persistence::file_associations::KIND,
            security::uac_bypass::KIND,
            program_execution::mui_cache::KIND,
        ])),
        ("amcache", select(&[program_execution::amcache::KIND])),
        ("syscache", select(&[program_execution::syscache::KIND])),
    ]
}

fn select(names: &[&str]) -> Vec<Artefact> {
    all_artefacts()
        .into_iter()
        .filter(|artefact| names.iter().any(|selected| *selected == artefact.kind))
        .collect()
}

fn normalize(name: &str) -> String {
    let mut normalized = name
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .replace(' ', "_");
    for extension in [".dat", ".hve"] {
        if normalized.ends_with(extension) {
            normalized.truncate(normalized.len() - extension.len());
            break;
        }
    }
    normalized
}
