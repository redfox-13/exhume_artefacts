use super::{Artefact, browser_activity, devices, file_operations, network, persistence};
use super::{program_execution, security, sysinfo, user_behavior};

macro_rules! define_profiles {
    (
        artefacts {
            $(
                $category:ident {
                    $($name:ident => $module:ident),* $(,)?
                }
            ),* $(,)?
        }
        hive_profiles {
            $(
                $hive:literal => [
                    $($selected_category:ident :: $selected_name:ident),* $(,)?
                ]
            ),* $(,)?
        }
    ) => {
        pub(super) const ARTEFACT_OPTION_DESCRIPTION: &str = concat!(
            "Choose one artefact by name. Full artefact names are accepted e.g. 'windows.hive.group.artefact'. Available: ",
            $(
                $(concat!(stringify!($category), ".", stringify!($name), ", "),)*
            )*
        );

        pub(super) const PROFILE_OPTION_DESCRIPTION: &str = concat!(
            "Choose one profile by name. Hive-file profiles: ",
            $(
                concat!($hive, ", "),
            )*
            "Artefact-type profiles: ",
            $(
                concat!(stringify!($category), ", "),
            )*
        );

        fn category_profiles() -> Vec<(&'static str, Vec<Artefact>)> {
            vec![
                $(
                    (
                        stringify!($category),
                        vec![$($category::$module::artefact()),*],
                    ),
                )*
            ]
        }

        fn hive_profiles() -> Vec<(&'static str, Vec<Artefact>)> {
            vec![
                $(
                    (
                        $hive,
                        select(&[
                            $(
                                concat!(
                                    stringify!($selected_category),
                                    ".",
                                    stringify!($selected_name),
                                ),
                            )*
                        ]),
                    ),
                )*
            ]
        }
    };
}

define_profiles! {
    artefacts {
        devices {
            usb => usb,
            usbstor => usbstor,
            volume_mappings => volume_mappings,
            readyboost_history => emdmgmt,
            audio_endpoints => audio_devices,
            portable_devices => portable_devices,
            printers => print_devices,
        },
        persistence {
            appinit => appinit,
            appcert_dlls => appcertdlls,
            command_processor => cmd_autorun,
            com_registration => com_registration,
            image_file_execution_options => ifeo,
            print_components => print_components,
            run => run,
            runonce_ex => runonceex,
            service => services,
            session_manager => session_manager,
            startup_approved => startup_approved,
            task_cache => task_cache,
            winlogon => winlogon,
            netsh_helpers => netsh,
            shell_overlay_handlers => shell_overlay,
            wsh_settings => wsh_settings,
            windows_address_book => wab,
            file_type_commands => command_shell,
            exefile_associations => file_associations,
        },
        program_execution {
            amcache => amcache,
            app_paths => app_paths,
            appcompat_cache => appcompat_cache,
            appcompat_flags => appcompat_flags,
            bam => bam,
            dam => dam,
            mui_cache => mui_cache,
            syscache => syscache,
            uninstall => uninstall,
            heap_leak_detection => heap,
            msi_products => msi_products,
            drivers32 => drivers32,
        },
        browser_activity {
            typed_urls => typed_urls,
            security_zones => security_zones,
            outlook_webview => outlook_homepage,
        },
        file_operations {
            comdlg32 => comdlg32,
            recent_docs => recent_docs,
            shellbags => shellbags,
            typed_paths => typed_paths,
            recent_document_controls => mru_controls,
        },
        user_behavior {
            feature_usage => feature_usage,
            recent_apps => recent_apps,
            run_mru => run_mru,
            userassist => userassist,
            wordwheel_query => wordwheel_query,
            last_logged_on => last_logged_on,
            app_keys => app_keys,
            this_pc_policy => this_pc_policy,
        },
        sysinfo {
            computer_name => computer_name,
            user_profiles => profiles,
            windows_version => windows_version,
            timezone => timezone,
            wbem => wbem,
            spp_clients => spp_clients,
            scheduling_agent => scheduling_agent,
            wow64_configuration => wow64,
            windows_update_client => sus_client,
            display_calibration => calibration,
        },
        network {
            interfaces => interfaces,
            mapped_drives => mapped_drives,
            network_list => network_list,
            port_proxy => port_proxy,
            proxy_settings => proxy_settings,
            persistent_routes => routes,
            group_policy_settings => gpo_settings,
        },
        security {
            defender => defender,
            lsa => lsa,
            sam_accounts => sam_accounts,
            sam_aliases => sam_aliases,
            uac => uac,
            security_center => security_center,
            powershell_execution_policy => execution_policy,
            file_handler_overrides => uac_bypass,
        },
    }
    hive_profiles {
        "system" => [
            devices::usb,
            devices::usbstor,
            devices::volume_mappings,
            persistence::appcert_dlls,
            persistence::print_components,
            persistence::service,
            persistence::session_manager,
            program_execution::appcompat_cache,
            program_execution::bam,
            program_execution::dam,
            sysinfo::computer_name,
            sysinfo::timezone,
            network::interfaces,
            network::port_proxy,
            network::persistent_routes,
            security::lsa,
        ],
        "software" => [
            devices::readyboost_history,
            devices::audio_endpoints,
            devices::portable_devices,
            devices::printers,
            persistence::appinit,
            persistence::command_processor,
            persistence::com_registration,
            persistence::image_file_execution_options,
            persistence::run,
            persistence::runonce_ex,
            persistence::startup_approved,
            persistence::task_cache,
            persistence::winlogon,
            persistence::netsh_helpers,
            persistence::shell_overlay_handlers,
            persistence::wsh_settings,
            persistence::windows_address_book,
            persistence::file_type_commands,
            persistence::exefile_associations,
            program_execution::app_paths,
            program_execution::appcompat_flags,
            program_execution::uninstall,
            program_execution::heap_leak_detection,
            program_execution::msi_products,
            program_execution::drivers32,
            browser_activity::security_zones,
            browser_activity::outlook_webview,
            network::network_list,
            network::proxy_settings,
            network::group_policy_settings,
            security::defender,
            security::uac,
            security::security_center,
            security::powershell_execution_policy,
            security::file_handler_overrides,
            sysinfo::user_profiles,
            sysinfo::windows_version,
            sysinfo::timezone,
            sysinfo::wbem,
            sysinfo::spp_clients,
            sysinfo::scheduling_agent,
            sysinfo::wow64_configuration,
            sysinfo::windows_update_client,
            sysinfo::display_calibration,
            user_behavior::last_logged_on,
            user_behavior::app_keys,
            user_behavior::this_pc_policy,
            file_operations::recent_document_controls,
        ],
        "sam" => [
            security::sam_accounts,
            security::sam_aliases,
        ],
        "ntuser" => [
            browser_activity::typed_urls,
            browser_activity::security_zones,
            browser_activity::outlook_webview,
            file_operations::comdlg32,
            file_operations::recent_docs,
            file_operations::shellbags,
            file_operations::typed_paths,
            file_operations::recent_document_controls,
            network::mapped_drives,
            persistence::com_registration,
            persistence::exefile_associations,
            persistence::run,
            persistence::runonce_ex,
            persistence::startup_approved,
            persistence::winlogon,
            program_execution::app_paths,
            program_execution::appcompat_flags,
            program_execution::mui_cache,
            program_execution::drivers32,
            user_behavior::app_keys,
            user_behavior::last_logged_on,
            user_behavior::this_pc_policy,
            user_behavior::feature_usage,
            user_behavior::recent_apps,
            user_behavior::run_mru,
            user_behavior::userassist,
            user_behavior::wordwheel_query,
        ],
        "default" => [
            browser_activity::security_zones,
            browser_activity::outlook_webview,
            file_operations::comdlg32,
            file_operations::recent_docs,
            file_operations::typed_paths,
            file_operations::recent_document_controls,
            network::mapped_drives,
            persistence::run,
            persistence::runonce_ex,
            program_execution::app_paths,
            program_execution::appcompat_flags,
            program_execution::mui_cache,
            program_execution::drivers32,
            user_behavior::feature_usage,
            user_behavior::recent_apps,
            user_behavior::run_mru,
            user_behavior::userassist,
            user_behavior::wordwheel_query,
            user_behavior::app_keys,
            user_behavior::last_logged_on,
            user_behavior::this_pc_policy,
        ],
        "usrclass" => [
            file_operations::shellbags,
            persistence::com_registration,
            persistence::exefile_associations,
            security::file_handler_overrides,
            program_execution::mui_cache,
        ],
        "amcache" => [
            program_execution::amcache,
        ],
        "syscache" => [
            program_execution::syscache,
        ],
    }
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

fn select(names: &[&str]) -> Vec<Artefact> {
    all_artefacts()
        .into_iter()
        .filter(|artefact| {
            let kind = artefact
                .kind
                .strip_prefix(super::HIVE_KIND_PREFIX)
                .unwrap_or(artefact.kind);
            names.iter().any(|selected| *selected == kind)
        })
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
