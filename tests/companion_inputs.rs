use anyhow::Result;
use exhume_artefacts::input::{CompanionOverride, filesystem_input, local_input};
use exhume_artefacts::{CompanionSpec, ObjectParsed, Parser, ParserInput, ParserSource};
use exhume_filesystem::{Filesystem, folder_impl::FolderFS};

struct Companions;
impl Parser for Companions {
    fn name(&self) -> &'static str {
        "companions"
    }
    fn companion_specs(&self) -> &'static [CompanionSpec] {
        const SPECS: &[CompanionSpec] = &[
            CompanionSpec::required_suffix("wal", "-wal"),
            CompanionSpec::optional_sibling("extra", "extra.bin"),
        ];
        SPECS
    }
    fn run_into(
        &self,
        _: ParserInput,
        _: &mut dyn FnMut(ObjectParsed) -> Result<()>,
    ) -> Result<()> {
        Ok(())
    }
}

#[test]
fn explicit_override_keeps_other_discovered_roles_and_reads_on_demand() {
    let dir = tempfile::tempdir().unwrap();
    let primary = dir.path().join("main.db");
    let override_path = dir.path().join("collected.bin");
    std::fs::write(&primary, b"main").unwrap();
    std::fs::write(dir.path().join("main.db-wal"), b"automatic").unwrap();
    std::fs::write(dir.path().join("extra.bin"), b"sibling").unwrap();
    std::fs::write(&override_path, b"explicit").unwrap();
    let overrides = [CompanionOverride {
        role: "wal".into(),
        path: override_path.to_str().unwrap().into(),
    }];
    let ParserInput::Compound(mut input) = local_input(&Companions, &primary, &overrides).unwrap()
    else {
        panic!("expected compound")
    };
    assert_eq!(input.companions.len(), 2);
    assert_eq!(input.companions[0].original_path, overrides[0].path);
    // Construction has not preloaded the companion bytes.
    std::fs::write(&override_path, b"updated").unwrap();
    let mut bytes = Vec::new();
    input
        .provider
        .copy_to(&input.companions[0], &mut bytes)
        .unwrap();
    assert_eq!(bytes, b"updated");
    bytes.clear();
    input
        .provider
        .copy_to(&input.companions[1], &mut bytes)
        .unwrap();
    assert_eq!(bytes, b"sibling");
}

#[test]
fn missing_required_invalid_explicit_unknown_duplicate_and_directory_fail() {
    let dir = tempfile::tempdir().unwrap();
    let primary = dir.path().join("main.db");
    std::fs::write(&primary, b"main").unwrap();
    assert!(local_input(&Companions, &primary, &[]).is_err());
    std::fs::write(dir.path().join("main.db-wal"), b"automatic").unwrap();
    assert!(local_input(&Companions, &primary, &[]).is_ok());
    for overrides in [
        vec![CompanionOverride {
            role: "unknown".into(),
            path: primary.to_str().unwrap().into(),
        }],
        vec![CompanionOverride {
            role: "wal".into(),
            path: dir.path().join("absent").to_str().unwrap().into(),
        }],
        vec![CompanionOverride {
            role: "wal".into(),
            path: dir.path().to_str().unwrap().into(),
        }],
        vec![
            CompanionOverride {
                role: "wal".into(),
                path: "a".into(),
            },
            CompanionOverride {
                role: "wal".into(),
                path: "b".into(),
            },
        ],
    ] {
        assert!(local_input(&Companions, &primary, &overrides).is_err());
    }
    // Optional means only absence is ignored, not an invalid entry type.
    std::fs::create_dir(dir.path().join("extra.bin")).unwrap();
    assert!(local_input(&Companions, &primary, &[]).is_err());
}

#[test]
fn filesystem_companions_use_the_evidence_provider() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("main.db"), b"main").unwrap();
    std::fs::write(dir.path().join("journal"), b"journal bytes").unwrap();
    let mut fs = FolderFS::new(dir.path().to_path_buf());
    let record = fs.get_file_by_path("/main.db", 0).unwrap();
    let source = ParserSource::new(
        "primary",
        "/main.db",
        None,
        None,
        Some(fs.file_identifier(&record)),
    );
    let overrides = [CompanionOverride {
        role: "wal".into(),
        path: "/journal".into(),
    }];
    let ParserInput::Compound(mut input) =
        filesystem_input(&Companions, &mut fs, source, &overrides).unwrap()
    else {
        panic!("expected compound")
    };
    let mut bytes = Vec::new();
    input.provider.copy_to(&input.primary, &mut bytes).unwrap();
    assert_eq!(bytes, b"main");
    bytes.clear();
    input
        .provider
        .copy_to(&input.companions[0], &mut bytes)
        .unwrap();
    assert_eq!(bytes, b"journal bytes");
}
