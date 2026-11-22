use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{self, BufReader, ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use backhand::kind::{BE_V4_0, Kind, LE_V4_0};
use backhand::{FilesystemReader, InnerNode, Squashfs, SquashfsFileReader, SuperBlock};
use rustix::fs::{Mode, OFlags, open};
use sha2::{Digest, Sha256};

use crate::domain::desktop_entry::{ParsedDesktopEntry, parse_desktop_entry};
use crate::domain::elf::{
    AppImagePayloadKind, SquashFsEndian, compute_elf_end_offset, detect_payload_at_window,
    iso_pvd_offsets, parse_elf_header,
};
use crate::domain::error::DomainError;
use crate::domain::iso9660::{Iso9660Archive, IsoEntryKind, IsoExtent};
use crate::domain::models::{
    ExtractedIcon, ExtractedMetadata, IconFormat, InspectedAppImage, STANDARD_ICON_BUCKETS,
    validate_sha256_hex,
};
use crate::domain::path_safety::{normalize_archive_entry_path, resolve_contained_symlink};
use crate::domain::ports::AppImageExtractorPort;
use crate::domain::sanitizer::sanitize_single_line_value;
use crate::domain::svg_sanitizer::validate_safe_svg;

const MAX_ELF_TABLE_BYTES: usize = 1024 * 1024;
const MAX_APPIMAGE_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_NODES: usize = 250_000;
const MAX_SQUASHFS_ID_COUNT: u16 = 16_384;
const MAX_SQUASHFS_METADATA_READ_BYTES: u64 = 128 * 1024 * 1024;
const MAX_DESKTOP_BYTES: u64 = 256 * 1024;
const MAX_ICON_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TOTAL_EXTRACTED_BYTES: u64 = 32 * 1024 * 1024;
const MAX_DESKTOP_CANDIDATES_PROBED: usize = 32;
const MAX_ICON_CANDIDATES_PROBED: usize = 64;
const MAX_TOTAL_ICONS: usize = 16;
const MAX_SYMLINK_HOPS: usize = 8;
const SQUASHFS_NOT_SET: u64 = u64::MAX;

#[derive(Default)]
pub struct StaticAppImageExtractor;

impl StaticAppImageExtractor {
    pub fn new() -> Self {
        Self
    }
}

impl AppImageExtractorPort for StaticAppImageExtractor {
    fn inspect_and_extract(
        &self,
        appimage_path: &Path,
        expected_sha256: Option<&str>,
    ) -> Result<InspectedAppImage, DomainError> {
        let fd = open(
            appimage_path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| {
            if errno == rustix::io::Errno::LOOP {
                DomainError::NotARegularFile(appimage_path.to_path_buf())
            } else if errno == rustix::io::Errno::NOENT {
                DomainError::InputFileNotFound(appimage_path.to_path_buf())
            } else {
                DomainError::Io {
                    context: format!("opening AppImage '{}'", appimage_path.display()),
                    reason: errno.to_string(),
                }
            }
        })?;
        let mut file = File::from(fd);

        let meta = file.metadata().map_err(|err| DomainError::Io {
            context: format!("statting AppImage '{}'", appimage_path.display()),
            reason: err.to_string(),
        })?;
        if !meta.is_file() {
            return Err(DomainError::NotARegularFile(appimage_path.to_path_buf()));
        }
        let file_len = meta.len();
        if file_len > MAX_APPIMAGE_FILE_BYTES {
            return Err(DomainError::ResourceLimitExceeded {
                resource: "AppImage file size".to_string(),
                limit: MAX_APPIMAGE_FILE_BYTES,
                context: appimage_path.display().to_string(),
            });
        }

        let sha256 = compute_sha256_rewound(&mut file, appimage_path)?;
        if let Some(expected_raw) = expected_sha256 {
            let expected = validate_sha256_hex(expected_raw)?;
            if sha256 != expected {
                return Err(DomainError::Sha256Mismatch {
                    path: appimage_path.to_path_buf(),
                    expected,
                    actual: sha256,
                });
            }
        }

        let mut header_buf = [0u8; 4096];
        let header_read =
            read_up_to(&mut file, &mut header_buf).map_err(|err| DomainError::Io {
                context: format!("reading ELF header '{}'", appimage_path.display()),
                reason: err.to_string(),
            })?;
        let summary = parse_elf_header(&header_buf[..header_read], appimage_path)?;

        let program_table = if summary.phnum > 0 && summary.phoff > 0 {
            let size = usize::from(summary.phentsize)
                .checked_mul(usize::from(summary.phnum))
                .ok_or_else(|| DomainError::InvalidAppImage {
                    path: appimage_path.to_path_buf(),
                    reason: "ELF program header size overflow".to_string(),
                })?;
            if size > MAX_ELF_TABLE_BYTES {
                return Err(DomainError::ResourceLimitExceeded {
                    resource: "ELF program header table".to_string(),
                    limit: MAX_ELF_TABLE_BYTES as u64,
                    context: appimage_path.display().to_string(),
                });
            }
            read_slice_at(&mut file, summary.phoff, size, appimage_path)?
        } else {
            Vec::new()
        };

        let section_table = if summary.shnum > 0 && summary.shoff > 0 {
            let size = usize::from(summary.shentsize)
                .checked_mul(usize::from(summary.shnum))
                .ok_or_else(|| DomainError::InvalidAppImage {
                    path: appimage_path.to_path_buf(),
                    reason: "ELF section header size overflow".to_string(),
                })?;
            if size > MAX_ELF_TABLE_BYTES {
                return Err(DomainError::ResourceLimitExceeded {
                    resource: "ELF section header table".to_string(),
                    limit: MAX_ELF_TABLE_BYTES as u64,
                    context: appimage_path.display().to_string(),
                });
            }
            read_slice_at(&mut file, summary.shoff, size, appimage_path)?
        } else {
            Vec::new()
        };

        let elf_end = compute_elf_end_offset(
            &summary,
            &program_table,
            &section_table,
            file_len,
            appimage_path,
        )?;

        let window = read_up_to_at(&mut file, elf_end, 4096, appimage_path)?;
        let mut iso_probe_bufs = Vec::new();
        for pvd_offset in iso_pvd_offsets() {
            if file_len >= pvd_offset + 6 {
                iso_probe_bufs.push(read_up_to_at(&mut file, pvd_offset, 8, appimage_path)?);
            }
        }
        let iso_probe_slices: Vec<&[u8]> = iso_probe_bufs.iter().map(Vec::as_slice).collect();

        let payload_kind =
            detect_payload_at_window(&summary, elf_end, &window, &iso_probe_slices, appimage_path)?;

        let metadata = match payload_kind {
            AppImagePayloadKind::Type2SquashFs { offset, endian } => {
                extract_from_squashfs(file, file_len, offset, endian, appimage_path)?
            }
            AppImagePayloadKind::Type1Iso => extract_from_iso9660(file, file_len, appimage_path)?,
        };

        Ok(InspectedAppImage { metadata, sha256 })
    }
}

struct BudgetedReader {
    inner: File,
    remaining_bytes: u64,
}

impl Read for BudgetedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining_bytes == 0 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "SquashFS read budget exceeded",
            ));
        }
        let max_len = (buf.len() as u64).min(self.remaining_bytes) as usize;
        let n = self.inner.read(&mut buf[..max_len])?;
        self.remaining_bytes -= n as u64;
        Ok(n)
    }
}

impl Seek for BudgetedReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

enum VirtualNode<'a> {
    File(PayloadHandle<'a>),
    Symlink(String),
    Dir,
}

enum PayloadHandle<'a> {
    Squashfs(&'a SquashfsFileReader),
    Iso { size: u64, extents: &'a [IsoExtent] },
}

struct ArchiveIndex<'a> {
    nodes: BTreeMap<PathBuf, VirtualNode<'a>>,
}

impl<'a> ArchiveIndex<'a> {
    fn resolve_target_entry(&self, initial_path: &Path) -> Result<Option<PathBuf>, DomainError> {
        let mut current = initial_path.to_path_buf();
        let mut visited: HashSet<PathBuf> = HashSet::new();

        for _ in 0..=MAX_SYMLINK_HOPS {
            if !visited.insert(current.clone()) {
                return Err(DomainError::InvalidAppImage {
                    path: initial_path.to_path_buf(),
                    reason: format!("cyclic symlink inside archive at '{}'", current.display()),
                });
            }
            match self.nodes.get(&current) {
                Some(VirtualNode::File(_)) => return Ok(Some(current)),
                Some(VirtualNode::Symlink(target)) => {
                    current = resolve_contained_symlink(&current, target)?;
                }
                Some(VirtualNode::Dir) | None => return Ok(None),
            }
        }

        Err(DomainError::InvalidAppImage {
            path: initial_path.to_path_buf(),
            reason: "symlink chain exceeded maximum hop limit inside archive".to_string(),
        })
    }

    fn resolve_file(&self, initial_path: &Path) -> Result<Option<&PayloadHandle<'a>>, DomainError> {
        let Some(resolved) = self.resolve_target_entry(initial_path)? else {
            return Ok(None);
        };
        match self.nodes.get(&resolved) {
            Some(VirtualNode::File(handle)) => Ok(Some(handle)),
            _ => Ok(None),
        }
    }
}

fn validate_squashfs_superblock(
    sb: &SuperBlock,
    offset: u64,
    file_len: u64,
    appimage_path: &Path,
) -> Result<(), DomainError> {
    if sb.inode_count > MAX_ARCHIVE_NODES as u32 {
        return Err(DomainError::ResourceLimitExceeded {
            resource: "SquashFS superblock inode_count".to_string(),
            limit: MAX_ARCHIVE_NODES as u64,
            context: appimage_path.display().to_string(),
        });
    }
    if sb.frag_count > MAX_ARCHIVE_NODES as u32 {
        return Err(DomainError::ResourceLimitExceeded {
            resource: "SquashFS superblock frag_count".to_string(),
            limit: MAX_ARCHIVE_NODES as u64,
            context: appimage_path.display().to_string(),
        });
    }
    if sb.id_count > MAX_SQUASHFS_ID_COUNT {
        return Err(DomainError::ResourceLimitExceeded {
            resource: "SquashFS superblock id_count".to_string(),
            limit: u64::from(MAX_SQUASHFS_ID_COUNT),
            context: appimage_path.display().to_string(),
        });
    }
    if sb.bytes_used < SuperBlock::SIZE as u64 {
        return Err(DomainError::InvalidAppImage {
            path: appimage_path.to_path_buf(),
            reason: "SquashFS bytes_used smaller than SuperBlock".to_string(),
        });
    }
    let archive_end =
        offset
            .checked_add(sb.bytes_used)
            .ok_or_else(|| DomainError::InvalidAppImage {
                path: appimage_path.to_path_buf(),
                reason: "SquashFS offset + bytes_used overflow".to_string(),
            })?;
    if archive_end > file_len {
        return Err(DomainError::InvalidAppImage {
            path: appimage_path.to_path_buf(),
            reason: "SquashFS bytes_used exceeds AppImage file length".to_string(),
        });
    }
    if sb.inode_table >= sb.bytes_used
        || sb.dir_table >= sb.bytes_used
        || sb.inode_table >= sb.dir_table
        || sb.id_table >= sb.bytes_used
        || (sb.frag_table != SQUASHFS_NOT_SET && sb.frag_table >= sb.bytes_used)
    {
        return Err(DomainError::InvalidAppImage {
            path: appimage_path.to_path_buf(),
            reason: "invalid SquashFS metadata table offsets".to_string(),
        });
    }
    for table in [sb.inode_table, sb.dir_table, sb.id_table, sb.frag_table] {
        if table != SQUASHFS_NOT_SET && offset.checked_add(table).is_none() {
            return Err(DomainError::InvalidAppImage {
                path: appimage_path.to_path_buf(),
                reason: "SquashFS table offset overflow".to_string(),
            });
        }
    }
    Ok(())
}

fn extract_from_squashfs(
    mut file: File,
    file_len: u64,
    offset: u64,
    endian: SquashFsEndian,
    appimage_path: &Path,
) -> Result<ExtractedMetadata, DomainError> {
    if offset > file_len || file_len - offset < SuperBlock::SIZE as u64 {
        return Err(DomainError::InvalidAppImage {
            path: appimage_path.to_path_buf(),
            reason: "truncated SquashFS superblock".to_string(),
        });
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|err| DomainError::Io {
            context: format!("seeking SquashFS superblock '{}'", appimage_path.display()),
            reason: err.to_string(),
        })?;
    let inner_kind = match endian {
        SquashFsEndian::Little => LE_V4_0,
        SquashFsEndian::Big => BE_V4_0,
    };
    let kind = Kind::from_const(inner_kind).map_err(|err| DomainError::InvalidAppImage {
        path: appimage_path.to_path_buf(),
        reason: err,
    })?;
    let mut sb_reader = BufReader::new(&mut file);
    let (superblock, _) = Squashfs::superblock_and_compression_options(&mut sb_reader, &kind)
        .map_err(|err| DomainError::InvalidAppImage {
            path: appimage_path.to_path_buf(),
            reason: format!("invalid SquashFS superblock at offset {offset}: {err}"),
        })?;
    drop(sb_reader);
    validate_squashfs_superblock(&superblock, offset, file_len, appimage_path)?;

    file.seek(SeekFrom::Start(0))
        .map_err(|err| DomainError::Io {
            context: format!("rewinding '{}'", appimage_path.display()),
            reason: err.to_string(),
        })?;
    let budgeted = BudgetedReader {
        inner: file,
        remaining_bytes: MAX_SQUASHFS_METADATA_READ_BYTES,
    };
    let fs =
        FilesystemReader::from_reader_with_offset_and_kind(BufReader::new(budgeted), offset, kind)
            .map_err(|err| DomainError::InvalidAppImage {
                path: appimage_path.to_path_buf(),
                reason: format!("failed to parse SquashFS payload at offset {offset}: {err}"),
            })?;

    let mut nodes = BTreeMap::new();
    for (idx, node) in fs.files().enumerate() {
        if idx >= MAX_ARCHIVE_NODES {
            return Err(DomainError::ResourceLimitExceeded {
                resource: "SquashFS archive entries".to_string(),
                limit: MAX_ARCHIVE_NODES as u64,
                context: appimage_path.display().to_string(),
            });
        }
        if node.fullpath == Path::new("/") {
            continue;
        }
        let Some(raw_str) = node.fullpath.to_str() else {
            return Err(DomainError::UnsafePathTraversal(
                node.fullpath.display().to_string(),
            ));
        };
        let normalized = normalize_archive_entry_path(raw_str)?;
        match &node.inner {
            InnerNode::File(reader) => {
                nodes.insert(
                    normalized,
                    VirtualNode::File(PayloadHandle::Squashfs(reader)),
                );
            }
            InnerNode::Symlink(sym) => {
                let target = sym
                    .link
                    .to_str()
                    .ok_or_else(|| DomainError::SymlinkEscape {
                        link: normalized.display().to_string(),
                        target: sym.link.display().to_string(),
                    })?;
                nodes.insert(normalized, VirtualNode::Symlink(target.to_string()));
            }
            InnerNode::Dir(_) => {
                nodes.insert(normalized, VirtualNode::Dir);
            }
            _ => {}
        }
    }

    let index = ArchiveIndex { nodes };
    extract_metadata_from_index(&index, appimage_path, |handle, max_bytes| match handle {
        PayloadHandle::Squashfs(reader) => read_squashfs_file_bounded(&fs, reader, max_bytes),
        PayloadHandle::Iso { .. } => Err(DomainError::InvalidAppImage {
            path: appimage_path.to_path_buf(),
            reason: "internal extractor mismatch".to_string(),
        }),
    })
}

fn extract_from_iso9660(
    mut file: File,
    file_len: u64,
    appimage_path: &Path,
) -> Result<ExtractedMetadata, DomainError> {
    let archive = Iso9660Archive::open(&mut file, file_len, appimage_path)?;
    let mut nodes = BTreeMap::new();

    for (idx, entry) in archive.entries().iter().enumerate() {
        if idx >= MAX_ARCHIVE_NODES {
            return Err(DomainError::ResourceLimitExceeded {
                resource: "ISO9660 archive entries".to_string(),
                limit: MAX_ARCHIVE_NODES as u64,
                context: appimage_path.display().to_string(),
            });
        }
        match &entry.kind {
            IsoEntryKind::File { size, extents } => {
                nodes.insert(
                    entry.path.clone(),
                    VirtualNode::File(PayloadHandle::Iso {
                        size: *size,
                        extents: extents.as_slice(),
                    }),
                );
            }
            IsoEntryKind::Symlink(target) => {
                nodes.insert(entry.path.clone(), VirtualNode::Symlink(target.clone()));
            }
            IsoEntryKind::Dir => {
                nodes.insert(entry.path.clone(), VirtualNode::Dir);
            }
        }
    }

    let file_cell = RefCell::new(file);
    let index = ArchiveIndex { nodes };
    extract_metadata_from_index(&index, appimage_path, |handle, max_bytes| match handle {
        PayloadHandle::Iso { size, extents } => {
            let mut f = file_cell.borrow_mut();
            archive.read_file(&mut *f, *size, extents, max_bytes, appimage_path)
        }
        PayloadHandle::Squashfs(_) => Err(DomainError::InvalidAppImage {
            path: appimage_path.to_path_buf(),
            reason: "internal extractor mismatch".to_string(),
        }),
    })
}

fn extract_metadata_from_index<'a, F>(
    index: &ArchiveIndex<'a>,
    appimage_path: &Path,
    read_handle: F,
) -> Result<ExtractedMetadata, DomainError>
where
    F: Fn(&PayloadHandle<'a>, u64) -> Result<Vec<u8>, DomainError>,
{
    let mut root_desktop_candidates: Vec<PathBuf> = Vec::new();
    let mut usr_desktop_candidates: Vec<PathBuf> = Vec::new();

    for path in index.nodes.keys() {
        let is_desktop = path
            .file_name()
            .and_then(|f| f.to_str())
            .is_some_and(|name| name.ends_with(".desktop"));
        if !is_desktop {
            continue;
        }
        if path.components().count() == 1 {
            root_desktop_candidates.push(path.clone());
        } else if path.starts_with("usr/share/applications") && path.components().count() == 4 {
            usr_desktop_candidates.push(path.clone());
        }
    }

    root_desktop_candidates.sort();
    usr_desktop_candidates.sort();

    let all_candidates = root_desktop_candidates
        .into_iter()
        .chain(usr_desktop_candidates);

    let mut fallback_parsed: Option<ParsedDesktopEntry> = None;
    let mut selected_parsed: Option<ParsedDesktopEntry> = None;
    let mut total_extracted_bytes = 0u64;

    for (probed, candidate) in all_candidates.enumerate() {
        if probed >= MAX_DESKTOP_CANDIDATES_PROBED {
            break;
        }
        let Some(handle) = index.resolve_file(&candidate)? else {
            continue;
        };
        let remaining_budget = MAX_TOTAL_EXTRACTED_BYTES.saturating_sub(total_extracted_bytes);
        if remaining_budget == 0 {
            return Err(DomainError::ResourceLimitExceeded {
                resource: "total extracted AppImage metadata bytes".to_string(),
                limit: MAX_TOTAL_EXTRACTED_BYTES,
                context: appimage_path.display().to_string(),
            });
        }
        let bytes = read_handle(handle, MAX_DESKTOP_BYTES.min(remaining_budget))?;
        total_extracted_bytes = total_extracted_bytes.saturating_add(bytes.len() as u64);
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        let Ok(parsed) = parse_desktop_entry(&text) else {
            continue;
        };
        if !parsed.no_display {
            selected_parsed = Some(parsed);
            break;
        }
        if fallback_parsed.is_none() {
            fallback_parsed = Some(parsed);
        }
    }

    let parsed = selected_parsed.or(fallback_parsed).ok_or_else(|| {
        DomainError::InvalidDesktopEntry(format!(
            "no valid Application .desktop file found inside '{}'",
            appimage_path.display()
        ))
    })?;

    let icons = extract_icons(
        index,
        parsed.icon.as_deref(),
        &read_handle,
        &mut total_extracted_bytes,
    )?;

    let fallback_name = appimage_path
        .file_stem()
        .and_then(|s| s.to_str())
        .map(sanitize_single_line_value)
        .unwrap_or_default();
    let app_name = parsed
        .app_name
        .filter(|n| !n.is_empty())
        .unwrap_or(fallback_name);

    Ok(ExtractedMetadata {
        app_name,
        version: parsed.appimage_version,
        generic_name: parsed.generic_name,
        comment: parsed.comment,
        icon_key: parsed.icon,
        categories: parsed.categories,
        mime_types: parsed.mime_types,
        keywords: parsed.keywords,
        startup_wm_class: parsed.startup_wm_class,
        terminal: parsed.terminal,
        startup_notify: parsed.startup_notify,
        exec_field_code: parsed.exec_field_code,
        icons,
    })
}

fn extract_icons<'a, F>(
    index: &ArchiveIndex<'a>,
    icon_key: Option<&str>,
    read_handle: &F,
    total_extracted_bytes: &mut u64,
) -> Result<Vec<ExtractedIcon>, DomainError>
where
    F: Fn(&PayloadHandle<'a>, u64) -> Result<Vec<u8>, DomainError>,
{
    let mut candidate_paths: Vec<PathBuf> = Vec::new();
    let mut seen_resolved: HashSet<PathBuf> = HashSet::new();

    if let Some(raw_icon) = icon_key {
        let trimmed = raw_icon.trim();
        if let Ok(rel) = normalize_archive_entry_path(trimmed)
            && has_supported_icon_extension(&rel)
        {
            candidate_paths.push(rel);
        }
        if let Some(stem) = extract_safe_icon_stem(trimmed) {
            let png_name = format!("{stem}.png");
            let svg_name = format!("{stem}.svg");
            for path in index.nodes.keys() {
                let Some(fname) = path.file_name().and_then(|f| f.to_str()) else {
                    continue;
                };
                if fname != png_name && fname != svg_name {
                    continue;
                }
                if path.components().count() == 1
                    || path.starts_with("usr/share/icons/hicolor")
                    || path.starts_with("usr/share/pixmaps")
                {
                    candidate_paths.push(path.clone());
                }
            }
        }
    }

    candidate_paths.push(PathBuf::from(".DirIcon"));

    let mut extracted = Vec::new();
    let mut probed_reads = 0usize;

    for candidate in candidate_paths {
        if extracted.len() >= MAX_TOTAL_ICONS || probed_reads >= MAX_ICON_CANDIDATES_PROBED {
            break;
        }
        let Some(resolved) = index.resolve_target_entry(&candidate)? else {
            continue;
        };
        if !seen_resolved.insert(resolved.clone()) {
            continue;
        }
        let Some(VirtualNode::File(handle)) = index.nodes.get(&resolved) else {
            continue;
        };
        probed_reads += 1;

        let remaining_budget = MAX_TOTAL_EXTRACTED_BYTES.saturating_sub(*total_extracted_bytes);
        if remaining_budget == 0 {
            break;
        }
        let bytes = match read_handle(handle, MAX_ICON_BYTES.min(remaining_budget)) {
            Ok(bytes) => bytes,
            Err(DomainError::ResourceLimitExceeded { .. }) => continue,
            Err(err) => return Err(err),
        };
        *total_extracted_bytes = total_extracted_bytes.saturating_add(bytes.len() as u64);
        if let Some(icon) = classify_icon_bytes(&resolved, bytes) {
            extracted.push(icon);
        }
    }

    Ok(extracted)
}

fn has_supported_icon_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("png") || ext.eq_ignore_ascii_case("svg"))
}

fn classify_icon_bytes(path: &Path, bytes: Vec<u8>) -> Option<ExtractedIcon> {
    if let Some((width, height)) = parse_png_dimensions(&bytes) {
        let max_dim = width.max(height);
        let size_dir = if let Some(hint) = extract_hicolor_size_dir(path) {
            hint
        } else {
            let bucket = map_dimension_to_hicolor_bucket(max_dim);
            format!("{bucket}x{bucket}")
        };
        return Some(ExtractedIcon {
            size_dir,
            format: IconFormat::Png,
            bytes,
        });
    }

    if validate_safe_svg(&bytes).is_ok() {
        return Some(ExtractedIcon {
            size_dir: "scalable".to_string(),
            format: IconFormat::Svg,
            bytes,
        });
    }

    None
}

fn parse_png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    const PNG_SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    if bytes.len() < 24 || bytes.get(0..8)? != PNG_SIG || bytes.get(12..16)? != b"IHDR" {
        return None;
    }
    let w = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let h = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    if w == 0 || h == 0 {
        return None;
    }
    Some((w, h))
}

fn extract_hicolor_size_dir(path: &Path) -> Option<String> {
    let parts: Vec<&str> = path.iter().filter_map(|p| p.to_str()).collect();
    for window in parts.windows(3) {
        if window[0] == "hicolor" && window[2] == "apps" {
            let size = window[1];
            if let Some((w, h)) = size.split_once('x')
                && w == h
                && let Ok(dim) = w.parse::<u32>()
                && STANDARD_ICON_BUCKETS.contains(&dim)
            {
                return Some(size.to_string());
            }
        }
    }
    None
}

fn map_dimension_to_hicolor_bucket(dim: u32) -> u32 {
    for &bucket in &STANDARD_ICON_BUCKETS {
        if dim <= bucket {
            return bucket;
        }
    }
    512
}

fn extract_safe_icon_stem(raw_icon: &str) -> Option<&str> {
    let file_part = Path::new(raw_icon).file_name()?.to_str()?;
    if file_part.is_empty()
        || file_part.contains('\0')
        || file_part.contains("..")
        || file_part.starts_with('.')
    {
        return None;
    }
    let stem = file_part
        .strip_suffix(".png")
        .or_else(|| file_part.strip_suffix(".svg"))
        .or_else(|| file_part.strip_suffix(".xpm"))
        .unwrap_or(file_part);
    if stem.is_empty() { None } else { Some(stem) }
}

fn read_squashfs_file_bounded(
    fs: &FilesystemReader<'_>,
    file_reader: &SquashfsFileReader,
    max_bytes: u64,
) -> Result<Vec<u8>, DomainError> {
    let declared_len = file_reader.file_len() as u64;
    if declared_len > max_bytes {
        return Err(DomainError::ResourceLimitExceeded {
            resource: "SquashFS file entry".to_string(),
            limit: max_bytes,
            context: format!("declared size {declared_len} bytes"),
        });
    }
    let reader =
        fs.file(file_reader)
            .reader_checked()
            .map_err(|err| DomainError::InvalidAppImage {
                path: PathBuf::from("<squashfs>"),
                reason: format!("failed to open SquashFS entry: {err}"),
            })?;
    let mut out = Vec::with_capacity((declared_len as usize).min(64 * 1024));
    reader
        .take(max_bytes + 1)
        .read_to_end(&mut out)
        .map_err(|err| DomainError::Io {
            context: "reading SquashFS file entry".to_string(),
            reason: err.to_string(),
        })?;
    if (out.len() as u64) > max_bytes {
        return Err(DomainError::ResourceLimitExceeded {
            resource: "SquashFS decompressed file".to_string(),
            limit: max_bytes,
            context: "bounded reader".to_string(),
        });
    }
    Ok(out)
}

fn compute_sha256_rewound(file: &mut File, path: &Path) -> Result<String, DomainError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|err| DomainError::Io {
            context: format!("seeking '{}' for sha256", path.display()),
            reason: err.to_string(),
        })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|err| DomainError::Io {
            context: format!("reading '{}' for sha256", path.display()),
            reason: err.to_string(),
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|err| DomainError::Io {
            context: format!("rewinding '{}' after sha256", path.display()),
            reason: err.to_string(),
        })?;
    Ok(hex::encode(hasher.finalize()))
}

fn read_up_to(file: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        let n = file.read(&mut buf[total..])?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

fn read_slice_at(
    file: &mut File,
    offset: u64,
    size: usize,
    path: &Path,
) -> Result<Vec<u8>, DomainError> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|err| DomainError::Io {
            context: format!("seeking ELF table in '{}'", path.display()),
            reason: err.to_string(),
        })?;
    let mut buf = vec![0u8; size];
    let n = read_up_to(file, &mut buf).map_err(|err| DomainError::Io {
        context: format!("reading ELF table in '{}'", path.display()),
        reason: err.to_string(),
    })?;
    buf.truncate(n);
    Ok(buf)
}

fn read_up_to_at(
    file: &mut File,
    offset: u64,
    max_len: usize,
    path: &Path,
) -> Result<Vec<u8>, DomainError> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|err| DomainError::Io {
            context: format!("seeking payload header in '{}'", path.display()),
            reason: err.to_string(),
        })?;
    let mut buf = vec![0u8; max_len];
    let n = read_up_to(file, &mut buf).map_err(|err| DomainError::Io {
        context: format!("reading payload header in '{}'", path.display()),
        reason: err.to_string(),
    })?;
    buf.truncate(n);
    Ok(buf)
}

fn is_executable_regular_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    meta.is_file() && (meta.permissions().mode() & 0o111) != 0
}

fn is_safe_search_dir(dir: &Path) -> bool {
    if !dir.is_absolute() {
        return false;
    }
    let Ok(meta) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    let Ok(target_meta) = std::fs::metadata(dir) else {
        return false;
    };
    if !target_meta.is_dir() {
        return false;
    }
    let mode = if meta.file_type().is_symlink() {
        target_meta.permissions().mode()
    } else {
        meta.permissions().mode()
    };
    (mode & 0o002) == 0
}

pub fn resolve_trusted_executable(name: &str) -> Option<PathBuf> {
    for system_dir in ["/usr/bin", "/bin"] {
        let candidate = Path::new(system_dir).join(name);
        if is_executable_regular_file(&candidate) {
            return Some(candidate);
        }
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        if !is_safe_search_dir(&dir) {
            continue;
        }
        let candidate = dir.join(name);
        if is_executable_regular_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use super::{
        ArchiveIndex, MAX_ICON_BYTES, MAX_TOTAL_EXTRACTED_BYTES, PayloadHandle, VirtualNode,
        extract_hicolor_size_dir, extract_icons, extract_safe_icon_stem,
        has_supported_icon_extension, parse_png_dimensions,
    };
    use crate::domain::error::DomainError;
    use crate::domain::models::IconFormat;

    fn sample_png(dim: u32) -> Vec<u8> {
        let mut png = Vec::new();
        png.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
        png.extend_from_slice(&13u32.to_be_bytes());
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&dim.to_be_bytes());
        png.extend_from_slice(&dim.to_be_bytes());
        png.extend_from_slice(&[8, 6, 0, 0, 0, 0, 0, 0, 0]);
        png
    }

    #[test]
    fn validates_png_and_hicolor_icon_paths() {
        let mut png = Vec::new();
        png.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
        png.extend_from_slice(&13u32.to_be_bytes());
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&128u32.to_be_bytes());
        png.extend_from_slice(&128u32.to_be_bytes());
        assert_eq!(parse_png_dimensions(&png), Some((128, 128)));
        assert_eq!(parse_png_dimensions(b"not-a-png"), None);

        assert_eq!(
            extract_hicolor_size_dir(Path::new("usr/share/icons/hicolor/256x256/apps/app.png")),
            Some("256x256".to_string())
        );
        assert_eq!(
            extract_hicolor_size_dir(Path::new("usr/share/icons/hicolor/999x999/apps/app.png")),
            None
        );

        assert_eq!(
            extract_safe_icon_stem("usr/share/icons/obsidian.png"),
            Some("obsidian")
        );
        assert_eq!(extract_safe_icon_stem(".."), None);

        assert!(has_supported_icon_extension(Path::new("bruno.png")));
        assert!(has_supported_icon_extension(Path::new("BRUNO.PNG")));
        assert!(has_supported_icon_extension(Path::new(
            "usr/share/icons/bruno.svg"
        )));
        assert!(has_supported_icon_extension(Path::new("BRUNO.SVG")));
        assert!(!has_supported_icon_extension(Path::new("bruno")));
        assert!(!has_supported_icon_extension(Path::new("bruno.xpm")));
        assert!(!has_supported_icon_extension(Path::new(".DirIcon")));
    }

    #[test]
    fn extract_icons_skips_extensionless_root_binary_without_probing_or_budget_loss() {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            PathBuf::from("bruno"),
            VirtualNode::File(PayloadHandle::Iso {
                size: 4096,
                extents: &[],
            }),
        );
        nodes.insert(
            PathBuf::from("bruno.png"),
            VirtualNode::File(PayloadHandle::Iso {
                size: 100,
                extents: &[],
            }),
        );
        nodes.insert(
            PathBuf::from(".DirIcon"),
            VirtualNode::Symlink("bruno.png".to_string()),
        );
        let index = ArchiveIndex { nodes };

        let probed_sizes: RefCell<Vec<u64>> = RefCell::new(Vec::new());
        let expected_png = sample_png(256);
        let mut total_bytes = 0u64;

        let icons = extract_icons(
            &index,
            Some("bruno"),
            &|handle, _max_bytes| {
                let PayloadHandle::Iso { size, .. } = handle else {
                    panic!("unexpected handle");
                };
                probed_sizes.borrow_mut().push(*size);
                if *size == 4096 {
                    panic!("extensionless root binary must never be probed");
                }
                Ok(expected_png.clone())
            },
            &mut total_bytes,
        )
        .unwrap();

        assert_eq!(*probed_sizes.borrow(), vec![100]);
        assert_eq!(total_bytes, expected_png.len() as u64);
        assert_eq!(icons.len(), 1);
        assert_eq!(icons[0].format, IconFormat::Png);
        assert_eq!(icons[0].size_dir, "256x256");
    }

    #[test]
    fn extract_icons_skips_oversized_icon_candidates_and_keeps_valid_smaller_icon() {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            PathBuf::from("usr/share/icons/hicolor/512x512/apps/bruno.png"),
            VirtualNode::File(PayloadHandle::Iso {
                size: MAX_ICON_BYTES + 1,
                extents: &[],
            }),
        );
        nodes.insert(
            PathBuf::from("usr/share/icons/hicolor/128x128/apps/bruno.png"),
            VirtualNode::File(PayloadHandle::Iso {
                size: 128,
                extents: &[],
            }),
        );
        nodes.insert(
            PathBuf::from(".DirIcon"),
            VirtualNode::Symlink("usr/share/icons/hicolor/512x512/apps/bruno.png".to_string()),
        );
        let index = ArchiveIndex { nodes };

        let mut total_bytes = 0u64;
        let expected_png = sample_png(128);
        let icons = extract_icons(
            &index,
            Some("bruno"),
            &|handle, max_bytes| {
                let PayloadHandle::Iso { size, .. } = handle else {
                    panic!("unexpected handle");
                };
                if *size > max_bytes {
                    return Err(DomainError::ResourceLimitExceeded {
                        resource: "ISO9660 file entry".to_string(),
                        limit: max_bytes,
                        context: format!("declared size {size} bytes"),
                    });
                }
                Ok(expected_png.clone())
            },
            &mut total_bytes,
        )
        .unwrap();

        assert_eq!(icons.len(), 1);
        assert_eq!(icons[0].size_dir, "128x128");
        assert_eq!(total_bytes, expected_png.len() as u64);
    }

    #[test]
    fn extract_icons_breaks_on_exhausted_budget_and_propagates_non_limit_errors() {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            PathBuf::from("app.png"),
            VirtualNode::File(PayloadHandle::Iso {
                size: 64,
                extents: &[],
            }),
        );
        let index = ArchiveIndex { nodes };

        let mut exhausted_budget = MAX_TOTAL_EXTRACTED_BYTES;
        let empty = extract_icons(
            &index,
            Some("app"),
            &|_handle, _max_bytes| panic!("must not read when remaining_budget == 0"),
            &mut exhausted_budget,
        )
        .unwrap();
        assert!(empty.is_empty());

        let mut zero_used = 0u64;
        let err = extract_icons(
            &index,
            Some("app"),
            &|_handle, _max_bytes| {
                Err(DomainError::Io {
                    context: "reading icon".to_string(),
                    reason: "disk error".to_string(),
                })
            },
            &mut zero_used,
        )
        .unwrap_err();
        assert!(matches!(err, DomainError::Io { .. }));
    }
}
