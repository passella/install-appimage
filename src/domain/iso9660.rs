use std::collections::{HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::domain::error::DomainError;
use crate::domain::path_safety::normalize_archive_entry_path;
use crate::domain::sanitizer::is_bidi_or_invisible_format;

const ISO_SECTOR_SIZE: usize = 2048;
const ISO_VD_START_OFFSET: u64 = 16 * 2048;
const MAX_VD_SECTORS: usize = 32;
const MAX_ISO_METADATA_READ_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ISO_DIR_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ISO_ENTRIES: usize = 250_000;
const MAX_ISO_DIRS: usize = 50_000;
const MAX_ISO_DEPTH: usize = 64;
const MAX_CE_HOPS: usize = 16;
const MAX_FILENAME_BYTES: usize = 4096;
const MAX_SYMLINK_BYTES: usize = 4096;
const MAX_FILE_EXTENTS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsoExtent {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsoEntryKind {
    File { size: u64, extents: Vec<IsoExtent> },
    Dir,
    Symlink(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsoEntry {
    pub path: PathBuf,
    pub kind: IsoEntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iso9660Archive {
    entries: Vec<IsoEntry>,
}

#[derive(Debug, Clone, Copy)]
struct VolumeDescriptorInfo {
    block_size: u16,
    root_lba: u32,
    root_size: u64,
    root_xattr_len: u8,
}

#[derive(Debug, Clone)]
struct PendingDir {
    path: PathBuf,
    lba: u32,
    size: u64,
    xattr_len: u8,
    depth: usize,
}

#[derive(Debug, Default)]
struct RockRidgeMetadata {
    saw_rock_ridge: bool,
    sp_skip: Option<usize>,
    name_bytes: Vec<u8>,
    has_name: bool,
    is_current_or_parent: bool,
    symlink_target: Option<String>,
    symlink_need_slash: bool,
    posix_mode: Option<u32>,
    relocated_child_lba: Option<u32>,
    relocated_entry: bool,
}

struct PendingMultiExtent {
    path: PathBuf,
    size: u64,
    extents: Vec<IsoExtent>,
}

struct MetadataBudget {
    remaining: u64,
}

impl MetadataBudget {
    fn new(limit: u64) -> Self {
        Self { remaining: limit }
    }

    fn consume(&mut self, bytes: u64, path: &Path, context: &str) -> Result<(), DomainError> {
        if bytes > self.remaining {
            return Err(DomainError::ResourceLimitExceeded {
                resource: format!("ISO9660 {context}"),
                limit: MAX_ISO_METADATA_READ_BYTES,
                context: path.display().to_string(),
            });
        }
        self.remaining -= bytes;
        Ok(())
    }
}

impl Iso9660Archive {
    pub fn open<R: Read + Seek>(
        reader: &mut R,
        file_len: u64,
        display_path: &Path,
    ) -> Result<Self, DomainError> {
        let mut budget = MetadataBudget::new(MAX_ISO_METADATA_READ_BYTES);
        let (pvd, joliet_svd) =
            scan_volume_descriptors(reader, file_len, &mut budget, display_path)?;

        let pvd = pvd.ok_or_else(|| DomainError::InvalidAppImage {
            path: display_path.to_path_buf(),
            reason: "missing ISO9660 Primary Volume Descriptor".to_string(),
        })?;

        let (pvd_entries, saw_rock_ridge) =
            traverse_volume(reader, file_len, pvd, false, &mut budget, display_path)?;

        if saw_rock_ridge {
            return Ok(Self {
                entries: pvd_entries,
            });
        }

        if let Some(svd) = joliet_svd {
            let (joliet_entries, _) =
                traverse_volume(reader, file_len, svd, true, &mut budget, display_path)?;
            return Ok(Self {
                entries: joliet_entries,
            });
        }

        Ok(Self {
            entries: pvd_entries,
        })
    }

    pub fn entries(&self) -> &[IsoEntry] {
        &self.entries
    }

    pub fn read_file<R: Read + Seek>(
        &self,
        reader: &mut R,
        size: u64,
        extents: &[IsoExtent],
        max_bytes: u64,
        display_path: &Path,
    ) -> Result<Vec<u8>, DomainError> {
        if size > max_bytes {
            return Err(DomainError::ResourceLimitExceeded {
                resource: "ISO9660 file entry".to_string(),
                limit: max_bytes,
                context: format!("declared size {size} bytes"),
            });
        }

        let mut out = Vec::with_capacity((size as usize).min(64 * 1024));
        let mut total_read = 0u64;

        for extent in extents {
            let Some(end) = extent.offset.checked_add(extent.length) else {
                return Err(DomainError::InvalidAppImage {
                    path: display_path.to_path_buf(),
                    reason: "ISO9660 file extent offset overflow".to_string(),
                });
            };
            let next_total = total_read.checked_add(extent.length).ok_or_else(|| {
                DomainError::InvalidAppImage {
                    path: display_path.to_path_buf(),
                    reason: "ISO9660 multi-extent size overflow".to_string(),
                }
            })?;
            if next_total > max_bytes || next_total > size {
                return Err(DomainError::ResourceLimitExceeded {
                    resource: "ISO9660 file entry".to_string(),
                    limit: max_bytes,
                    context: display_path.display().to_string(),
                });
            }
            let _ = end;
            reader
                .seek(SeekFrom::Start(extent.offset))
                .map_err(|err| DomainError::Io {
                    context: format!("seeking ISO9660 extent in '{}'", display_path.display()),
                    reason: err.to_string(),
                })?;

            let chunk_len =
                usize::try_from(extent.length).map_err(|_| DomainError::ResourceLimitExceeded {
                    resource: "ISO9660 file extent".to_string(),
                    limit: max_bytes,
                    context: display_path.display().to_string(),
                })?;
            let start = out.len();
            out.resize(start + chunk_len, 0);
            reader
                .read_exact(&mut out[start..])
                .map_err(|err| DomainError::InvalidAppImage {
                    path: display_path.to_path_buf(),
                    reason: format!("truncated ISO9660 file data: {err}"),
                })?;
            total_read = next_total;
        }

        if total_read != size {
            return Err(DomainError::InvalidAppImage {
                path: display_path.to_path_buf(),
                reason: "ISO9660 file extent sizes do not match declared file length".to_string(),
            });
        }

        Ok(out)
    }
}

fn scan_volume_descriptors<R: Read + Seek>(
    reader: &mut R,
    file_len: u64,
    budget: &mut MetadataBudget,
    display_path: &Path,
) -> Result<(Option<VolumeDescriptorInfo>, Option<VolumeDescriptorInfo>), DomainError> {
    let mut pvd: Option<VolumeDescriptorInfo> = None;
    let mut best_joliet: Option<(u8, VolumeDescriptorInfo)> = None;
    let mut sector = [0u8; ISO_SECTOR_SIZE];

    for idx in 0..MAX_VD_SECTORS {
        let offset = ISO_VD_START_OFFSET + (idx as u64) * (ISO_SECTOR_SIZE as u64);
        let Some(end) = offset.checked_add(ISO_SECTOR_SIZE as u64) else {
            break;
        };
        if end > file_len {
            break;
        }
        budget.consume(ISO_SECTOR_SIZE as u64, display_path, "volume descriptors")?;
        reader
            .seek(SeekFrom::Start(offset))
            .map_err(|err| DomainError::Io {
                context: format!(
                    "seeking ISO9660 volume descriptor '{}'",
                    display_path.display()
                ),
                reason: err.to_string(),
            })?;
        reader
            .read_exact(&mut sector)
            .map_err(|err| DomainError::InvalidAppImage {
                path: display_path.to_path_buf(),
                reason: format!("truncated ISO9660 volume descriptor: {err}"),
            })?;

        if &sector[1..6] != b"CD001" {
            break;
        }

        let vd_type = sector[0];
        if vd_type == 255 {
            break;
        }

        if vd_type == 1 && pvd.is_none() {
            pvd = Some(parse_volume_descriptor_root(&sector, display_path)?);
        } else if vd_type == 2
            && let Some(level) = detect_joliet_level(&sector[88..120])
        {
            let svd = parse_volume_descriptor_root(&sector, display_path)?;
            let replace = best_joliet.is_none_or(|(cur_lvl, _)| level > cur_lvl);
            if replace {
                best_joliet = Some((level, svd));
            }
        }
    }

    Ok((pvd, best_joliet.map(|(_, svd)| svd)))
}

fn parse_volume_descriptor_root(
    sector: &[u8; ISO_SECTOR_SIZE],
    display_path: &Path,
) -> Result<VolumeDescriptorInfo, DomainError> {
    let block_le = u16::from_le_bytes([sector[128], sector[129]]);
    let block_be = u16::from_be_bytes([sector[130], sector[131]]);
    if block_le != block_be || !matches!(block_le, 512 | 1024 | 2048) {
        return Err(DomainError::InvalidAppImage {
            path: display_path.to_path_buf(),
            reason: format!("unsupported ISO9660 logical block size {block_le}"),
        });
    }

    let root_rec = &sector[156..190];
    let rec_len = root_rec[0] as usize;
    if rec_len < 34 || (root_rec[25] & 0x02) == 0 {
        return Err(DomainError::InvalidAppImage {
            path: display_path.to_path_buf(),
            reason: "invalid ISO9660 root directory record".to_string(),
        });
    }

    let root_xattr_len = root_rec[1];
    let root_lba = u32::from_le_bytes([root_rec[2], root_rec[3], root_rec[4], root_rec[5]]);
    let root_size = u64::from(u32::from_le_bytes([
        root_rec[10],
        root_rec[11],
        root_rec[12],
        root_rec[13],
    ]));

    Ok(VolumeDescriptorInfo {
        block_size: block_le,
        root_lba,
        root_size,
        root_xattr_len,
    })
}

fn detect_joliet_level(escape: &[u8]) -> Option<u8> {
    if escape.len() < 3 {
        return None;
    }
    let level = match &escape[0..3] {
        b"%/E" => 3,
        b"%/C" => 2,
        b"%/@" => 1,
        _ => return None,
    };
    if escape[3..].iter().all(|&b| b == 0x00 || b == 0x20) {
        Some(level)
    } else {
        None
    }
}

fn traverse_volume<R: Read + Seek>(
    reader: &mut R,
    file_len: u64,
    vol: VolumeDescriptorInfo,
    is_joliet: bool,
    budget: &mut MetadataBudget,
    display_path: &Path,
) -> Result<(Vec<IsoEntry>, bool), DomainError> {
    let mut entries = Vec::new();
    let mut queue = VecDeque::new();
    let mut visited_dirs = HashSet::new();
    let mut susp_skip: Option<usize> = None;
    let mut saw_rock_ridge = false;

    queue.push_back(PendingDir {
        path: PathBuf::new(),
        lba: vol.root_lba,
        size: vol.root_size,
        xattr_len: vol.root_xattr_len,
        depth: 0,
    });

    while let Some(dir) = queue.pop_front() {
        if dir.depth > MAX_ISO_DEPTH {
            return Err(DomainError::ResourceLimitExceeded {
                resource: "ISO9660 directory depth".to_string(),
                limit: MAX_ISO_DEPTH as u64,
                context: display_path.display().to_string(),
            });
        }
        if visited_dirs.len() >= MAX_ISO_DIRS {
            return Err(DomainError::ResourceLimitExceeded {
                resource: "ISO9660 directory count".to_string(),
                limit: MAX_ISO_DIRS as u64,
                context: display_path.display().to_string(),
            });
        }
        if !visited_dirs.insert(dir.lba) {
            return Err(DomainError::InvalidAppImage {
                path: display_path.to_path_buf(),
                reason: format!("cyclic ISO9660 directory loop detected at LBA {}", dir.lba),
            });
        }
        if dir.size > MAX_ISO_DIR_BYTES {
            return Err(DomainError::ResourceLimitExceeded {
                resource: "ISO9660 directory extent".to_string(),
                limit: MAX_ISO_DIR_BYTES,
                context: display_path.display().to_string(),
            });
        }

        let dir_offset = compute_extent_offset(
            dir.lba,
            dir.xattr_len,
            vol.block_size,
            dir.size,
            file_len,
            display_path,
        )?;

        let dir_len_usize =
            usize::try_from(dir.size).map_err(|_| DomainError::ResourceLimitExceeded {
                resource: "ISO9660 directory extent".to_string(),
                limit: MAX_ISO_DIR_BYTES,
                context: display_path.display().to_string(),
            })?;
        budget.consume(dir.size, display_path, "directory metadata")?;

        let mut dir_buf = vec![0u8; dir_len_usize];
        reader
            .seek(SeekFrom::Start(dir_offset))
            .map_err(|err| DomainError::Io {
                context: format!("seeking ISO9660 directory '{}'", display_path.display()),
                reason: err.to_string(),
            })?;
        reader
            .read_exact(&mut dir_buf)
            .map_err(|err| DomainError::InvalidAppImage {
                path: display_path.to_path_buf(),
                reason: format!("truncated ISO9660 directory extent: {err}"),
            })?;

        parse_directory_extent(
            reader,
            file_len,
            vol.block_size,
            is_joliet,
            &dir,
            &dir_buf,
            &mut susp_skip,
            &mut saw_rock_ridge,
            &mut queue,
            &mut entries,
            budget,
            display_path,
        )?;
    }

    Ok((entries, saw_rock_ridge))
}

#[allow(clippy::too_many_arguments)]
fn parse_directory_extent<R: Read + Seek>(
    reader: &mut R,
    file_len: u64,
    block_size: u16,
    is_joliet: bool,
    dir: &PendingDir,
    dir_buf: &[u8],
    susp_skip: &mut Option<usize>,
    saw_rock_ridge: &mut bool,
    queue: &mut VecDeque<PendingDir>,
    entries: &mut Vec<IsoEntry>,
    budget: &mut MetadataBudget,
    display_path: &Path,
) -> Result<(), DomainError> {
    let bs = usize::from(block_size);
    let mut pos = 0usize;
    let mut pending_multi: Option<PendingMultiExtent> = None;

    while pos < dir_buf.len() {
        let rec_len = usize::from(dir_buf[pos]);
        if rec_len == 0 {
            let next = (pos / bs + 1) * bs;
            if next <= pos {
                break;
            }
            pos = next;
            continue;
        }

        if rec_len < 34 || pos + rec_len > dir_buf.len() {
            return Err(DomainError::InvalidAppImage {
                path: display_path.to_path_buf(),
                reason: "malformed or truncated ISO9660 directory record".to_string(),
            });
        }

        let rec = &dir_buf[pos..pos + rec_len];
        pos += rec_len;

        let xattr_len = rec[1];
        let extent_lba = u32::from_le_bytes([rec[2], rec[3], rec[4], rec[5]]);
        let data_len = u32::from_le_bytes([rec[10], rec[11], rec[12], rec[13]]);
        let file_flags = rec[25];
        let file_unit_size = rec[26];
        let interleave_gap = rec[27];
        let fi_len = usize::from(rec[32]);

        if 33 + fi_len > rec_len {
            return Err(DomainError::InvalidAppImage {
                path: display_path.to_path_buf(),
                reason: "ISO9660 file identifier exceeds directory record length".to_string(),
            });
        }
        if file_unit_size != 0 || interleave_gap != 0 {
            return Err(DomainError::UnsupportedAppImageFormat {
                path: display_path.to_path_buf(),
                reason: "interleaved ISO9660 records are not supported".to_string(),
            });
        }

        let fi_bytes = &rec[33..33 + fi_len];
        let su_start = 33 + fi_len + usize::from(fi_len.is_multiple_of(2));
        let su_slice = rec.get(su_start..).unwrap_or(&[]);

        if fi_len == 1 && fi_bytes[0] == 0x00 {
            if !is_joliet && dir.depth == 0 {
                let rr = parse_rock_ridge_area(
                    reader,
                    file_len,
                    block_size,
                    su_slice,
                    0,
                    budget,
                    display_path,
                )?;
                if rr.saw_rock_ridge {
                    *saw_rock_ridge = true;
                }
                if let Some(skip) = rr.sp_skip {
                    *susp_skip = Some(skip);
                }
            }
            continue;
        }
        if fi_len == 1 && fi_bytes[0] == 0x01 {
            continue;
        }

        let rr = if !is_joliet {
            let skip = susp_skip.unwrap_or(0);
            let parsed = parse_rock_ridge_area(
                reader,
                file_len,
                block_size,
                su_slice,
                skip,
                budget,
                display_path,
            )?;
            if parsed.saw_rock_ridge {
                *saw_rock_ridge = true;
            }
            parsed
        } else {
            RockRidgeMetadata::default()
        };

        if rr.relocated_entry || rr.is_current_or_parent {
            continue;
        }

        let entry_name = if rr.has_name {
            let name_str = std::str::from_utf8(&rr.name_bytes).map_err(|_| {
                DomainError::UnsafePathTraversal("<non-utf8 rock ridge name>".to_string())
            })?;
            validate_single_entry_name(name_str)?
        } else if is_joliet {
            let decoded = decode_joliet_filename(fi_bytes, display_path)?;
            validate_single_entry_name(&decoded)?
        } else {
            let decoded = decode_plain_iso_filename(fi_bytes, display_path)?;
            validate_single_entry_name(&decoded)?
        };

        let rel_path = if dir.path.as_os_str().is_empty() {
            PathBuf::from(&entry_name)
        } else {
            dir.path.join(&entry_name)
        };
        let rel_str = rel_path
            .to_str()
            .ok_or_else(|| DomainError::UnsafePathTraversal(rel_path.display().to_string()))?;
        let normalized_path = normalize_archive_entry_path(rel_str)?;

        if let Some(child_lba) = rr.relocated_child_lba {
            flush_pending_multi(pending_multi.take(), display_path)?;
            let (child_size, child_xattr) = read_relocated_dir_dot(
                reader,
                file_len,
                block_size,
                child_lba,
                budget,
                display_path,
            )?;
            push_checked_entry(
                entries,
                IsoEntry {
                    path: normalized_path.clone(),
                    kind: IsoEntryKind::Dir,
                },
                display_path,
            )?;
            queue.push_back(PendingDir {
                path: normalized_path,
                lba: child_lba,
                size: child_size,
                xattr_len: child_xattr,
                depth: dir.depth + 1,
            });
            continue;
        }

        let posix_type = rr.posix_mode.map(|m| m & 0o170000);
        if posix_type == Some(0o120000) {
            flush_pending_multi(pending_multi.take(), display_path)?;
            let Some(target) = rr.symlink_target else {
                return Err(DomainError::InvalidAppImage {
                    path: display_path.to_path_buf(),
                    reason: format!(
                        "Rock Ridge symlink '{}' is missing SL target",
                        normalized_path.display()
                    ),
                });
            };
            push_checked_entry(
                entries,
                IsoEntry {
                    path: normalized_path,
                    kind: IsoEntryKind::Symlink(target),
                },
                display_path,
            )?;
            continue;
        }

        let is_dir =
            posix_type == Some(0o040000) || (posix_type.is_none() && (file_flags & 0x02) != 0);
        if is_dir {
            flush_pending_multi(pending_multi.take(), display_path)?;
            push_checked_entry(
                entries,
                IsoEntry {
                    path: normalized_path.clone(),
                    kind: IsoEntryKind::Dir,
                },
                display_path,
            )?;
            queue.push_back(PendingDir {
                path: normalized_path,
                lba: extent_lba,
                size: u64::from(data_len),
                xattr_len,
                depth: dir.depth + 1,
            });
            continue;
        }

        let is_regular = posix_type.is_none() || posix_type == Some(0o100000);
        if !is_regular {
            flush_pending_multi(pending_multi.take(), display_path)?;
            continue;
        }

        let ext_len = u64::from(data_len);
        let ext_offset = compute_extent_offset(
            extent_lba,
            xattr_len,
            block_size,
            ext_len,
            file_len,
            display_path,
        )?;
        let extent = IsoExtent {
            offset: ext_offset,
            length: ext_len,
        };
        let has_more_extents = (file_flags & 0x80) != 0;

        match pending_multi.take() {
            Some(mut multi) => {
                if multi.path != normalized_path {
                    return Err(DomainError::InvalidAppImage {
                        path: display_path.to_path_buf(),
                        reason: "unterminated multi-extent ISO9660 file record".to_string(),
                    });
                }
                if multi.extents.len() >= MAX_FILE_EXTENTS {
                    return Err(DomainError::ResourceLimitExceeded {
                        resource: "ISO9660 file extents".to_string(),
                        limit: MAX_FILE_EXTENTS as u64,
                        context: normalized_path.display().to_string(),
                    });
                }
                multi.size = multi.size.checked_add(ext_len).ok_or_else(|| {
                    DomainError::InvalidAppImage {
                        path: display_path.to_path_buf(),
                        reason: "ISO9660 multi-extent file size overflow".to_string(),
                    }
                })?;
                multi.extents.push(extent);
                if has_more_extents {
                    pending_multi = Some(multi);
                } else {
                    push_checked_entry(
                        entries,
                        IsoEntry {
                            path: multi.path,
                            kind: IsoEntryKind::File {
                                size: multi.size,
                                extents: multi.extents,
                            },
                        },
                        display_path,
                    )?;
                }
            }
            None => {
                if has_more_extents {
                    pending_multi = Some(PendingMultiExtent {
                        path: normalized_path,
                        size: ext_len,
                        extents: vec![extent],
                    });
                } else {
                    push_checked_entry(
                        entries,
                        IsoEntry {
                            path: normalized_path,
                            kind: IsoEntryKind::File {
                                size: ext_len,
                                extents: vec![extent],
                            },
                        },
                        display_path,
                    )?;
                }
            }
        }
    }

    flush_pending_multi(pending_multi, display_path)?;
    Ok(())
}

fn flush_pending_multi(
    pending: Option<PendingMultiExtent>,
    display_path: &Path,
) -> Result<(), DomainError> {
    if pending.is_some() {
        return Err(DomainError::InvalidAppImage {
            path: display_path.to_path_buf(),
            reason: "unterminated multi-extent ISO9660 file at end of directory".to_string(),
        });
    }
    Ok(())
}

fn push_checked_entry(
    entries: &mut Vec<IsoEntry>,
    entry: IsoEntry,
    display_path: &Path,
) -> Result<(), DomainError> {
    if entries.len() >= MAX_ISO_ENTRIES {
        return Err(DomainError::ResourceLimitExceeded {
            resource: "ISO9660 archive entries".to_string(),
            limit: MAX_ISO_ENTRIES as u64,
            context: display_path.display().to_string(),
        });
    }
    entries.push(entry);
    Ok(())
}

fn read_relocated_dir_dot<R: Read + Seek>(
    reader: &mut R,
    file_len: u64,
    block_size: u16,
    lba: u32,
    budget: &mut MetadataBudget,
    display_path: &Path,
) -> Result<(u64, u8), DomainError> {
    let bs = u64::from(block_size);
    let offset = compute_extent_offset(lba, 0, block_size, bs, file_len, display_path)?;
    budget.consume(bs, display_path, "relocated directory header")?;
    let mut buf = vec![0u8; usize::from(block_size)];
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|err| DomainError::Io {
            context: format!("seeking relocated ISO9660 dir '{}'", display_path.display()),
            reason: err.to_string(),
        })?;
    reader
        .read_exact(&mut buf)
        .map_err(|err| DomainError::InvalidAppImage {
            path: display_path.to_path_buf(),
            reason: format!("truncated relocated ISO9660 directory: {err}"),
        })?;
    let rec_len = usize::from(buf[0]);
    if rec_len < 34 || rec_len > buf.len() || buf[32] != 1 || buf[33] != 0x00 {
        return Err(DomainError::InvalidAppImage {
            path: display_path.to_path_buf(),
            reason: "invalid relocated ISO9660 directory '.' entry".to_string(),
        });
    }
    let xattr_len = buf[1];
    let size = u64::from(u32::from_le_bytes([buf[10], buf[11], buf[12], buf[13]]));
    Ok((size, xattr_len))
}

fn parse_rock_ridge_area<R: Read + Seek>(
    reader: &mut R,
    file_len: u64,
    block_size: u16,
    initial_su: &[u8],
    susp_skip: usize,
    budget: &mut MetadataBudget,
    display_path: &Path,
) -> Result<RockRidgeMetadata, DomainError> {
    let mut meta = RockRidgeMetadata::default();
    if susp_skip >= initial_su.len() {
        return Ok(meta);
    }

    let mut current_buf = initial_su[susp_skip..].to_vec();
    let mut visited_ce: HashSet<(u32, u32, u32)> = HashSet::new();

    for hop in 0..=MAX_CE_HOPS {
        let mut next_ce: Option<(u32, u32, u32)> = None;
        let mut idx = 0usize;

        while idx + 4 <= current_buf.len() {
            let sig = [current_buf[idx], current_buf[idx + 1]];
            let len = usize::from(current_buf[idx + 2]);
            if len < 4 || idx + len > current_buf.len() {
                break;
            }
            let entry = &current_buf[idx..idx + len];
            idx += len;

            match &sig {
                b"SP" if len == 7 && entry[4] == 0xBE && entry[5] == 0xEF => {
                    meta.saw_rock_ridge = true;
                    meta.sp_skip = Some(usize::from(entry[6]));
                }
                b"ST" => {
                    meta.saw_rock_ridge = true;
                    break;
                }
                b"CE" if len == 28 => {
                    meta.saw_rock_ridge = true;
                    let ce_lba = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                    let ce_off = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]);
                    let ce_len = u32::from_le_bytes([entry[20], entry[21], entry[22], entry[23]]);
                    next_ce = Some((ce_lba, ce_off, ce_len));
                }
                b"PX" if len >= 36 => {
                    meta.saw_rock_ridge = true;
                    meta.posix_mode =
                        Some(u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]));
                }
                b"NM" if len >= 5 => {
                    meta.saw_rock_ridge = true;
                    let flags = entry[4];
                    if (flags & 0x06) != 0 {
                        meta.is_current_or_parent = true;
                    } else if (flags & 0x28) == 0 {
                        let name_chunk = &entry[5..];
                        if meta.name_bytes.len() + name_chunk.len() > MAX_FILENAME_BYTES {
                            return Err(DomainError::ResourceLimitExceeded {
                                resource: "ISO9660 Rock Ridge filename".to_string(),
                                limit: MAX_FILENAME_BYTES as u64,
                                context: display_path.display().to_string(),
                            });
                        }
                        meta.name_bytes.extend_from_slice(name_chunk);
                        meta.has_name = true;
                    }
                }
                b"SL" if len >= 5 => {
                    meta.saw_rock_ridge = true;
                    parse_sl_entry(entry, &mut meta, display_path)?;
                }
                b"CL" if len == 12 => {
                    meta.saw_rock_ridge = true;
                    meta.relocated_child_lba =
                        Some(u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]));
                }
                b"RE" => {
                    meta.saw_rock_ridge = true;
                    meta.relocated_entry = true;
                }
                b"TF" | b"PN" | b"PL" | b"ER" | b"RR" => {
                    meta.saw_rock_ridge = true;
                }
                _ => {}
            }
        }

        let Some((ce_lba, ce_off, ce_len)) = next_ce else {
            break;
        };
        if hop >= MAX_CE_HOPS {
            return Err(DomainError::ResourceLimitExceeded {
                resource: "ISO9660 SUSP CE continuation hops".to_string(),
                limit: MAX_CE_HOPS as u64,
                context: display_path.display().to_string(),
            });
        }
        if !visited_ce.insert((ce_lba, ce_off, ce_len)) {
            return Err(DomainError::InvalidAppImage {
                path: display_path.to_path_buf(),
                reason: "cyclic ISO9660 SUSP CE continuation detected".to_string(),
            });
        }
        if u64::from(ce_len) > u64::from(block_size) || u64::from(ce_off) > u64::from(block_size) {
            return Err(DomainError::InvalidAppImage {
                path: display_path.to_path_buf(),
                reason: "ISO9660 SUSP CE continuation exceeds block size".to_string(),
            });
        }

        let block_base = u64::from(ce_lba)
            .checked_mul(u64::from(block_size))
            .ok_or_else(|| DomainError::InvalidAppImage {
                path: display_path.to_path_buf(),
                reason: "ISO9660 CE offset overflow".to_string(),
            })?;
        let ce_start = block_base.checked_add(u64::from(ce_off)).ok_or_else(|| {
            DomainError::InvalidAppImage {
                path: display_path.to_path_buf(),
                reason: "ISO9660 CE offset overflow".to_string(),
            }
        })?;
        let ce_end = ce_start.checked_add(u64::from(ce_len)).ok_or_else(|| {
            DomainError::InvalidAppImage {
                path: display_path.to_path_buf(),
                reason: "ISO9660 CE end offset overflow".to_string(),
            }
        })?;
        if ce_end > file_len {
            return Err(DomainError::InvalidAppImage {
                path: display_path.to_path_buf(),
                reason: "ISO9660 SUSP CE continuation exceeds file length".to_string(),
            });
        }

        budget.consume(u64::from(ce_len), display_path, "SUSP CE metadata")?;
        current_buf.resize(ce_len as usize, 0);
        reader
            .seek(SeekFrom::Start(ce_start))
            .map_err(|err| DomainError::Io {
                context: format!("seeking ISO9660 CE area '{}'", display_path.display()),
                reason: err.to_string(),
            })?;
        reader
            .read_exact(&mut current_buf)
            .map_err(|err| DomainError::InvalidAppImage {
                path: display_path.to_path_buf(),
                reason: format!("truncated ISO9660 CE continuation: {err}"),
            })?;
    }

    Ok(meta)
}

fn parse_sl_entry(
    entry: &[u8],
    meta: &mut RockRidgeMetadata,
    display_path: &Path,
) -> Result<(), DomainError> {
    let target = meta.symlink_target.get_or_insert_with(String::new);
    let mut cursor = 5usize;
    while cursor + 2 <= entry.len() {
        let comp_flags = entry[cursor];
        let comp_len = usize::from(entry[cursor + 1]);
        cursor += 2;
        if cursor + comp_len > entry.len() {
            return Err(DomainError::InvalidAppImage {
                path: display_path.to_path_buf(),
                reason: "truncated Rock Ridge SL component".to_string(),
            });
        }
        let comp_bytes = &entry[cursor..cursor + comp_len];
        cursor += comp_len;

        if (comp_flags & 0x08) != 0 {
            if target.is_empty() {
                target.push('/');
            }
            meta.symlink_need_slash = false;
            continue;
        }

        if meta.symlink_need_slash {
            if target.len() + 1 > MAX_SYMLINK_BYTES {
                return Err(DomainError::ResourceLimitExceeded {
                    resource: "ISO9660 Rock Ridge symlink".to_string(),
                    limit: MAX_SYMLINK_BYTES as u64,
                    context: display_path.display().to_string(),
                });
            }
            target.push('/');
        }

        if (comp_flags & 0x02) != 0 {
            if target.len() + 1 > MAX_SYMLINK_BYTES {
                return Err(DomainError::ResourceLimitExceeded {
                    resource: "ISO9660 Rock Ridge symlink".to_string(),
                    limit: MAX_SYMLINK_BYTES as u64,
                    context: display_path.display().to_string(),
                });
            }
            target.push('.');
        } else if (comp_flags & 0x04) != 0 {
            if target.len() + 2 > MAX_SYMLINK_BYTES {
                return Err(DomainError::ResourceLimitExceeded {
                    resource: "ISO9660 Rock Ridge symlink".to_string(),
                    limit: MAX_SYMLINK_BYTES as u64,
                    context: display_path.display().to_string(),
                });
            }
            target.push_str("..");
        } else {
            let chunk =
                std::str::from_utf8(comp_bytes).map_err(|_| DomainError::InvalidAppImage {
                    path: display_path.to_path_buf(),
                    reason: "non-UTF-8 Rock Ridge symlink component".to_string(),
                })?;
            if target.len() + chunk.len() > MAX_SYMLINK_BYTES {
                return Err(DomainError::ResourceLimitExceeded {
                    resource: "ISO9660 Rock Ridge symlink".to_string(),
                    limit: MAX_SYMLINK_BYTES as u64,
                    context: display_path.display().to_string(),
                });
            }
            target.push_str(chunk);
        }

        meta.symlink_need_slash = (comp_flags & 0x01) == 0;
    }
    Ok(())
}

fn decode_joliet_filename(fi_bytes: &[u8], display_path: &Path) -> Result<String, DomainError> {
    let (pairs, remainder) = fi_bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(DomainError::InvalidAppImage {
            path: display_path.to_path_buf(),
            reason: "odd byte length in Joliet UCS-2 filename".to_string(),
        });
    }
    let mut code_units = Vec::with_capacity(pairs.len());
    for pair in pairs {
        code_units.push(u16::from_be_bytes(*pair));
    }
    let raw = String::from_utf16(&code_units).map_err(|_| DomainError::InvalidAppImage {
        path: display_path.to_path_buf(),
        reason: "invalid UTF-16BE sequence in Joliet filename".to_string(),
    })?;
    Ok(strip_iso_version_suffix(&raw).to_string())
}

fn decode_plain_iso_filename(fi_bytes: &[u8], display_path: &Path) -> Result<String, DomainError> {
    let raw = std::str::from_utf8(fi_bytes).map_err(|_| DomainError::InvalidAppImage {
        path: display_path.to_path_buf(),
        reason: "non-UTF-8 ISO9660 filename".to_string(),
    })?;
    let without_ver = strip_iso_version_suffix(raw);
    let without_trailing_dot = without_ver.strip_suffix('.').unwrap_or(without_ver);
    let has_ascii_alpha = without_trailing_dot
        .bytes()
        .any(|b| b.is_ascii_alphabetic());
    let has_ascii_lower = without_trailing_dot.bytes().any(|b| b.is_ascii_lowercase());
    if has_ascii_alpha && !has_ascii_lower {
        Ok(without_trailing_dot.to_ascii_lowercase())
    } else {
        Ok(without_trailing_dot.to_string())
    }
}

fn strip_iso_version_suffix(raw: &str) -> &str {
    if let Some((base, ver)) = raw.rsplit_once(';')
        && !ver.is_empty()
        && ver.bytes().all(|b| b.is_ascii_digit())
    {
        base
    } else {
        raw
    }
}

fn validate_single_entry_name(name: &str) -> Result<String, DomainError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name
            .chars()
            .any(|ch| ch.is_control() || is_bidi_or_invisible_format(ch))
    {
        return Err(DomainError::UnsafePathTraversal(name.to_string()));
    }
    Ok(name.to_string())
}

fn compute_extent_offset(
    lba: u32,
    xattr_len: u8,
    block_size: u16,
    data_len: u64,
    file_len: u64,
    display_path: &Path,
) -> Result<u64, DomainError> {
    let start_block = u64::from(lba)
        .checked_add(u64::from(xattr_len))
        .ok_or_else(|| DomainError::InvalidAppImage {
            path: display_path.to_path_buf(),
            reason: "ISO9660 extent block overflow".to_string(),
        })?;
    let offset = start_block
        .checked_mul(u64::from(block_size))
        .ok_or_else(|| DomainError::InvalidAppImage {
            path: display_path.to_path_buf(),
            reason: "ISO9660 extent byte offset overflow".to_string(),
        })?;
    let end = offset
        .checked_add(data_len)
        .ok_or_else(|| DomainError::InvalidAppImage {
            path: display_path.to_path_buf(),
            reason: "ISO9660 extent end offset overflow".to_string(),
        })?;
    if end > file_len {
        return Err(DomainError::InvalidAppImage {
            path: display_path.to_path_buf(),
            reason: "ISO9660 extent exceeds AppImage file length".to_string(),
        });
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::Path;

    use crate::domain::error::DomainError;

    use super::{Iso9660Archive, IsoEntryKind};

    fn write_both_endian_u16(buf: &mut [u8], val: u16) {
        buf[0..2].copy_from_slice(&val.to_le_bytes());
        buf[2..4].copy_from_slice(&val.to_be_bytes());
    }

    fn write_both_endian_u32(buf: &mut [u8], val: u32) {
        buf[0..4].copy_from_slice(&val.to_le_bytes());
        buf[4..8].copy_from_slice(&val.to_be_bytes());
    }

    fn push_dir_record(
        out: &mut Vec<u8>,
        lba: u32,
        len: u32,
        flags: u8,
        file_id: &[u8],
        su: &[u8],
    ) {
        let pad = usize::from(file_id.len().is_multiple_of(2));
        let rec_len = 33 + file_id.len() + pad + su.len();
        let mut rec = vec![0u8; rec_len];
        rec[0] = rec_len as u8;
        write_both_endian_u32(&mut rec[2..10], lba);
        write_both_endian_u32(&mut rec[10..18], len);
        rec[25] = flags;
        rec[32] = file_id.len() as u8;
        rec[33..33 + file_id.len()].copy_from_slice(file_id);
        rec[33 + file_id.len() + pad..].copy_from_slice(su);
        out.extend_from_slice(&rec);
    }

    fn rr_nm(name: &[u8]) -> Vec<u8> {
        let mut out = vec![b'N', b'M', (5 + name.len()) as u8, 1, 0];
        out.extend_from_slice(name);
        out
    }

    fn rr_px(mode: u32) -> Vec<u8> {
        let mut out = vec![0u8; 36];
        out[0] = b'P';
        out[1] = b'X';
        out[2] = 36;
        out[3] = 1;
        write_both_endian_u32(&mut out[4..12], mode);
        out
    }

    fn rr_sl_single(comp: &[u8]) -> Vec<u8> {
        let mut out = vec![
            b'S',
            b'L',
            (7 + comp.len()) as u8,
            1,
            0,
            0,
            comp.len() as u8,
        ];
        out.extend_from_slice(comp);
        out
    }

    fn encode_utf16be(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() * 2);
        for cu in s.encode_utf16() {
            out.extend_from_slice(&cu.to_be_bytes());
        }
        out
    }

    fn init_iso_pvd(
        img: &mut [u8],
        vd_sector: usize,
        vd_type: u8,
        escape: Option<&[u8]>,
        root_lba: u32,
        root_size: u32,
    ) {
        let off = vd_sector * 2048;
        img[off] = vd_type;
        img[off + 1..off + 6].copy_from_slice(b"CD001");
        img[off + 6] = 1;
        if let Some(esc) = escape {
            img[off + 88..off + 88 + esc.len()].copy_from_slice(esc);
        }
        write_both_endian_u16(&mut img[off + 128..off + 132], 2048);
        let root = &mut img[off + 156..off + 190];
        root[0] = 34;
        write_both_endian_u32(&mut root[2..10], root_lba);
        write_both_endian_u32(&mut root[10..18], root_size);
        root[25] = 0x02;
        root[32] = 1;
    }

    fn terminate_vd(img: &mut [u8], vd_sector: usize) {
        let off = vd_sector * 2048;
        img[off] = 255;
        img[off + 1..off + 6].copy_from_slice(b"CD001");
        img[off + 6] = 1;
    }

    #[test]
    fn parses_rock_ridge_files_dirs_and_symlinks_and_reads_file_bytes() {
        let mut img = vec![0u8; 32 * 2048];
        let desktop_bytes = b"[Desktop Entry]\nType=Application\nName=IsoApp\nExec=AppRun\n";
        let icon_bytes = b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>";

        let desktop_lba = 22u32;
        let icon_lba = 23u32;
        let usr_dir_lba = 20u32;
        let root_dir_lba = 19u32;

        let mut root_dir = Vec::new();
        push_dir_record(
            &mut root_dir,
            root_dir_lba,
            2048,
            0x02,
            &[0x00],
            &[b'S', b'P', 7, 1, 0xBE, 0xEF, 0],
        );
        push_dir_record(&mut root_dir, root_dir_lba, 2048, 0x02, &[0x01], &[]);

        let mut desktop_su = rr_px(0o100644);
        desktop_su.extend_from_slice(&rr_nm(b"IsoApp.desktop"));
        push_dir_record(
            &mut root_dir,
            desktop_lba,
            desktop_bytes.len() as u32,
            0x00,
            b"ISOAPP.DES;1",
            &desktop_su,
        );

        let mut usr_su = rr_px(0o040755);
        usr_su.extend_from_slice(&rr_nm(b"usr"));
        push_dir_record(&mut root_dir, usr_dir_lba, 2048, 0x02, b"USR", &usr_su);

        let mut sym_su = rr_px(0o120777);
        sym_su.extend_from_slice(&rr_nm(b".DirIcon"));
        sym_su.extend_from_slice(&[
            b'S', b'L', 20, 1, 0, 0, 3, b'u', b's', b'r', 0, 8, b'i', b'c', b'o', b'n', b'.', b's',
            b'v', b'g',
        ]);
        push_dir_record(&mut root_dir, 0, 0, 0x00, b"DIRICON", &sym_su);

        let mut usr_dir = Vec::new();
        push_dir_record(&mut usr_dir, usr_dir_lba, 2048, 0x02, &[0x00], &[]);
        push_dir_record(&mut usr_dir, root_dir_lba, 2048, 0x02, &[0x01], &[]);
        let mut icon_su = rr_px(0o100644);
        icon_su.extend_from_slice(&rr_nm(b"icon.svg"));
        push_dir_record(
            &mut usr_dir,
            icon_lba,
            icon_bytes.len() as u32,
            0x00,
            b"ICON.SVG;1",
            &icon_su,
        );

        init_iso_pvd(&mut img, 16, 1, None, root_dir_lba, 2048);
        terminate_vd(&mut img, 17);
        img[root_dir_lba as usize * 2048..root_dir_lba as usize * 2048 + root_dir.len()]
            .copy_from_slice(&root_dir);
        img[usr_dir_lba as usize * 2048..usr_dir_lba as usize * 2048 + usr_dir.len()]
            .copy_from_slice(&usr_dir);
        img[desktop_lba as usize * 2048..desktop_lba as usize * 2048 + desktop_bytes.len()]
            .copy_from_slice(desktop_bytes);
        img[icon_lba as usize * 2048..icon_lba as usize * 2048 + icon_bytes.len()]
            .copy_from_slice(icon_bytes);

        let len = img.len() as u64;
        let mut cursor = Cursor::new(img);
        let archive = Iso9660Archive::open(&mut cursor, len, Path::new("test.AppImage")).unwrap();

        let desktop_entry = archive
            .entries()
            .iter()
            .find(|e| e.path == Path::new("IsoApp.desktop"))
            .unwrap();
        match &desktop_entry.kind {
            IsoEntryKind::File { size, extents } => {
                let read = archive
                    .read_file(
                        &mut cursor,
                        *size,
                        extents,
                        4096,
                        Path::new("test.AppImage"),
                    )
                    .unwrap();
                assert_eq!(read, desktop_bytes);
            }
            other => panic!("unexpected entry kind: {other:?}"),
        }

        let diricon_entry = archive
            .entries()
            .iter()
            .find(|e| e.path == Path::new(".DirIcon"))
            .unwrap();
        assert_eq!(
            diricon_entry.kind,
            IsoEntryKind::Symlink("usr/icon.svg".to_string())
        );

        let icon_entry = archive
            .entries()
            .iter()
            .find(|e| e.path == Path::new("usr/icon.svg"))
            .unwrap();
        assert!(matches!(icon_entry.kind, IsoEntryKind::File { .. }));
    }

    #[test]
    fn falls_back_to_joliet_svd_when_rock_ridge_absent() {
        let mut img = vec![0u8; 28 * 2048];
        let payload = b"joliet-desktop";

        init_iso_pvd(&mut img, 16, 1, None, 19, 2048);
        init_iso_pvd(&mut img, 17, 2, Some(b"%/E"), 20, 2048);
        terminate_vd(&mut img, 18);

        let mut pvd_root = Vec::new();
        push_dir_record(&mut pvd_root, 19, 2048, 0x02, &[0x00], &[]);
        push_dir_record(&mut pvd_root, 19, 2048, 0x02, &[0x01], &[]);
        push_dir_record(
            &mut pvd_root,
            21,
            payload.len() as u32,
            0x00,
            b"MYAPP.DES;1",
            &[],
        );
        img[19 * 2048..19 * 2048 + pvd_root.len()].copy_from_slice(&pvd_root);

        let mut svd_root = Vec::new();
        push_dir_record(&mut svd_root, 20, 2048, 0x02, &[0x00], &[]);
        push_dir_record(&mut svd_root, 20, 2048, 0x02, &[0x01], &[]);
        push_dir_record(
            &mut svd_root,
            21,
            payload.len() as u32,
            0x00,
            &encode_utf16be("MyApp.desktop;1"),
            &[],
        );
        img[20 * 2048..20 * 2048 + svd_root.len()].copy_from_slice(&svd_root);
        img[21 * 2048..21 * 2048 + payload.len()].copy_from_slice(payload);

        let len = img.len() as u64;
        let mut cursor = Cursor::new(img);
        let archive = Iso9660Archive::open(&mut cursor, len, Path::new("joliet.AppImage")).unwrap();
        let entry = archive
            .entries()
            .iter()
            .find(|e| e.path == Path::new("MyApp.desktop"))
            .unwrap();
        assert!(matches!(entry.kind, IsoEntryKind::File { .. }));
    }

    #[test]
    fn blocks_directory_loops_oob_extents_and_traversal_filenames() {
        let mut loop_img = vec![0u8; 24 * 2048];
        init_iso_pvd(&mut loop_img, 16, 1, None, 19, 2048);
        terminate_vd(&mut loop_img, 17);
        let mut root_dir = Vec::new();
        push_dir_record(&mut root_dir, 19, 2048, 0x02, &[0x00], &[]);
        let mut sub_su = rr_px(0o040755);
        sub_su.extend_from_slice(&rr_nm(b"sub"));
        push_dir_record(&mut root_dir, 19, 2048, 0x02, b"SUB", &sub_su);
        loop_img[19 * 2048..19 * 2048 + root_dir.len()].copy_from_slice(&root_dir);
        let loop_len = loop_img.len() as u64;
        assert!(matches!(
            Iso9660Archive::open(&mut Cursor::new(loop_img), loop_len, Path::new("loop.iso")),
            Err(DomainError::InvalidAppImage { .. })
        ));

        let mut trav_img = vec![0u8; 24 * 2048];
        init_iso_pvd(&mut trav_img, 16, 1, None, 19, 2048);
        terminate_vd(&mut trav_img, 17);
        let mut trav_dir = Vec::new();
        push_dir_record(&mut trav_dir, 19, 2048, 0x02, &[0x00], &[]);
        let mut bad_su = rr_px(0o100644);
        bad_su.extend_from_slice(&rr_nm(b"../evil.desktop"));
        push_dir_record(&mut trav_dir, 20, 10, 0x00, b"BAD;1", &bad_su);
        trav_img[19 * 2048..19 * 2048 + trav_dir.len()].copy_from_slice(&trav_dir);
        let trav_len = trav_img.len() as u64;
        assert!(matches!(
            Iso9660Archive::open(&mut Cursor::new(trav_img), trav_len, Path::new("trav.iso")),
            Err(DomainError::UnsafePathTraversal(_))
        ));

        let mut oob_img = vec![0u8; 21 * 2048];
        init_iso_pvd(&mut oob_img, 16, 1, None, 19, 2048);
        terminate_vd(&mut oob_img, 17);
        let mut oob_dir = Vec::new();
        push_dir_record(&mut oob_dir, 19, 2048, 0x02, &[0x00], &[]);
        let mut oob_su = rr_px(0o100644);
        oob_su.extend_from_slice(&rr_nm(b"oob.desktop"));
        push_dir_record(&mut oob_dir, 9999, 512, 0x00, b"OOB;1", &oob_su);
        oob_img[19 * 2048..19 * 2048 + oob_dir.len()].copy_from_slice(&oob_dir);
        let oob_len = oob_img.len() as u64;
        assert!(matches!(
            Iso9660Archive::open(&mut Cursor::new(oob_img), oob_len, Path::new("oob.iso")),
            Err(DomainError::InvalidAppImage { .. })
        ));
    }

    #[test]
    fn supports_ce_continuations_cl_relocated_dirs_multi_extent_and_blocks_ce_cycles_and_size_overflow()
     {
        let mut img = vec![0u8; 34 * 2048];
        let part1 = b"hello-";
        let part2 = b"world";
        let ce_sector = 24usize;
        let relocated_dir_lba = 25u32;
        let multi_lba1 = 26u32;
        let multi_lba2 = 27u32;

        let ce_nm = rr_nm(b"LongRockRidgeApp.desktop");
        let ce_off = ce_sector * 2048;
        img[ce_off..ce_off + ce_nm.len()].copy_from_slice(&ce_nm);

        let mut ce_entry = vec![0u8; 28];
        ce_entry[0] = b'C';
        ce_entry[1] = b'E';
        ce_entry[2] = 28;
        ce_entry[3] = 1;
        write_both_endian_u32(&mut ce_entry[4..12], ce_sector as u32);
        write_both_endian_u32(&mut ce_entry[12..20], 0);
        write_both_endian_u32(&mut ce_entry[20..28], ce_nm.len() as u32);

        let mut root_dir = Vec::new();
        push_dir_record(&mut root_dir, 19, 2048, 0x02, &[0x00], &[]);
        push_dir_record(&mut root_dir, 19, 2048, 0x02, &[0x01], &[]);

        let mut ext1_su = rr_px(0o100644);
        ext1_su.extend_from_slice(&ce_entry);
        push_dir_record(
            &mut root_dir,
            multi_lba1,
            part1.len() as u32,
            0x80,
            b"LONG.DES;1",
            &ext1_su,
        );
        push_dir_record(
            &mut root_dir,
            multi_lba2,
            part2.len() as u32,
            0x00,
            b"LONG.DES;1",
            &ext1_su,
        );

        let mut cl_su = vec![b'C', b'L', 12, 1];
        cl_su.extend_from_slice(&relocated_dir_lba.to_le_bytes());
        cl_su.extend_from_slice(&relocated_dir_lba.to_be_bytes());
        cl_su.extend_from_slice(&rr_nm(b"deep"));
        push_dir_record(&mut root_dir, 0, 0, 0x00, b"DEEP", &cl_su);

        let mut rr_moved = Vec::new();
        push_dir_record(&mut rr_moved, 21, 2048, 0x02, &[0x00], &[]);
        let mut re_su = vec![b'R', b'E', 4, 1];
        re_su.extend_from_slice(&rr_nm(b"ignored"));
        push_dir_record(
            &mut rr_moved,
            relocated_dir_lba,
            2048,
            0x02,
            b"IGNORED",
            &re_su,
        );

        let mut moved_su = rr_px(0o040755);
        moved_su.extend_from_slice(&rr_nm(b"rr_moved"));
        push_dir_record(&mut root_dir, 21, 2048, 0x02, b"RR_MOVED", &moved_su);

        let mut rel_dir = Vec::new();
        push_dir_record(&mut rel_dir, relocated_dir_lba, 2048, 0x02, &[0x00], &[]);
        let mut nested_sym_su = rr_px(0o120777);
        nested_sym_su.extend_from_slice(&rr_nm(b"link"));
        nested_sym_su.extend_from_slice(&rr_sl_single(b"target"));
        push_dir_record(&mut rel_dir, 0, 0, 0x00, b"LINK", &nested_sym_su);

        init_iso_pvd(&mut img, 16, 1, None, 19, 2048);
        terminate_vd(&mut img, 17);
        img[19 * 2048..19 * 2048 + root_dir.len()].copy_from_slice(&root_dir);
        img[21 * 2048..21 * 2048 + rr_moved.len()].copy_from_slice(&rr_moved);
        img[relocated_dir_lba as usize * 2048..relocated_dir_lba as usize * 2048 + rel_dir.len()]
            .copy_from_slice(&rel_dir);
        img[multi_lba1 as usize * 2048..multi_lba1 as usize * 2048 + part1.len()]
            .copy_from_slice(part1);
        img[multi_lba2 as usize * 2048..multi_lba2 as usize * 2048 + part2.len()]
            .copy_from_slice(part2);

        let len = img.len() as u64;
        let mut cursor = Cursor::new(img);
        let archive = Iso9660Archive::open(&mut cursor, len, Path::new("ce.iso")).unwrap();

        let multi_entry = archive
            .entries()
            .iter()
            .find(|e| e.path == Path::new("LongRockRidgeApp.desktop"))
            .unwrap();
        match &multi_entry.kind {
            IsoEntryKind::File { size, extents } => {
                assert_eq!(*size, 11);
                assert_eq!(extents.len(), 2);
                let data = archive
                    .read_file(&mut cursor, *size, extents, 64, Path::new("ce.iso"))
                    .unwrap();
                assert_eq!(data, b"hello-world");
                assert!(matches!(
                    archive.read_file(&mut cursor, *size, extents, 5, Path::new("ce.iso")),
                    Err(DomainError::ResourceLimitExceeded { .. })
                ));
            }
            other => panic!("unexpected entry kind: {other:?}"),
        }

        assert!(
            archive
                .entries()
                .iter()
                .any(|e| e.path == Path::new("deep/link"))
        );
        assert!(
            !archive
                .entries()
                .iter()
                .any(|e| e.path.starts_with("rr_moved/ignored"))
        );

        let mut ce_cycle_img = vec![0u8; 25 * 2048];
        init_iso_pvd(&mut ce_cycle_img, 16, 1, None, 19, 2048);
        terminate_vd(&mut ce_cycle_img, 17);
        let mut ce_loop = vec![0u8; 28];
        ce_loop[0] = b'C';
        ce_loop[1] = b'E';
        ce_loop[2] = 28;
        ce_loop[3] = 1;
        write_both_endian_u32(&mut ce_loop[4..12], 24);
        write_both_endian_u32(&mut ce_loop[12..20], 0);
        write_both_endian_u32(&mut ce_loop[20..28], 28);
        ce_cycle_img[24 * 2048..24 * 2048 + 28].copy_from_slice(&ce_loop);
        let mut cyc_dir = Vec::new();
        push_dir_record(&mut cyc_dir, 19, 2048, 0x02, &[0x00], &[]);
        push_dir_record(&mut cyc_dir, 20, 10, 0x00, b"A;1", &ce_loop);
        ce_cycle_img[19 * 2048..19 * 2048 + cyc_dir.len()].copy_from_slice(&cyc_dir);
        let cyc_len = ce_cycle_img.len() as u64;
        assert!(matches!(
            Iso9660Archive::open(
                &mut Cursor::new(ce_cycle_img),
                cyc_len,
                Path::new("cycle.iso")
            ),
            Err(DomainError::InvalidAppImage { .. })
        ));
    }
}
