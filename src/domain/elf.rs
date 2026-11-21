use std::path::Path;

use crate::domain::error::DomainError;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELF_CLASS_32: u8 = 1;
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LSB: u8 = 1;
const ELF_DATA_MSB: u8 = 2;
const PT_LOAD: u32 = 1;
const SHT_NOBITS: u32 = 8;
const MAX_PHNUM: u16 = 1024;
const MAX_SHNUM: u16 = 4096;
const SQUASHFS_MAGIC_LE: [u8; 4] = *b"hsqs";
const SQUASHFS_MAGIC_BE: [u8; 4] = *b"sqsh";
const DWARFS_MAGIC: [u8; 6] = *b"DWARFS";
const ISO9660_PVD_OFFSETS: [u64; 3] = [0x8000, 0x8800, 0x9000];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfEndianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppImageSignature {
    Type1,
    Type2,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfHeaderSummary {
    pub class: ElfClass,
    pub endianness: ElfEndianness,
    pub signature: AppImageSignature,
    pub phoff: u64,
    pub phentsize: u16,
    pub phnum: u16,
    pub shoff: u64,
    pub shentsize: u16,
    pub shnum: u16,
    pub header_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SquashFsEndian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppImagePayloadKind {
    Type2SquashFs { offset: u64, endian: SquashFsEndian },
    Type1Iso,
}

impl ElfHeaderSummary {
    pub fn program_table_end(&self) -> Result<u64, DomainError> {
        let len = u64::from(self.phentsize)
            .checked_mul(u64::from(self.phnum))
            .ok_or_else(|| DomainError::InvalidAppImage {
                path: Path::new("<elf>").to_path_buf(),
                reason: "program header table size overflow".to_string(),
            })?;
        self.phoff
            .checked_add(len)
            .ok_or_else(|| DomainError::InvalidAppImage {
                path: Path::new("<elf>").to_path_buf(),
                reason: "program header table offset overflow".to_string(),
            })
    }

    pub fn section_table_end(&self) -> Result<u64, DomainError> {
        let len = u64::from(self.shentsize)
            .checked_mul(u64::from(self.shnum))
            .ok_or_else(|| DomainError::InvalidAppImage {
                path: Path::new("<elf>").to_path_buf(),
                reason: "section header table size overflow".to_string(),
            })?;
        self.shoff
            .checked_add(len)
            .ok_or_else(|| DomainError::InvalidAppImage {
                path: Path::new("<elf>").to_path_buf(),
                reason: "section header table offset overflow".to_string(),
            })
    }
}

pub fn parse_elf_header(bytes: &[u8], path: &Path) -> Result<ElfHeaderSummary, DomainError> {
    if bytes.len() < 52 || bytes.get(0..4) != Some(&ELF_MAGIC) {
        return Err(DomainError::InvalidAppImage {
            path: path.to_path_buf(),
            reason: "missing ELF magic header".to_string(),
        });
    }

    let class = match bytes.get(4).copied() {
        Some(ELF_CLASS_32) => ElfClass::Elf32,
        Some(ELF_CLASS_64) => ElfClass::Elf64,
        other => {
            return Err(DomainError::InvalidAppImage {
                path: path.to_path_buf(),
                reason: format!("unsupported ELF class {other:?}"),
            });
        }
    };

    let endianness = match bytes.get(5).copied() {
        Some(ELF_DATA_LSB) => ElfEndianness::Little,
        Some(ELF_DATA_MSB) => ElfEndianness::Big,
        other => {
            return Err(DomainError::InvalidAppImage {
                path: path.to_path_buf(),
                reason: format!("unsupported ELF endianness {other:?}"),
            });
        }
    };

    let signature = match bytes.get(8..11) {
        Some(b"AI\x01") => AppImageSignature::Type1,
        Some(b"AI\x02") => AppImageSignature::Type2,
        _ => AppImageSignature::None,
    };

    let (phoff, shoff, phentsize, phnum, shentsize, shnum, header_size) = match class {
        ElfClass::Elf32 => (
            u64::from(read_u32(bytes, 28, endianness, path)?),
            u64::from(read_u32(bytes, 32, endianness, path)?),
            read_u16(bytes, 42, endianness, path)?,
            read_u16(bytes, 44, endianness, path)?,
            read_u16(bytes, 46, endianness, path)?,
            read_u16(bytes, 48, endianness, path)?,
            52,
        ),
        ElfClass::Elf64 => {
            if bytes.len() < 64 {
                return Err(DomainError::InvalidAppImage {
                    path: path.to_path_buf(),
                    reason: "truncated ELF64 header".to_string(),
                });
            }
            (
                read_u64(bytes, 32, endianness, path)?,
                read_u64(bytes, 40, endianness, path)?,
                read_u16(bytes, 54, endianness, path)?,
                read_u16(bytes, 56, endianness, path)?,
                read_u16(bytes, 58, endianness, path)?,
                read_u16(bytes, 60, endianness, path)?,
                64,
            )
        }
    };

    if phnum > MAX_PHNUM {
        return Err(DomainError::ResourceLimitExceeded {
            resource: "ELF program headers".to_string(),
            limit: u64::from(MAX_PHNUM),
            context: path.display().to_string(),
        });
    }
    if shnum > MAX_SHNUM {
        return Err(DomainError::ResourceLimitExceeded {
            resource: "ELF section headers".to_string(),
            limit: u64::from(MAX_SHNUM),
            context: path.display().to_string(),
        });
    }

    Ok(ElfHeaderSummary {
        class,
        endianness,
        signature,
        phoff,
        phentsize,
        phnum,
        shoff,
        shentsize,
        shnum,
        header_size,
    })
}

pub fn compute_elf_end_offset(
    summary: &ElfHeaderSummary,
    program_table: &[u8],
    section_table: &[u8],
    file_len: u64,
    path: &Path,
) -> Result<u64, DomainError> {
    let mut end = summary.header_size;

    if summary.phnum > 0 && summary.phoff > 0 {
        let table_end = summary.program_table_end()?;
        if table_end <= file_len {
            end = end.max(table_end);
        }
        let min_entry_size = match summary.class {
            ElfClass::Elf32 => 32usize,
            ElfClass::Elf64 => 56usize,
        };
        let entry_size = usize::from(summary.phentsize);
        if entry_size >= min_entry_size {
            for idx in 0..usize::from(summary.phnum) {
                let start = idx * entry_size;
                let Some(entry) = program_table.get(start..start + entry_size) else {
                    break;
                };
                let p_type = read_u32(entry, 0, summary.endianness, path)?;
                if p_type == PT_LOAD {
                    let (offset, filesz) = match summary.class {
                        ElfClass::Elf32 => (
                            u64::from(read_u32(entry, 4, summary.endianness, path)?),
                            u64::from(read_u32(entry, 16, summary.endianness, path)?),
                        ),
                        ElfClass::Elf64 => (
                            read_u64(entry, 8, summary.endianness, path)?,
                            read_u64(entry, 32, summary.endianness, path)?,
                        ),
                    };
                    if let Some(seg_end) = offset.checked_add(filesz)
                        && seg_end <= file_len
                    {
                        end = end.max(seg_end);
                    }
                }
            }
        }
    }

    if summary.shnum > 0 && summary.shoff > 0 {
        let table_end = summary.section_table_end()?;
        if table_end <= file_len {
            end = end.max(table_end);
        }
        let min_entry_size = match summary.class {
            ElfClass::Elf32 => 40usize,
            ElfClass::Elf64 => 64usize,
        };
        let entry_size = usize::from(summary.shentsize);
        if entry_size >= min_entry_size {
            for idx in 0..usize::from(summary.shnum) {
                let start = idx * entry_size;
                let Some(entry) = section_table.get(start..start + entry_size) else {
                    break;
                };
                let sh_type = read_u32(entry, 4, summary.endianness, path)?;
                if sh_type != SHT_NOBITS {
                    let (offset, size) = match summary.class {
                        ElfClass::Elf32 => (
                            u64::from(read_u32(entry, 16, summary.endianness, path)?),
                            u64::from(read_u32(entry, 20, summary.endianness, path)?),
                        ),
                        ElfClass::Elf64 => (
                            read_u64(entry, 24, summary.endianness, path)?,
                            read_u64(entry, 32, summary.endianness, path)?,
                        ),
                    };
                    if let Some(sec_end) = offset.checked_add(size)
                        && sec_end <= file_len
                    {
                        end = end.max(sec_end);
                    }
                }
            }
        }
    }

    Ok(end)
}

pub fn detect_payload_at_window(
    _summary: &ElfHeaderSummary,
    elf_end: u64,
    window: &[u8],
    iso_probes: &[&[u8]],
    path: &Path,
) -> Result<AppImagePayloadKind, DomainError> {
    if let Some(magic) = window.get(0..4) {
        if magic == SQUASHFS_MAGIC_LE {
            return Ok(AppImagePayloadKind::Type2SquashFs {
                offset: elf_end,
                endian: SquashFsEndian::Little,
            });
        }
        if magic == SQUASHFS_MAGIC_BE {
            return Ok(AppImagePayloadKind::Type2SquashFs {
                offset: elf_end,
                endian: SquashFsEndian::Big,
            });
        }
    }

    if window.get(0..6) == Some(&DWARFS_MAGIC) {
        return Err(DomainError::UnsupportedAppImageFormat {
            path: path.to_path_buf(),
            reason: "DwarFS AppImage payload is not supported under fail-closed static extraction (never executes untrusted ELF)".to_string(),
        });
    }

    let max_scan = window.len().min(4096);
    for rel in 1..max_scan.saturating_sub(3) {
        if let Some(slice) = window.get(rel..rel + 4)
            && (slice == SQUASHFS_MAGIC_LE || slice == SQUASHFS_MAGIC_BE)
        {
            let offset =
                elf_end
                    .checked_add(rel as u64)
                    .ok_or_else(|| DomainError::InvalidAppImage {
                        path: path.to_path_buf(),
                        reason: "SquashFS offset overflow".to_string(),
                    })?;
            let endian = if slice == SQUASHFS_MAGIC_LE {
                SquashFsEndian::Little
            } else {
                SquashFsEndian::Big
            };
            return Ok(AppImagePayloadKind::Type2SquashFs { offset, endian });
        }
        if let Some(slice) = window.get(rel..rel + 6)
            && slice == DWARFS_MAGIC
        {
            return Err(DomainError::UnsupportedAppImageFormat {
                path: path.to_path_buf(),
                reason: "DwarFS AppImage payload is not supported under fail-closed static extraction (never executes untrusted ELF)".to_string(),
            });
        }
    }

    for iso in iso_probes {
        if iso.get(1..6) == Some(b"CD001") {
            return Ok(AppImagePayloadKind::Type1Iso);
        }
    }

    Err(DomainError::UnsupportedAppImageFormat {
        path: path.to_path_buf(),
        reason:
            "no verified SquashFS (Type 2) or ISO9660 CD001 (Type 1) payload found after ELF binary"
                .to_string(),
    })
}

pub const fn iso_pvd_offsets() -> [u64; 3] {
    ISO9660_PVD_OFFSETS
}

fn read_u16(
    buf: &[u8],
    offset: usize,
    endian: ElfEndianness,
    path: &Path,
) -> Result<u16, DomainError> {
    let slice = buf
        .get(offset..offset + 2)
        .ok_or_else(|| DomainError::InvalidAppImage {
            path: path.to_path_buf(),
            reason: "unexpected EOF reading ELF u16 field".to_string(),
        })?;
    let arr: [u8; 2] = [slice[0], slice[1]];
    Ok(match endian {
        ElfEndianness::Little => u16::from_le_bytes(arr),
        ElfEndianness::Big => u16::from_be_bytes(arr),
    })
}

fn read_u32(
    buf: &[u8],
    offset: usize,
    endian: ElfEndianness,
    path: &Path,
) -> Result<u32, DomainError> {
    let slice = buf
        .get(offset..offset + 4)
        .ok_or_else(|| DomainError::InvalidAppImage {
            path: path.to_path_buf(),
            reason: "unexpected EOF reading ELF u32 field".to_string(),
        })?;
    let arr: [u8; 4] = [slice[0], slice[1], slice[2], slice[3]];
    Ok(match endian {
        ElfEndianness::Little => u32::from_le_bytes(arr),
        ElfEndianness::Big => u32::from_be_bytes(arr),
    })
}

fn read_u64(
    buf: &[u8],
    offset: usize,
    endian: ElfEndianness,
    path: &Path,
) -> Result<u64, DomainError> {
    let slice = buf
        .get(offset..offset + 8)
        .ok_or_else(|| DomainError::InvalidAppImage {
            path: path.to_path_buf(),
            reason: "unexpected EOF reading ELF u64 field".to_string(),
        })?;
    let arr: [u8; 8] = [
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ];
    Ok(match endian {
        ElfEndianness::Little => u64::from_le_bytes(arr),
        ElfEndianness::Big => u64::from_be_bytes(arr),
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        AppImagePayloadKind, AppImageSignature, ElfClass, ElfEndianness, SquashFsEndian,
        compute_elf_end_offset, detect_payload_at_window, parse_elf_header,
    };

    fn minimal_elf64_le(signature: [u8; 3], shoff: u64, shentsize: u16, shnum: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 2;
        buf[5] = 1;
        buf[6] = 1;
        buf[8..11].copy_from_slice(&signature);
        buf[40..48].copy_from_slice(&shoff.to_le_bytes());
        buf[58..60].copy_from_slice(&shentsize.to_le_bytes());
        buf[60..62].copy_from_slice(&shnum.to_le_bytes());
        buf
    }

    #[test]
    fn rejects_non_elf_or_truncated_headers() {
        assert!(parse_elf_header(b"not an elf", Path::new("bad.AppImage")).is_err());
        assert!(parse_elf_header(&[0x7f, b'E', b'L', b'F', 2, 1], Path::new("short")).is_err());
    }

    #[test]
    fn parses_elf64_type2_and_detects_squashfs_at_window_boundary_and_dwarfs() {
        let hdr = minimal_elf64_le(*b"AI\x02", 128, 64, 2);
        let summary = parse_elf_header(&hdr, Path::new("app.AppImage")).unwrap();
        assert_eq!(summary.class, ElfClass::Elf64);
        assert_eq!(summary.endianness, ElfEndianness::Little);
        assert_eq!(summary.signature, AppImageSignature::Type2);

        let end =
            compute_elf_end_offset(&summary, &[], &[], 4096, Path::new("app.AppImage")).unwrap();
        assert_eq!(end, 256);

        let mut window_boundary = vec![0u8; 4096];
        window_boundary[4092..4096].copy_from_slice(b"hsqs");
        let payload = detect_payload_at_window(
            &summary,
            end,
            &window_boundary,
            &[],
            Path::new("app.AppImage"),
        )
        .unwrap();
        assert_eq!(
            payload,
            AppImagePayloadKind::Type2SquashFs {
                offset: 256 + 4092,
                endian: SquashFsEndian::Little
            }
        );

        assert!(
            detect_payload_at_window(
                &summary,
                u64::MAX - 10,
                &window_boundary,
                &[],
                Path::new("app.AppImage")
            )
            .is_err()
        );

        let dwarfs_err =
            detect_payload_at_window(&summary, end, b"DWARFS\x01", &[], Path::new("app.AppImage"));
        assert!(dwarfs_err.is_err());
    }

    #[test]
    fn requires_cd001_verification_even_when_ai01_present() {
        let hdr = minimal_elf64_le(*b"AI\x01", 0, 0, 0);
        let summary = parse_elf_header(&hdr, Path::new("t1.AppImage")).unwrap();

        assert!(
            detect_payload_at_window(&summary, 64, &[], &[], Path::new("spoof.AppImage")).is_err()
        );
        assert!(
            detect_payload_at_window(&summary, 64, &[], &[b"NOTISO"], Path::new("spoof.AppImage"))
                .is_err()
        );

        let payload = detect_payload_at_window(
            &summary,
            64,
            &[],
            &[b"\x01CD001\x01\x00"],
            Path::new("t1.AppImage"),
        )
        .unwrap();
        assert_eq!(payload, AppImagePayloadKind::Type1Iso);
    }
}
