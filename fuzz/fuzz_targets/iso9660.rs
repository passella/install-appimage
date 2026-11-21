#![no_main]

use std::io::Cursor;
use std::path::Path;

use install_appimage::domain::iso9660::{Iso9660Archive, IsoEntryKind};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = Path::new("fuzz.AppImage");
    let mut cursor = Cursor::new(data);
    let Ok(archive) = Iso9660Archive::open(&mut cursor, data.len() as u64, path) else {
        return;
    };

    for entry in archive.entries().iter().take(16) {
        if let IsoEntryKind::File { size, extents } = &entry.kind {
            let _ = archive.read_file(&mut cursor, *size, extents, 64 * 1024, path);
        }
    }
});
