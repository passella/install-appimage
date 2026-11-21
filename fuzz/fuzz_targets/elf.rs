#![no_main]

use std::path::Path;

use install_appimage::domain::elf::{
    compute_elf_end_offset, detect_payload_at_window, parse_elf_header,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = Path::new("fuzz.AppImage");
    let Ok(summary) = parse_elf_header(data, path) else {
        return;
    };
    let _ = summary.program_table_end();
    let _ = summary.section_table_end();

    let ph_start = (summary.phoff as usize).min(data.len());
    let sh_start = (summary.shoff as usize).min(data.len());
    let elf_end = compute_elf_end_offset(
        &summary,
        &data[ph_start..],
        &data[sh_start..],
        data.len() as u64,
        path,
    );
    if let Ok(end) = elf_end {
        let win_start = (end as usize).min(data.len());
        let win_end = win_start.saturating_add(4096).min(data.len());
        let probe = data.get(0x8000..0x8008).unwrap_or(&[]);
        let _ = detect_payload_at_window(&summary, end, &data[win_start..win_end], &[probe], path);
    }
});
