#![no_main]

use install_appimage::domain::svg_sanitizer::validate_safe_svg;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = validate_safe_svg(data);
});
