//! Arbitrary bytes as an APK (zip): entry listing, bounded decompression,
//! then every query on the whole-APK index and on its resources.arsc.
#![no_main]

use androguard_core::index::Index;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The strict loader's header checks (every DEX androguard's DEX() rejects
    // is recorded, not loaded).
    let _ = androguard_core::apk::load_bytes_mode(data, androguard_core::apk::HeaderMode::Record);
    if let Ok(dexes) = androguard_core::apk::load_bytes(data) {
        if let Ok(idx) = Index::build(dexes) {
            androguard_core::exercise::index(idx);
        }
    }
    if let Ok(Some(arsc)) = androguard_core::arsc::Arsc::from_apk_bytes(data) {
        androguard_core::exercise::arsc(arsc);
    }
});
