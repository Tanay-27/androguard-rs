//! Arbitrary bytes as a DEX file, through every query.
#![no_main]

use androguard_core::dex::Dex;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(dex) = Dex::parse(data.to_vec()) {
        let _ = androguard_core::exercise::dex(dex);
    }
});
