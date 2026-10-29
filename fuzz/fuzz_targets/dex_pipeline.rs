//! Arbitrary bytes as a DEX file: androguard's load steps (DEX(),
//! Analysis.add(), create_xref()) as `agload` follows them, then every
//! query.
#![no_main]

use androguard_core::agload;
use androguard_core::dex::Dex;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let st = agload::load(data, 970, 6650).ok();
    if let Ok(dex) = Dex::parse(data.to_vec()) {
        if let Some(st) = &st {
            if agload::add_error(st, &dex).is_none() {
                let _ = agload::xref_error(st, &dex);
            }
        }
        let _ = androguard_core::exercise::dex(dex);
    }
});
