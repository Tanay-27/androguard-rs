//! Arbitrary bytes as resources.arsc: the parse, the analysis, then every
//! resources query.
#![no_main]

use androguard_core::arsc::Arsc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(arsc) = Arsc::parse(data.to_vec()) {
        androguard_core::exercise::arsc(arsc);
    }
});
