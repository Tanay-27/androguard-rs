//! Arbitrary bytes as binary XML: the whole AXMLParser walk, with every
//! accessor AXMLPrinter uses.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = androguard_core::axml::walk(data);
});
