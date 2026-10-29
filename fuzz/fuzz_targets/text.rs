//! Arbitrary bytes as DEX string data, through decoding and every text
//! transform applied to it.
#![no_main]

use androguard_core::classes::py_str_repr;
use androguard_core::render::{escape_field, mutf8_decode, py_bytes_repr, py_lower};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = py_bytes_repr(data);
    if let Some(s) = mutf8_decode(data) {
        let lower = py_lower(&s);
        let _ = py_str_repr(&lower);
        let mut out = String::new();
        escape_field(&s, &mut out);
    }
});
