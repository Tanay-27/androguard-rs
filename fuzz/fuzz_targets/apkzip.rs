//! Arbitrary bytes as an APK, read the apkInspector way: open, read every
//! entry, then the v2/v3 signing block and its signers' certificates.
#![no_main]

use androguard_core::zipapk::{self, ApkZip, MemSource};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let src = MemSource(data.to_vec());
    let sb = zipapk::signing_block(&src);
    for at in [sb.v2_value, sb.v3_value].into_iter().flatten() {
        if let Ok(block) = zipapk::read_block_value(&src, at) {
            let _ = zipapk::signer_certificates(&block, false);
            let _ = zipapk::signer_certificates(&block, true);
        }
    }
    if let Ok(z) = ApkZip::open(Box::new(src)) {
        for name in z.names().to_vec() {
            if let Ok(b) = z.read(&name) {
                if name.ends_with(".xml") {
                    let _ = androguard_core::axml::walk(&b);
                }
            }
        }
    }
});
