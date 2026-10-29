//! Arbitrary bytes as a method's code. Besides not crashing, the formatting
//! decoder (androguard-compatible text) and the index's lightweight decoder
//! must agree on whether androguard would reject the method, and if not, on
//! every instruction offset — otherwise bytecode() and the xref index would
//! disagree about the same method. The Instruction rows (`insn_rows`, behind
//! `Apk.instructions()`) must agree with both: same error, same offsets and
//! text, lengths and raw slices within the method.
#![no_main]

use androguard_core::insn::Decoder;
use dex_bytecode::{FnResolver, RefKind};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let code = &data[..data.len() / 2 * 2]; // code_items are whole 16-bit units
    let resolver = FnResolver(|k: RefKind, i: u32| Some(format!("{k:?}@{i}")));
    let formatted = dex_bytecode::decode_all_with_resolver(code, 0, &resolver);

    let mut light = Decoder::new(code);
    let offsets: Vec<u32> = (&mut light).map(|i| i.off).collect();

    let rows = androguard_core::insn_rows::insn_rows_with(&resolver, code);

    match formatted {
        Err(e) => {
            assert!(light.invalid, "androguard rejects this method but the index decoder accepted it: {e:?}");
            let _ = androguard_core::render::invalid_instruction_str(&e);
            let r = rows.expect_err("insn_rows accepted a method androguard rejects");
            assert_eq!((r.offset, r.message()), (e.offset, e.message()), "insn_rows reports another error");
        }
        Ok(insns) => {
            assert!(!light.invalid, "the index decoder rejected a method androguard accepts");
            let expected: Vec<u32> = insns.iter().map(|i| i.offset).collect();
            assert_eq!(offsets, expected, "decoders disagree on instruction boundaries");
            let rows = rows.expect("insn_rows rejected a method androguard accepts");
            assert_eq!(rows.len(), insns.len(), "insn_rows yields another number of instructions");
            for (r, i) in rows.iter().zip(&insns) {
                assert_eq!(r.off, i.offset);
                assert_eq!(r.output.as_deref(), (!i.output_is_none).then_some(i.operands.as_str()));
                assert!(r.raw_len as u64 <= r.len && r.off as usize + r.raw_len as usize <= code.len());
                if r.op_value <= 0xff {
                    assert_eq!((r.len, r.raw_len), (i.length as u64, i.length));
                }
            }
        }
    }
});
