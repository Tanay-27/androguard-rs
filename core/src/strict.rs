//! Which method makes androguard 4.1.3's `AnalyzeAPK` fail.
//!
//! `Analysis.add(vm)` builds a `MethodAnalysis` for every EncodedMethod of
//! every class_def (in class_def order; a class_data shared by several
//! class_defs is visited once per class_def), and `MethodAnalysis.__init__`
//! disassembles the method when it has a code_item (`_create_basic_block`).
//! Nothing catches `InvalidInstruction` there, so the first method in that
//! order that can't be disassembled fails the whole analysis. The index
//! instead loads everything and leaves such a method without instructions;
//! `first_invalid` finds the method androguard would have failed on, so the
//! Python side can raise its exception.

use rayon::prelude::*;
use rustc_hash::FxHashSet;

use crate::dex::Dex;
use crate::insn::Decoder;
use crate::render::AgResolver;

/// The first method (in `Analysis.add()` order over `dexes`, which are in
/// load order) whose code androguard can't disassemble: (DEX number,
/// class_def index, position in its class_data's direct + virtual methods,
/// code_off, androguard's error). None if every method disassembles.
///
/// A code_item running past the end of the DEX is skipped, as the index
/// skips it (see README, "Truncated code items").
pub fn first_invalid(dexes: &[Dex]) -> Option<(usize, usize, usize, u32, dex_bytecode::DexError)> {
    crate::pool::install(|| {
        // Validity of each distinct code_item, decoded in parallel with the
        // index's decoder (the decode fuzzer checks it agrees with the
        // formatting decoder on validity).
        let per_dex: Vec<Vec<(usize, usize, u32)>> = dexes.iter().map(code_order).collect();
        let found = per_dex.par_iter().enumerate().find_map_first(|(d, order)| {
            let dex = &dexes[d];
            let mut seen = FxHashSet::default();
            let offs: Vec<u32> = order.iter().map(|o| o.2).filter(|o| seen.insert(*o)).collect();
            let bad: FxHashSet<u32> = offs
                .par_iter()
                .filter(|&&off| {
                    let Ok(code) = dex.code(off) else { return false };
                    let mut dec = Decoder::new(code);
                    for _ in &mut dec {}
                    dec.invalid
                })
                .copied()
                .collect();
            order.iter().find(|o| bad.contains(&o.2)).map(|&(ci, pos, off)| (d, ci, pos, off))
        })?;
        let (d, ci, pos, off) = found;
        let dex = &dexes[d];
        let code = dex.code(off).ok()?;
        let err = dex_bytecode::decode_all_with_resolver(code, 0, &AgResolver { dex }).err()?;
        Some((d, ci, pos, off, err))
    })
}

/// (class_def index, position, code_off) of every method with a code_item,
/// in `Analysis.add()` order. A class_data already listed (shared by an
/// earlier class_def) adds nothing new: its code was checked at its first
/// use, which comes first.
fn code_order(dex: &Dex) -> Vec<(usize, usize, u32)> {
    let mut out = Vec::new();
    let mut seen_data = FxHashSet::default();
    for ci in 0..dex.class_count() {
        let Ok(cd) = dex.class_def(ci) else { continue };
        if !dex.has_class_data(cd.class_data_off) || !seen_data.insert(cd.class_data_off) {
            continue;
        }
        let Ok(data) = dex.class_data(cd.class_data_off) else { continue };
        for (pos, m) in data.direct_methods.iter().chain(&data.virtual_methods).enumerate() {
            if dex.has_code_item(m.code_off) {
                out.push((ci, pos, m.code_off));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdex::{Class, Spec, build};

    fn dex(codes: Vec<Vec<u8>>) -> Dex {
        // strings: 0 "LA;", 1 "V", 2 "a", 3 "b", 4 "c"
        let n = codes.len() as u32;
        build(&Spec {
            strings: vec!["LA;", "V", "a", "b", "c"],
            types: vec![0, 1],
            protos: vec![(1, 1)],
            fields: vec![],
            methods: (0..n).map(|i| (0, 0, 2 + i)).collect(),
            classes: vec![Class {
                type_idx: 0,
                super_idx: 0,
                static_fields: vec![],
                instance_fields: vec![],
                direct: codes.into_iter().enumerate().map(|(i, c)| (i as u32, 0x9, Some(c))).collect(),
                static_values: vec![],
            }],
        })
    }

    #[test]
    fn valid_dex_has_none() {
        let d = dex(vec![vec![0x0e, 0], vec![0x00, 0, 0x0e, 0]]);
        assert!(first_invalid(std::slice::from_ref(&d)).is_none());
    }

    #[test]
    fn first_in_add_order() {
        // 0x3e is unused: androguard can't disassemble it.
        let d = dex(vec![vec![0x0e, 0], vec![0x00, 0, 0x3e, 0], vec![0x3e, 0]]);
        let (dn, ci, pos, _, e) = first_invalid(std::slice::from_ref(&d)).unwrap();
        assert_eq!((dn, ci, pos), (0, 0, 1));
        assert_eq!(e.offset, Some(2));
        let ok = dex(vec![vec![0x0e, 0]]);
        let both = [ok, d];
        assert_eq!(first_invalid(&both).map(|f| (f.0, f.2)), Some((1, 1)));
    }
}
