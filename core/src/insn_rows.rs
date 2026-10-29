//! Per-method instruction rows: what androguard 4.1.3's `Instruction`
//! objects answer, decoded on demand from one method's insns, nothing kept.
//!
//! One row per instruction `LinearSweepAlgorithm` yields: byte offset,
//! `get_op_value()`, `get_length()`, `get_output()` (None where androguard
//! returns None) and, for opcodes androguard gives a reference kind, the
//! resolved reference (`get_kind(cm, kind, ref)`, which is both
//! `get_translated_kind()` and the text in `get_operands()`'s kind tuple).
//! Raw bytes are a slice of the insns (`raw_len` bytes from `off`), so
//! format fields (`A`, `BBBB`, ...) can be unpacked from them exactly as
//! androguard's constructors do.

use std::cell::RefCell;

use dex_bytecode::{DexError, RefKind, ResolveRef, decode_length, decode_one_with_resolver};

use crate::dex::Dex;
use crate::render::AgResolver;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsnRow {
    /// Byte offset in the method's insns.
    pub off: u32,
    /// `get_op_value()`: the opcode byte, or a payload's ident (0x100,
    /// 0x200, 0x300).
    pub op_value: u16,
    /// `get_length()` in bytes. A payload's comes from its header, so it can
    /// run past the method (the sweep then ends with it).
    pub len: u64,
    /// `len(get_raw())`: `len`, except a packed-switch whose size overruns
    /// the buffer (androguard reads fewer targets) and a fill-array-data cut
    /// short by the end of the method.
    pub raw_len: u32,
    /// `get_output()`, None where androguard's returns None.
    pub output: Option<String>,
    /// The resolved reference, for opcodes with a reference index androguard
    /// resolves (`get_ref_kind()` exists). androguard's `get_kind()` returns
    /// None for a proto or call site (also None here).
    pub kind: Option<String>,
}

/// Records the reference the decoder resolved while formatting, so it isn't
/// resolved twice.
struct Capture<'a, R> {
    inner: &'a R,
    last: RefCell<Option<String>>,
}

impl<R: ResolveRef> ResolveRef for Capture<'_, R> {
    fn resolve(&self, kind: RefKind, index: u32) -> Option<String> {
        let s = self.inner.resolve(kind, index);
        *self.last.borrow_mut() = s.clone();
        s
    }
}

fn u16_le(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]) as u64)
}

fn u32_le(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64)
}

/// The reference index of an opcode whose androguard class has
/// `get_ref_kind()` (21c, 22c, 31c, 35c, 3rc), or None.
fn ref_index(op: u8, raw: &[u8]) -> Option<u32> {
    match op {
        0x1b => Some(u32_le(raw, 2) as u32),
        0x1a | 0x1c | 0x1f | 0x20 | 0x22..=0x25 | 0x52..=0x6d | 0x6e..=0x72 | 0x74..=0x78 | 0xfc..=0xff => {
            Some(u16_le(raw, 2) as u32)
        }
        _ => None,
    }
}

/// androguard's `Kind` for an opcode with a reference, as the resolver's.
fn ref_kind(op: u8) -> RefKind {
    match op {
        0x1a | 0x1b => RefKind::String,
        0x1c | 0x1f | 0x20 | 0x22..=0x25 => RefKind::Type,
        0x52..=0x6d => RefKind::Field,
        0x6e..=0x72 | 0x74..=0x78 | 0xfe => RefKind::Method,
        _ => RefKind::None,
    }
}

/// A payload's `(get_length(), len(get_raw()))`, as androguard computes
/// them from its header; `rest` starts at the payload.
pub fn payload_lengths(unit: u16, rest: &[u8]) -> (u64, u64) {
    let remaining = rest.len() as u64;
    match unit {
        0x100 => {
            let size = u16_le(rest, 2);
            let targets = if size * 4 > remaining { remaining.saturating_sub(16) } else { size };
            (8 + 4 * size, 8 + 4 * targets)
        }
        0x200 => {
            let l = 4 + 8 * u16_le(rest, 2);
            (l, l)
        }
        _ => {
            let l = 8 + ((u32_le(rest, 4) * u16_le(rest, 2) + 1) & !1);
            (l, l.min(remaining))
        }
    }
}

/// One instruction's place in a method's insns: `InsnRow` without the text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InsnSpan {
    pub off: u32,
    pub op_value: u16,
    pub len: u64,
    pub raw_len: u32,
}

/// The instructions `insn_rows` gives (same boundaries, same error on
/// bytecode androguard rejects), without formatting their text or
/// resolving references.
pub fn insn_spans(code: &[u8]) -> Result<Vec<InsnSpan>, DexError> {
    let mut out = Vec::with_capacity(code.len() / 4);
    let mut off = 0usize;
    while off < code.len() {
        let (unit, length) = decode_length(code, off).map_err(|mut e| {
            e.offset = Some(off);
            e
        })?;
        let rest = &code[off..];
        let span = if unit > 0xff {
            let (len, raw_len) = payload_lengths(unit, rest);
            InsnSpan { off: off as u32, op_value: unit, len, raw_len: raw_len as u32 }
        } else {
            InsnSpan { off: off as u32, op_value: unit, len: length as u64, raw_len: length }
        };
        let next = off as u64 + span.len;
        out.push(span);
        if next >= code.len() as u64 {
            break;
        }
        off = next as usize;
    }
    Ok(out)
}

/// Every instruction of one method's insns, as androguard 4.1.3's
/// `DCode.get_instructions()` yields them. On bytecode androguard rejects,
/// the error `decode_all_with_resolver` gives (offset set), and no rows.
pub fn insn_rows(dex: &Dex, code: &[u8]) -> Result<Vec<InsnRow>, DexError> {
    insn_rows_with(&AgResolver { dex }, code)
}

/// `insn_rows` with any resolver (the fuzzers use a synthetic one).
pub fn insn_rows_with<R: ResolveRef>(resolver: &R, code: &[u8]) -> Result<Vec<InsnRow>, DexError> {
    let cap = Capture { inner: resolver, last: RefCell::new(None) };
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < code.len() {
        let row = row_at(&cap, code, off)?;
        // The sweep stops once an instruction's length reaches the end.
        let next = off as u64 + row.len;
        out.push(row);
        if next >= code.len() as u64 {
            break;
        }
        off = next as usize;
    }
    Ok(out)
}

/// The row of the instruction starting at `off` (an offset `insn_spans`
/// gives): what `insn_rows` has for it, decoding only that instruction.
pub fn insn_row_at(dex: &Dex, code: &[u8], off: usize) -> Result<InsnRow, DexError> {
    let cap = Capture { inner: &AgResolver { dex }, last: RefCell::new(None) };
    row_at(&cap, code, off)
}

/// What an instruction's resolved reference (`InsnRow::kind`) depends on,
/// besides the DEX: its opcode and reference index, for the instruction at
/// `off` (an offset `insn_spans` gives); None for one without a reference
/// androguard resolves (its `kind` is None).
pub fn kind_key(code: &[u8], off: usize) -> Option<(u8, u32)> {
    let rest = code.get(off..)?;
    let unit = u16_le(rest, 0) as u16;
    if unit > 0xff && (unit as u8 == 0 || unit as u8 == 0xff) {
        return None;
    }
    let op = unit as u8;
    let idx = ref_index(op, rest)?;
    match ref_kind(op) {
        RefKind::None => None,
        _ => Some((op, idx)),
    }
}

fn row_at<R: ResolveRef>(cap: &Capture<'_, R>, code: &[u8], off: usize) -> Result<InsnRow, DexError> {
    *cap.last.borrow_mut() = None;
    let ins = decode_one_with_resolver(code, off, cap).map_err(|mut e| {
        e.offset = Some(off);
        e
    })?;
    let rest = &code[off..];
    let unit = u16_le(rest, 0) as u16;
    Ok(if ins.opcode == 0 && unit > 0xff {
        let (len, raw_len) = payload_lengths(unit, rest);
        InsnRow { off: off as u32, op_value: unit, len, raw_len: raw_len as u32, output: Some(ins.operands), kind: None }
    } else {
        let op = ins.opcode;
        let kind = ref_index(op, rest).and_then(|idx| match ref_kind(op) {
            // androguard's get_kind() has no branch for PROTO / CALL_SITE.
            RefKind::None => None,
            k => Some(cap.last.borrow_mut().take().unwrap_or_else(|| {
                // 35c with more than 5 registers prints nothing, so the
                // decoder resolved nothing; androguard still resolves it.
                cap.inner.resolve(k, idx).unwrap_or_default()
            })),
        });
        let output = if ins.output_is_none { None } else { Some(ins.operands) };
        InsnRow { off: off as u32, op_value: op as u16, len: ins.length as u64, raw_len: ins.length, output, kind }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdex::{Class, Spec, build};

    fn dex() -> Dex {
        // strings: 0 "<init>", 1 "LA;", 2 "V", 3 "hello", 4 "f"
        build(&Spec {
            strings: vec!["<init>", "LA;", "V", "hello", "f"],
            types: vec![1, 2],
            protos: vec![(2, 1)],
            fields: vec![(0, 0, 4)],
            methods: vec![(0, 0, 0)],
            classes: vec![Class {
                type_idx: 0,
                super_idx: 0,
                static_fields: vec![],
                instance_fields: vec![],
                direct: vec![(0, 0x10001, Some(vec![0x0e, 0]))],
                static_values: vec![],
            }],
        })
    }

    fn row(off: u32, op: u16, len: u64, out: &str, kind: Option<&str>) -> InsnRow {
        InsnRow { off, op_value: op, len, raw_len: len as u32, output: Some(out.into()), kind: kind.map(Into::into) }
    }

    #[test]
    fn plain_and_kinded() {
        let d = dex();
        let code = [
            0x12, 0xf1, // const/4 v1, -1
            0x1a, 0x00, 0x03, 0x00, // const-string v0, "hello"
            0x1b, 0x02, 0x03, 0x00, 0x00, 0x00, // const-string/jumbo v2, hello (no quotes)
            0x60, 0x00, 0x00, 0x00, // sget v0, LA;->f LA;
            0x70, 0x10, 0x00, 0x00, 0x01, 0x00, // invoke-direct {v1}, LA;-><init>()V
            0x0e, 0x00,
        ];
        let rows = insn_rows(&d, &code).unwrap();
        assert_eq!(
            rows,
            vec![
                row(0, 0x12, 2, "v1, -1", None),
                row(2, 0x1a, 4, "v0, \"hello\"", Some("hello")),
                row(6, 0x1b, 6, "v2, hello", Some("hello")),
                row(12, 0x60, 4, "v0, LA;->f LA;", Some("LA;->f LA;")),
                row(16, 0x70, 6, "v1, LA;-><init>()V", Some("LA;-><init>()V")),
                row(22, 0x0e, 2, "", None),
            ]
        );
    }

    #[test]
    fn kinds_androguard_does_not_resolve() {
        let d = dex();
        // invoke-custom (call site) and const-method-type (proto): None.
        // 35c with A=6: no output text, but the method still resolves.
        let code = [0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x6e, 0x60, 0x00, 0x00, 0x00, 0x00];
        let rows = insn_rows(&d, &code).unwrap();
        assert_eq!(rows[0].kind, None);
        assert_eq!(rows[1].kind, None);
        assert_eq!(rows[1].output.as_deref(), Some("v0, None"));
        assert_eq!(rows[2].output.as_deref(), Some(""));
        assert_eq!(rows[2].kind.as_deref(), Some("LA;-><init>()V"));
        // invoke-polymorphic with A=0: get_output() is None.
        let rows = insn_rows(&d, &[0xfa, 0x00, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!((rows[0].output.clone(), rows[0].kind.clone()), (None, None));
    }

    #[test]
    fn payloads() {
        let d = dex();
        // nop, then packed-switch (size 2, first_key -1), sparse-switch
        // (size 1), fill-array-data (width 1, size 3: data padded to 4).
        let mut code = vec![0x00, 0x00];
        code.extend([0x00, 0x01, 0x02, 0x00, 0xff, 0xff, 0xff, 0xff, 1, 0, 0, 0, 2, 0, 0, 0]);
        code.extend([0x00, 0x02, 0x01, 0x00, 5, 0, 0, 0, 9, 0, 0, 0]);
        code.extend([0x00, 0x03, 0x01, 0x00, 3, 0, 0, 0, b'a', b'b', b'c', 0]);
        let rows = insn_rows(&d, &code).unwrap();
        assert_eq!(rows.len(), 4);
        assert_eq!((rows[1].off, rows[1].op_value, rows[1].len, rows[1].raw_len), (2, 0x100, 16, 16));
        assert_eq!(rows[1].output.as_deref(), Some("-1 0"));
        assert_eq!((rows[2].off, rows[2].op_value, rows[2].len), (18, 0x200, 12));
        assert_eq!(rows[2].output.as_deref(), Some("5"));
        assert_eq!((rows[3].off, rows[3].op_value, rows[3].len, rows[3].raw_len), (30, 0x300, 12, 12));
        assert_eq!(rows[3].output.as_deref(), Some("b'abc\\x00' | \\x61\\x62\\x63\\x00"));
    }

    #[test]
    fn truncated_payloads_end_the_sweep() {
        let d = dex();
        // fill-array-data claiming 100 bytes with 2 present: raw is what's there.
        let code = [0x00, 0x03, 0x01, 0x00, 100, 0, 0, 0, 7, 8];
        let rows = insn_rows(&d, &code).unwrap();
        assert_eq!((rows.len(), rows[0].len, rows[0].raw_len), (1, 108, 10));
        // packed-switch whose size overruns a tiny buffer: 2 targets read
        // (len(buff) - 16), length still from the size.
        let code = [0x00, 0x01, 0x10, 0x00, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0];
        let rows = insn_rows(&d, &code).unwrap();
        assert_eq!((rows.len(), rows[0].len, rows[0].raw_len), (1, 72, 16));
        // A payload cut short of its last instruction ends the sweep but keeps it.
        let code = [0x0e, 0x00, 0x00, 0x02, 0x01, 0x00, 1, 0, 0, 0, 2, 0, 0, 0];
        let rows = insn_rows(&d, &code).unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn jumbo_string_index_is_signed() {
        // androguard reads 31c's index as a signed int and indexes a Python
        // list with it: -1 is the last string, -5 the first, -6 out of range.
        let d = dex();
        let text = |idx: u32| {
            let mut code = vec![0x1b, 0x00];
            code.extend(idx.to_le_bytes());
            let r = insn_rows(&d, &code).unwrap().remove(0);
            (r.output.unwrap(), r.kind.unwrap())
        };
        assert_eq!(text(0xffff_ffff), ("v0, f".into(), "f".into()));
        assert_eq!(text(0xffff_fffb), ("v0, <init>".into(), "<init>".into()));
        assert_eq!(text(0xffff_fffa).1, "AG:IS: invalid string");
        assert_eq!(text(0x8000_0000).1, "AG:IS: invalid string");
        assert_eq!(text(5).1, "AG:IS: invalid string");
    }

    #[test]
    fn invalid_is_an_error_with_offset() {
        let d = dex();
        let e = insn_rows(&d, &[0x0e, 0x00, 0x3e, 0x00]).unwrap_err();
        assert_eq!(e.offset, Some(2));
        assert!(e.message().contains("0x3e"));
        // Same validity as the formatting decoder on a short read.
        assert!(insn_rows(&d, &[0x14, 0x00, 0x00]).is_err());
    }

    #[test]
    fn spans_agree_with_rows() {
        let d = dex();
        let codes: Vec<Vec<u8>> = vec![
            vec![0x12, 0xf1, 0x1a, 0x00, 0x03, 0x00, 0x0e, 0x00],
            vec![0x00, 0x03, 0x01, 0x00, 100, 0, 0, 0, 7, 8],
            vec![0x00, 0x01, 0x10, 0x00, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0],
            vec![0x0e, 0x00, 0x00, 0x02, 0x01, 0x00, 1, 0, 0, 0, 2, 0, 0, 0],
            vec![0x0e, 0x00, 0x3e, 0x00],
            vec![0x14, 0x00, 0x00],
            vec![0x0e, 0x01],
            vec![0x00, 0x05, 0x00, 0x00],
            vec![0xfa, 0x60, 0, 0, 0, 0, 0, 0],
        ];
        for code in codes {
            match (insn_rows(&d, &code), insn_spans(&code)) {
                (Ok(rows), Ok(spans)) => {
                    let r: Vec<_> = rows.iter().map(|r| (r.off, r.op_value, r.len, r.raw_len)).collect();
                    let s: Vec<_> = spans.iter().map(|s| (s.off, s.op_value, s.len, s.raw_len)).collect();
                    assert_eq!(r, s);
                    for row in &rows {
                        assert_eq!(&insn_row_at(&d, &code, row.off as usize).unwrap(), row);
                        assert_eq!(kind_key(&code, row.off as usize).is_some(), row.kind.is_some());
                    }
                }
                (Err(a), Err(b)) => assert_eq!((a.offset, a.message()), (b.offset, b.message())),
                (a, b) => panic!("{code:?}: {a:?} vs {b:?}"),
            }
        }
    }

    #[test]
    fn agrees_with_decode_all() {
        // Same instruction boundaries and text as the decoder bytecode() uses.
        let d = dex();
        let code = [0x12, 0x01, 0x28, 0xff, 0x00, 0x01, 0x01, 0x00, 0, 0, 0, 0, 3, 0, 0, 0, 0x0e, 0x00];
        let rows = insn_rows(&d, &code).unwrap();
        let all = dex_bytecode::decode_all_with_resolver(&code, 0, &AgResolver { dex: &d }).unwrap();
        assert_eq!(rows.len(), all.len());
        for (r, i) in rows.iter().zip(&all) {
            assert_eq!((r.off, r.len, r.output.as_deref()), (i.offset, i.length as u64, Some(i.operands.as_str())));
        }
    }
}
