//! Table-driven Dalvik decoder. Yields (offset, opcode, reference) per
//! instruction straight from the insns bytes; nothing is allocated or kept.

use crate::dex::u16_at;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ref {
    None,
    String,
    Type,
    Field,
    Method,
    Proto,
    CallSite,
    MethodHandle,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fmt {
    /// Reference index in code unit 1 (21c, 22c, 35c, 3rc, 45cc, 4rcc).
    Unit1,
    /// 32-bit reference index in code units 1-2 (31c).
    Wide,
    NoRef,
}

/// (length in 16-bit code units, how to read the reference, its kind).
fn op_info(op: u8) -> (u32, Fmt, Ref) {
    use Fmt::*;
    match op {
        0x00 | 0x01 | 0x04 | 0x07 => (1, NoRef, Ref::None),
        0x02 | 0x05 | 0x08 => (2, NoRef, Ref::None),
        0x03 | 0x06 | 0x09 => (3, NoRef, Ref::None),
        0x0a..=0x12 => (1, NoRef, Ref::None),
        0x13 | 0x15 | 0x16 | 0x19 => (2, NoRef, Ref::None),
        0x14 | 0x17 => (3, NoRef, Ref::None),
        0x18 => (5, NoRef, Ref::None),
        0x1a => (2, Unit1, Ref::String),
        0x1b => (3, Wide, Ref::String),
        0x1c | 0x1f | 0x22 => (2, Unit1, Ref::Type),
        0x1d | 0x1e | 0x21 | 0x27 | 0x28 => (1, NoRef, Ref::None),
        0x20 | 0x23 => (2, Unit1, Ref::Type),
        0x24 | 0x25 => (3, Unit1, Ref::Type),
        0x26 | 0x2a | 0x2b | 0x2c => (3, NoRef, Ref::None),
        0x29 | 0x2d..=0x3d => (2, NoRef, Ref::None),
        0x3e..=0x43 => (1, NoRef, Ref::None),
        0x44..=0x51 => (2, NoRef, Ref::None),
        0x52..=0x6d => (2, Unit1, Ref::Field),
        0x6e..=0x72 | 0x74..=0x78 => (3, Unit1, Ref::Method),
        0x73 | 0x79 | 0x7a => (1, NoRef, Ref::None),
        0x7b..=0x8f => (1, NoRef, Ref::None),
        0x90..=0xaf => (2, NoRef, Ref::None),
        0xb0..=0xcf => (1, NoRef, Ref::None),
        0xd0..=0xe2 => (2, NoRef, Ref::None),
        0xe3..=0xf9 => (1, NoRef, Ref::None),
        0xfa | 0xfb => (4, Unit1, Ref::Method),
        0xfc | 0xfd => (3, Unit1, Ref::CallSite),
        0xfe => (2, Unit1, Ref::MethodHandle),
        0xff => (2, Unit1, Ref::Proto),
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Insn {
    /// Offset in bytes from the start of insns (androguard's `idx`).
    pub off: u32,
    pub op: u8,
    /// Nonzero only for the three payload pseudo-instructions (0x0100, 0x0200, 0x0300).
    pub payload: u8,
    pub kind: Ref,
    pub idx: u32,
}

pub struct Decoder<'a> {
    code: &'a [u8],
    units: usize,
    pos: usize,
    /// Set if a payload claims to run past the end of insns. androguard's
    /// sweep just stops there; what came before still counts.
    pub truncated: bool,
    /// Set if androguard 4.1.3 would reject this method's bytecode (its
    /// get_instructions() raises InvalidInstruction). Then the method has no
    /// instructions at all, so callers must discard what was yielded.
    pub invalid: bool,
}

impl<'a> Decoder<'a> {
    pub fn new(code: &'a [u8]) -> Self {
        Decoder { code, units: code.len() / 2, pos: 0, truncated: false, invalid: false }
    }

    #[inline]
    fn unit(&self, i: usize) -> Option<u32> {
        u16_at(self.code, i * 2).ok().map(|u| u as u32)
    }

    /// A payload's length in code units, or None where androguard's parse
    /// of it hits a short read (struct.error -> InvalidInstruction). Mirrors
    /// the vendored decoder's `decode_payload`.
    fn payload_len(&self, ident: u32) -> Option<u64> {
        let p = self.pos;
        let remaining = ((self.units - p) * 2) as u64;
        match ident {
            // packed-switch-payload: ident, size, first_key(2), targets(size*2)
            1 => {
                if remaining < 8 {
                    return None;
                }
                let size = self.unit(p + 1)? as u64;
                let targets = if size * 4 > remaining { remaining.saturating_sub(16) } else { size };
                (8 + 4 * targets <= remaining).then_some(4 + 2 * size)
            }
            // sparse-switch-payload: ident, size, keys(size*2), targets(size*2)
            2 => {
                let size = self.unit(p + 1)? as u64;
                (4 + 8 * size <= remaining).then_some(2 + 4 * size)
            }
            // fill-array-data-payload: ident, width, size(2), data (truncated if short, never an error)
            3 => {
                if remaining < 8 {
                    return None;
                }
                let width = self.unit(p + 1)? as u64;
                let size = self.unit(p + 2)? as u64 | (self.unit(p + 3)? as u64) << 16;
                Some(4 + (size * width).div_ceil(2))
            }
            _ => None,
        }
    }

    fn reject(&mut self) -> Option<Insn> {
        self.invalid = true;
        self.pos = self.units;
        None
    }
}

/// Opcodes androguard 4.1.3 treats as unused (Instruction00x): always invalid.
fn unused(op: u8) -> bool {
    matches!(op, 0x3e..=0x43 | 0x73 | 0x79 | 0x7a | 0xe3..=0xf9)
}

impl Iterator for Decoder<'_> {
    type Item = Insn;

    fn next(&mut self) -> Option<Insn> {
        if self.pos >= self.units {
            return None;
        }
        let u0 = self.unit(self.pos)?;
        let op = (u0 & 0xff) as u8;
        let off = (self.pos * 2) as u32;

        // Same validity rules as the vendored decoder (androguard 4.1.3's
        // LinearSweepAlgorithm): see decode_one_with_resolver.
        if u0 > 0xff && (op == 0x00 || op == 0xff) {
            let ident = u0 >> 8;
            if op != 0x00 || !(1..=3).contains(&ident) {
                return self.reject();
            }
            let Some(len) = self.payload_len(ident) else { return self.reject() };
            if self.pos as u64 + len > self.units as u64 {
                // Runs past the method: androguard's sweep simply ends here.
                self.truncated = true;
                self.pos = self.units;
            } else {
                self.pos += len as usize;
            }
            return Some(Insn { off, op, payload: ident as u8, kind: Ref::None, idx: 0 });
        }

        let (len, fmt, kind) = op_info(op);
        let padding = (u0 >> 8) as u8;
        if unused(op)
            || self.pos + len as usize > self.units
            || (matches!(op, 0x00 | 0x0e | 0x29 | 0x2a | 0x03 | 0x06 | 0x09) && padding != 0)
            || (matches!(op, 0xfa) && padding >> 4 > 5)
        {
            return self.reject();
        }
        let idx = match fmt {
            Fmt::Unit1 => self.unit(self.pos + 1)?,
            Fmt::Wide => self.unit(self.pos + 1)? | self.unit(self.pos + 2)? << 16,
            Fmt::NoRef => 0,
        };
        self.pos += len as usize;
        Some(Insn { off, op, payload: 0, kind, idx })
    }
}
