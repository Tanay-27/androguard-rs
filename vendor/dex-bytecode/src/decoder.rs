//! Linear-sweep Dalvik instruction decoder.
//! Matches androguard LinearSweepAlgorithm.get_instructions.
//!
//! MODIFIED from upstream androguard/dex-bytecode (see VENDORED.md): operand
//! text and invalid-bytecode rules changed to match androguard 4.1.3's
//! `get_output()` and `LinearSweepAlgorithm` byte for byte.

use alloc::vec::Vec;
use core::convert::TryInto;

use crate::error::DexError;
use crate::instruction::{Instruction, RefKind};
use crate::opcodes::{format_length, get_opcode_entry, get_payload_kind, Format, PayloadKind};
use crate::resolve::ResolveRef;

/// Read little-endian u16 from `data` at `offset`. Returns None if out of bounds.
#[inline]
fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let end = offset + 2;
    if end > data.len() {
        return None;
    }
    let bytes: [u8; 2] = data[offset..end].try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

#[inline]
fn read_i16(data: &[u8], offset: usize) -> Option<i16> {
    read_u16(data, offset).map(|u| u as i16)
}

#[inline]
fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset + 4;
    if end > data.len() {
        return None;
    }
    let bytes: [u8; 4] = data[offset..end].try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

#[inline]
fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
    read_u32(data, offset).map(|u| u as i32)
}

#[inline]
fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let end = offset + 8;
    if end > data.len() {
        return None;
    }
    let bytes: [u8; 8] = data[offset..end].try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Python's `"{:+0<width>x}h".format(rel)`: the sign counts toward `width`,
/// so `+007h` for width 4 — not `+0007h`.
fn fmt_rel_hex(rel: i32, width: usize) -> String {
    let sign = if rel < 0 { '-' } else { '+' };
    format!("{sign}{:0w$x}h", (rel as i64).unsigned_abs(), w = width.saturating_sub(1))
}

/// Python's `"%x" % n` for a signed value: `-1f`, not two's complement.
fn py_hex(n: i64) -> String {
    if n < 0 {
        format!("-{:x}", n.unsigned_abs())
    } else {
        format!("{:x}", n)
    }
}

/// Python's `repr(bytes)`.
fn py_bytes_repr(b: &[u8]) -> String {
    let quote = if b.contains(&b'\'') && !b.contains(&b'"') { '"' } else { '\'' };
    let mut s = String::with_capacity(b.len() * 2 + 3);
    s.push('b');
    s.push(quote);
    for &c in b {
        match c {
            b'\\' => s.push_str("\\\\"),
            b'\t' => s.push_str("\\t"),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            c if c as char == quote => {
                s.push('\\');
                s.push(quote);
            }
            0x20..=0x7e => s.push(c as char),
            _ => s.push_str(&format!("\\x{:02x}", c)),
        }
    }
    s.push(quote);
    s
}

/// Decode a single instruction at `offset` in `data`. Returns the instruction and its length.
pub fn decode_one(data: &[u8], offset: usize) -> Result<Instruction, DexError> {
    decode_one_with_resolver(data, offset, &NoResolver)
}

/// Decode a single instruction at `offset` with reference resolution.
/// Indices are resolved to display strings when the resolver returns `Some`.
pub fn decode_one_with_resolver<R: ResolveRef>(
    data: &[u8],
    offset: usize,
    resolver: &R,
) -> Result<Instruction, DexError> {
    let unit = read_u16(data, offset)
        .ok_or_else(|| DexError::invalid("truncated at first 16-bit unit"))?;
    let op_byte = unit as u8;

    // androguard 4.1.3: any unit > 0xFF whose low byte is 0x00 or 0xFF is a
    // payload or nothing — not a nop/const-method-type with a nonzero high
    // byte. (ODEX-only optimized opcodes aren't supported.) Error messages
    // below are androguard's, verbatim.
    if unit > 0xFF && (op_byte == 0x00 || op_byte == 0xFF) {
        return match get_payload_kind(unit) {
            Some(payload) => decode_payload(data, offset, payload),
            None => Err(DexError::invalid_owned(format!("Unknown Instruction '0x{:04x}'", unit))),
        };
    }

    let entry = get_opcode_entry(op_byte);
    let len = format_length(entry.format) as usize;

    if entry.format == Format::F00x {
        return Err(DexError::invalid_owned(format!(
            "Instruction with opcode '0x{:02x}' is unused! This looks like invalid bytecode.",
            op_byte
        )));
    }

    // A short read is a struct.error in androguard, reported with the repr of
    // every byte left in the method.
    if offset + len > data.len() {
        return Err(DexError::invalid_owned(format!(
            "Invalid Instruction for '0x{:02x}': {}",
            op_byte,
            py_bytes_repr(&data[offset..])
        )));
    }

    // androguard rejects these formats when their padding byte is nonzero.
    if matches!(entry.format, Format::F10x | Format::F20t | Format::F30t | Format::F32x)
        && high_byte(data, offset) != 0
    {
        let fmt = match entry.format {
            Format::F10x => "10x",
            Format::F20t => "20t",
            Format::F30t => "30t",
            _ => "32x",
        };
        return Err(DexError::invalid_owned(format!(
            "High byte of opcode with format {fmt} must be zero!"
        )));
    }
    if entry.format == Format::F45cc && high_byte(data, offset) >> 4 > 5 {
        return Err(DexError::invalid_owned(format!(
            "A is greater than 5 (it is {}) which should never happen!",
            high_byte(data, offset) >> 4
        )));
    }

    let ref_fmt = |kind: RefKind, idx: u32| {
        resolver
            .resolve(kind, idx)
            .unwrap_or_else(|| Instruction::format_ref(kind, idx))
    };
    decode_format(data, offset, op_byte, entry, len, ref_fmt)
}

fn decode_format<F>(
    data: &[u8],
    offset: usize,
    opcode: u8,
    entry: &crate::opcodes::OpcodeEntry,
    len: usize,
    ref_fmt: F,
) -> Result<Instruction, DexError>
where
    F: Fn(RefKind, u32) -> String,
{
    use crate::opcodes::Format;
    use alloc::format;

    let ref_fmt_primary = |idx: u32| ref_fmt(entry.ref_kind, idx);

    let operands = match entry.format {
        Format::F10x => String::new(),
        Format::F10t => {
            let aa = high_byte(data, offset) as i8;
            fmt_rel_hex(aa as i32, 2)
        }
        Format::F11n => {
            let byte = data[offset + 1] as i8;
            let a = (data[offset + 1] & 0x0F) as u32;
            let b = byte >> 4; // 4-bit sign-extended
            format!("v{}, {}", a, b)
        }
        Format::F11x => {
            let aa = high_byte(data, offset);
            format!("v{}", aa)
        }
        Format::F12x => {
            let (a, b) = ab_from_first(data, offset);
            format!("v{}, v{}", a, b)
        }
        Format::F20t => {
            let aaaa = read_i16(data, offset + 2).unwrap_or(0);
            fmt_rel_hex(aaaa as i32, 4)
        }
        Format::F20bc => {
            let aa = data[offset + 1];
            let bbbb = read_u16(data, offset + 2).unwrap_or(0);
            format!("{}, {}", aa, bbbb)
        }
        Format::F21c => {
            let aa = data[offset + 1];
            let bbbb = read_u16(data, offset + 2).unwrap_or(0) as u32;
            if entry.ref_kind == RefKind::String {
                format!("v{}, \"{}\"", aa, ref_fmt_primary(bbbb))
            } else {
                format!("v{}, {}", aa, ref_fmt_primary(bbbb))
            }
        }
        Format::F21h => {
            let aa = data[offset + 1];
            let bbbb = read_i16(data, offset + 2).unwrap_or(0);
            let val: i64 = if opcode == 0x15 {
                (bbbb as i64) << 16
            } else if opcode == 0x19 {
                (bbbb as i64) << 48
            } else {
                bbbb as i64
            };
            format!("v{}, {}", aa, val)
        }
        Format::F21s => {
            let aa = data[offset + 1];
            let bbbb = read_i16(data, offset + 2).unwrap_or(0);
            format!("v{}, {}", aa, bbbb)
        }
        Format::F21t => {
            let aa = data[offset + 1];
            let bbbb = read_i16(data, offset + 2).unwrap_or(0);
            format!("v{}, {}", aa, fmt_rel_hex(bbbb as i32, 4))
        }
        Format::F22b => {
            let aa = data[offset + 1];
            let bb = data[offset + 2];
            let cc = data[offset + 3] as i8;
            format!("v{}, v{}, {}", aa, bb, cc)
        }
        Format::F22c => {
            let (a, b) = ab_from_first(data, offset);
            let cccc = read_u16(data, offset + 2).unwrap_or(0) as u32;
            format!("v{}, v{}, {}", a, b, ref_fmt_primary(cccc))
        }
        Format::F22s => {
            let (a, b) = ab_from_first(data, offset);
            let cccc = read_i16(data, offset + 2).unwrap_or(0);
            format!("v{}, v{}, {}", a, b, cccc)
        }
        Format::F22t => {
            let (a, b) = ab_from_first(data, offset);
            let cccc = read_i16(data, offset + 2).unwrap_or(0);
            format!("v{}, v{}, {}", a, b, fmt_rel_hex(cccc as i32, 4))
        }
        Format::F22cs => {
            let (a, b) = ab_from_first(data, offset);
            let cccc = read_u16(data, offset + 2).unwrap_or(0) as u32;
            format!("v{}, v{}, {}", a, b, ref_fmt_primary(cccc))
        }
        Format::F23x => {
            let aa = data[offset + 1];
            let bb = data[offset + 2];
            let cc = data[offset + 3];
            format!("v{}, v{}, v{}", aa, bb, cc)
        }
        Format::F30t => {
            let aaaaaaaa = read_i32(data, offset + 2).unwrap_or(0);
            fmt_rel_hex(aaaaaaaa, 8)
        }
        Format::F31c => {
            let aa = data[offset + 1];
            let bbbbbbbb = read_u32(data, offset + 2).unwrap_or(0);
            format!("v{}, {}", aa, ref_fmt_primary(bbbbbbbb))
        }
        Format::F31i => {
            let aa = data[offset + 1];
            let bbbbbbbb = read_i32(data, offset + 2).unwrap_or(0);
            format!("v{}, {}", aa, bbbbbbbb)
        }
        Format::F31t => {
            let aa = data[offset + 1];
            let bbbbbbbb = read_i32(data, offset + 2).unwrap_or(0);
            format!("v{}, {}", aa, fmt_rel_hex(bbbbbbbb, 8))
        }
        Format::F32x => {
            let aaaa = read_u16(data, offset + 2).unwrap_or(0);
            let bbbb = read_u16(data, offset + 4).unwrap_or(0);
            format!("v{}, v{}", aaaa, bbbb)
        }
        Format::F35c | Format::F35mi | Format::F35ms => {
            let (a, g, c, d, e, f) = decode_35c(data, offset);
            let bbbb = read_u16(data, offset + 2).unwrap_or(0) as u32;
            let regs = format_35_regs(a, c, d, e, f, g);
            if a > 5 {
                String::new()
            } else if regs.is_empty() {
                ref_fmt_primary(bbbb)
            } else {
                format!("{}, {}", regs, ref_fmt_primary(bbbb))
            }
        }
        Format::F3rc | Format::F3rmi | Format::F3rms => {
            let aa = data[offset + 1];
            let bbbb = read_u16(data, offset + 2).unwrap_or(0) as u32;
            let cccc = read_u16(data, offset + 4).unwrap_or(0);
            let nnnn = cccc as i64 + aa as i64 - 1;
            let kind = ref_fmt_primary(bbbb);
            if cccc as i64 == nnnn {
                format!("v{}, {}", cccc, kind)
            } else {
                format!("v{} ... v{}, {}", cccc, nnnn, kind)
            }
        }
        Format::F40sc => {
            let bbbbbbbb = read_u32(data, offset + 2).unwrap_or(0);
            let aaaa = read_u16(data, offset + 6).unwrap_or(0);
            format!("{}, {}", aaaa, ref_fmt_primary(bbbbbbbb))
        }
        Format::F41c => {
            let bbbbbbbb = read_u32(data, offset + 2).unwrap_or(0);
            let aaaa = read_u16(data, offset + 6).unwrap_or(0);
            format!("v{}, {}", aaaa, ref_fmt_primary(bbbbbbbb))
        }
        Format::F45cc => {
            let (a, g, c, d, e, f) = decode_35c(data, offset);
            let bbbb = read_u16(data, offset + 2).unwrap_or(0) as u32;
            let hhhh = read_u16(data, offset + 6).unwrap_or(0) as u32;
            let regs = format_35_regs(a, c, d, e, f, g);
            if regs.is_empty() {
                // androguard's get_output() falls off the end and returns None;
                // flagged on the Instruction below.
                String::from("None")
            } else {
                format!("{}, {}, {}", regs, bbbb, hhhh)
            }
        }
        Format::F4rcc => {
            let aa = data[offset + 1];
            let bbbb = read_u16(data, offset + 2).unwrap_or(0) as u32;
            let cccc = read_u16(data, offset + 4).unwrap_or(0);
            let hhhh = read_u16(data, offset + 6).unwrap_or(0) as u32;
            let nnnn = cccc as i64 + aa as i64 - 1;
            format!("v{} .. v{} {} {}", cccc, nnnn, bbbb, hhhh)
        }
        Format::F51l => {
            let aa = data[offset + 1];
            let raw = read_u64(data, offset + 2).unwrap_or(0);
            format!("v{}, {}", aa, raw as i64)
        }
        Format::F52c => {
            let cccccccc = read_u32(data, offset + 2).unwrap_or(0);
            let aaaa = read_u16(data, offset + 6).unwrap_or(0);
            let bbbb = read_u16(data, offset + 8).unwrap_or(0);
            format!("v{}, v{}, {}", aaaa, bbbb, ref_fmt_primary(cccccccc))
        }
        Format::F5rc => {
            let bbbbbbbb = read_u32(data, offset + 2).unwrap_or(0);
            let aaaa = read_u16(data, offset + 6).unwrap_or(0);
            let cccc = read_u16(data, offset + 8).unwrap_or(0);
            let nnnn = cccc as i64 + aaaa as i64 - 1;
            let kind = ref_fmt_primary(bbbbbbbb);
            if cccc as i64 == nnnn {
                format!("v{}, {}", cccc, kind)
            } else {
                format!("v{} ... v{}, {}", cccc, nnnn, kind)
            }
        }
        Format::F22x => {
            let aa = data[offset + 1];
            let bbbb = read_u16(data, offset + 2).unwrap_or(0);
            format!("v{}, v{}", aa, bbbb)
        }
        Format::F00x => String::new(),
    };

    let mut ins = Instruction::new(offset as u32, len as u32, opcode, entry.mnemonic, operands);
    ins.output_is_none = entry.format == Format::F45cc && (data[offset + 1] >> 4) == 0;
    Ok(ins)
}

#[inline]
fn high_byte(data: &[u8], offset: usize) -> u8 {
    data.get(offset + 1).copied().unwrap_or(0)
}

#[inline]
fn ab_from_first(data: &[u8], offset: usize) -> (u8, u8) {
    let w = read_u16(data, offset).unwrap_or(0);
    let a = ((w >> 8) & 0x0F) as u8;
    let b = ((w >> 12) & 0x0F) as u8;
    (a, b)
}

#[inline]
fn decode_35c(data: &[u8], offset: usize) -> (u8, u8, u8, u8, u8, u8) {
    let w1 = read_u16(data, offset).unwrap_or(0);
    let w2 = read_u16(data, offset + 4).unwrap_or(0);
    let a = ((w1 >> 12) & 0x0F) as u8;
    let g = ((w1 >> 8) & 0x0F) as u8;
    let c = (w2 & 0x0F) as u8;
    let d = ((w2 >> 4) & 0x0F) as u8;
    let e = ((w2 >> 8) & 0x0F) as u8;
    let f = ((w2 >> 12) & 0x0F) as u8;
    (a, g, c, d, e, f)
}

fn format_35_regs(a: u8, c: u8, d: u8, e: u8, f: u8, g: u8) -> String {
    match a {
        0 => String::new(),
        1 => format!("v{}", c),
        2 => format!("v{}, v{}", c, d),
        3 => format!("v{}, v{}, v{}", c, d, e),
        4 => format!("v{}, v{}, v{}, v{}", c, d, e, f),
        5 => format!("v{}, v{}, v{}, v{}, v{}", c, d, e, f, g),
        _ => String::new(),
    }
}

/// Payload pseudo-instructions, parsed exactly as androguard 4.1.3 does:
/// a header or element that can't be read is a struct.error (reported with
/// the repr of the rest of the method); fill-array-data silently truncates
/// its data; packed-switch reads fewer targets when its size overruns the
/// buffer. The returned length can run past the method: the sweep then just
/// stops, as androguard's does.
fn decode_payload(data: &[u8], offset: usize, kind: PayloadKind) -> Result<Instruction, DexError> {
    let rest = &data[offset..];
    let remaining = rest.len() as u64;
    let short_read = || {
        let ident = read_u16(rest, 0).unwrap_or(0);
        DexError::invalid_owned(format!("Invalid Instruction for '0x{:04x}': {}", ident, py_bytes_repr(rest)))
    };
    let (name, len, operands) = match kind {
        PayloadKind::PackedSwitch => {
            // ident, size, first_key, then targets.
            if remaining < 8 {
                return Err(short_read());
            }
            let size = read_u16(rest, 2).unwrap_or(0) as u64;
            let first_key = read_i32(rest, 4).unwrap_or(0) as i64;
            // androguard: `if size * 4 > len(buff): max_size = len(buff) - 8 - 8`.
            let targets = if size * 4 > remaining { remaining.saturating_sub(16) } else { size };
            if 8 + 4 * targets > remaining {
                return Err(short_read());
            }
            let keys = (0..targets).map(|i| py_hex(first_key + i as i64)).collect::<Vec<_>>().join(" ");
            ("packed-switch-payload", 8 + size * 4, keys)
        }
        PayloadKind::SparseSwitch => {
            // ident, size, then size keys and size targets.
            if remaining < 4 {
                return Err(short_read());
            }
            let size = read_u16(rest, 2).unwrap_or(0) as u64;
            if 4 + 8 * size > remaining {
                return Err(short_read());
            }
            let keys = (0..size as usize)
                .map(|i| py_hex(read_i32(rest, 4 + 4 * i).unwrap_or(0) as i64))
                .collect::<Vec<_>>()
                .join(" ");
            ("sparse-switch-payload", 4 + 8 * size, keys)
        }
        PayloadKind::FillArrayData => {
            // ident, element_width, size, then the data (padded to even).
            if remaining < 8 {
                return Err(short_read());
            }
            let width = read_u16(rest, 2).unwrap_or(0) as u64;
            let size = read_u32(rest, 4).unwrap_or(0) as u64;
            let data_len = (size * width + 1) & !1;
            let bytes = &rest[8..(8 + data_len).min(remaining) as usize];
            let mut s = py_bytes_repr(bytes);
            s.push_str(" | ");
            for b in bytes {
                s.push_str(&format!("\\x{:02x}", b));
            }
            ("fill-array-data-payload", 8 + data_len, s)
        }
    };
    Ok(Instruction::new(offset as u32, len.min(u32::MAX as u64) as u32, 0, name, operands))
}

/// Linear-sweep decoder: decodes all instructions in `data` (bytecode only, no size limit).
/// Stops at first error or when buffer is exhausted.
pub fn decode_all(data: &[u8], start_offset: usize) -> Result<Vec<Instruction>, DexError> {
    decode_all_with_resolver(data, start_offset, &NoResolver)
}

/// Like [`decode_all`] but uses `resolver` to resolve string/type/field/method indices.
pub fn decode_all_with_resolver<R: ResolveRef>(
    data: &[u8],
    start_offset: usize,
    resolver: &R,
) -> Result<Vec<Instruction>, DexError> {
    // Don't preallocate from the (untrusted) code length: one Instruction is
    // ~56 bytes, so a crafted 100 MiB method would reserve ~2.8 GiB up front.
    let mut out = Vec::new();
    let mut offset = start_offset;
    while offset < data.len() {
        let ins = decode_one_with_resolver(data, offset, resolver).map_err(|mut e| {
            e.offset = Some(offset);
            e
        })?;
        let len = ins.length() as usize;
        out.push(ins);
        offset += len;
    }
    Ok(out)
}

/// Dummy resolver used when no external resolver is provided (always falls back to `kind@index`).
struct NoResolver;

impl ResolveRef for NoResolver {
    fn resolve(&self, _kind: RefKind, _index: u32) -> Option<String> {
        None
    }
}

/// Iterator over decoded instructions (stops on first error).
pub struct Decoder<'a> {
    data: &'a [u8],
    offset: usize,
    size_16bit_units: Option<usize>, // if set, max byte = size_16bit_units * 2
}

impl<'a> Decoder<'a> {
    /// Decode from raw bytecode. `data` is the instruction bytes; decoding runs until buffer end
    /// or (if `size_16bit_units` is given) until `size_16bit_units * 2` bytes are consumed.
    pub fn new(data: &'a [u8], start_offset: usize, size_16bit_units: Option<usize>) -> Self {
        Self {
            data,
            offset: start_offset,
            size_16bit_units,
        }
    }

    /// Decode from bytecode with no size limit (use full buffer).
    pub fn with_ip(data: &'a [u8], ip: u64, _options: u32) -> Result<Self, DexError> {
        Ok(Self {
            data,
            offset: ip as usize,
            size_16bit_units: None,
        })
    }

    #[inline]
    pub const fn ip(&self) -> u64 {
        self.offset as u64
    }
}

impl<'a> Iterator for Decoder<'a> {
    type Item = Result<Instruction, DexError>;

    fn next(&mut self) -> Option<Self::Item> {
        let max = self
            .size_16bit_units
            .map(|s| s * 2)
            .unwrap_or(self.data.len());
        if self.offset >= max || self.offset >= self.data.len() {
            return None;
        }
        match decode_one(self.data, self.offset) {
            Ok(ins) => {
                self.offset += ins.length() as usize;
                Some(Ok(ins))
            }
            Err(e) => Some(Err(e)),
        }
    }
}
