//! Render DEX references exactly as androguard 4.1.3's `get_kind()` does, so
//! instruction text matches `Instruction.get_output()` byte for byte.
//!
//! Lone UTF-16 surrogates (legal in DEX strings, illegal in a Rust `String`)
//! are carried through as private-use chars U+10F000 + (s - 0xD800); see
//! `escape_line`, which prints them the way Python's `backslashreplace` does.

use dex_bytecode::{RefKind, ResolveRef};

use crate::dex::{Dex, u16_at, u32_at};

const SURROGATE_BASE: u32 = 0x10F000;

/// MUTF-8 decode with the exact semantics of `mutf8` 1.1.0's C extension,
/// which androguard uses for DEX strings (androguard doesn't pin mutf8, so
/// installs get the latest; 1.0.6 decodes planes >= 2 wrongly).
///
/// - Fast path: with no 0xED, 0xC0 or 0x00 byte, strict UTF-8 is tried first
///   (CPython's and Rust's strict decoders accept the same inputs).
/// - Otherwise, or if that fails, a byte loop: 2- and 3-byte forms decode
///   without checking continuation bytes; a surrogate pair written as two
///   3-byte forms joins into one code point; lone surrogates are kept; any
///   other byte >= 0x80 (including 4-byte UTF-8 leads) passes through as
///   U+0080..U+00FF. A 2/3-byte form cut short is an error (None).
pub fn mutf8_decode(s: &[u8]) -> Option<String> {
    if !s.iter().any(|&b| b == 0xED || b == 0xC0 || b == 0x00) {
        if let Ok(utf8) = std::str::from_utf8(s) {
            return Some(utf8.to_owned());
        }
    }
    let mut out = String::with_capacity(s.len());
    let push = |out: &mut String, cp: u32| match cp {
        0xD800..=0xDFFF => out.push(char::from_u32(SURROGATE_BASE + cp - 0xD800).unwrap()),
        _ => out.push(char::from_u32(cp).unwrap_or('\u{FFFD}')),
    };
    let mut i = 0;
    while i < s.len() {
        let x = s[i] as u32;
        if x == 0 {
            return None;
        } else if x < 0x80 {
            out.push(x as u8 as char);
        } else if x & 0xE0 == 0xC0 {
            let b2 = *s.get(i + 1)? as u32;
            push(&mut out, (x & 0x1F) << 6 | (b2 & 0x3F));
            i += 1;
        } else if x & 0xF0 == 0xE0 {
            if i + 2 >= s.len() {
                return None;
            }
            let (b2, b3) = (s[i + 1] as u32, s[i + 2] as u32);
            if x == 0xED && b2 & 0xF0 == 0xA0 && i + 5 < s.len() && s[i + 3] == 0xED && s[i + 4] & 0xF0 == 0xB0 {
                let (b5, b6) = (s[i + 4] as u32, s[i + 5] as u32);
                push(&mut out, 0x10000 + ((b2 & 0x0F) << 16 | (b3 & 0x3F) << 10 | (b5 & 0x0F) << 6 | (b6 & 0x3F)));
                i += 6;
                continue;
            }
            push(&mut out, (x & 0x0F) << 12 | (b2 & 0x3F) << 6 | (b3 & 0x3F));
            i += 2;
        } else {
            push(&mut out, x);
        }
        i += 1;
    }
    Some(out)
}

/// Python's `repr(bytes)`.
pub fn py_bytes_repr(b: &[u8]) -> String {
    let quote = if b.contains(&b'\'') && !b.contains(&b'"') { '"' } else { '\'' };
    let mut s = String::with_capacity(b.len() + 3);
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
            _ => s.push_str(&format!("\\x{c:02x}")),
        }
    }
    s.push(quote);
    s
}

/// Escape one dump field so a line can hold any instruction text: `\`, LF, CR
/// and TAB are backslash-escaped, and carried lone surrogates print as
/// `\udXXX`, the same as the Python side's `backslashreplace`.
pub fn escape_field(s: &str, out: &mut String) {
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (SURROGATE_BASE..SURROGATE_BASE + 0x800).contains(&(c as u32)) => {
                out.push_str(&format!("\\u{:04x}", c as u32 - SURROGATE_BASE + 0xD800));
            }
            c => out.push(c),
        }
    }
}

/// `s` as Python's `str.encode("utf-8", "surrogatepass")` gives it: carried
/// lone surrogates (see above) back as their 3-byte forms.
pub fn wtf8(s: &str) -> std::borrow::Cow<'_, [u8]> {
    let carried = |c: char| (SURROGATE_BASE..SURROGATE_BASE + 0x800).contains(&(c as u32));
    if !s.chars().any(carried) {
        return std::borrow::Cow::Borrowed(s.as_bytes());
    }
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        if carried(c) {
            let sur = c as u32 - SURROGATE_BASE + 0xD800;
            out.extend_from_slice(&[0xE0 | (sur >> 12) as u8, 0x80 | ((sur >> 6) & 0x3F) as u8, 0x80 | (sur & 0x3F) as u8]);
        } else {
            out.extend_from_slice(c.encode_utf8(&mut [0u8; 4]).as_bytes());
        }
    }
    std::borrow::Cow::Owned(out)
}

/// const-string/jumbo's index `idx` as androguard 4.1.3 resolves it in a
/// table of `n` strings: a signed int used as a Python list index, so a
/// negative one counts from the end; out of range either way stays out of
/// range (and resolves to "AG:IS: invalid string").
pub fn signed_string_index(idx: u32, n: usize) -> u32 {
    let n = n as i64;
    match idx as i32 as i64 {
        neg if neg < 0 && n + neg >= 0 => (n + neg) as u32,
        _ => idx,
    }
}

pub struct AgResolver<'a> {
    pub dex: &'a Dex,
}

impl AgResolver<'_> {
    pub fn string(&self, idx: u32) -> String {
        match self.dex.string(idx) {
            Ok(raw) => mutf8_decode(raw)
                .unwrap_or_else(|| format!("ANDROGUARD[INVALID_STRING] {}", py_bytes_repr(raw))),
            Err(_) => "AG:IS: invalid string".into(),
        }
    }

    /// const-string/jumbo's index as androguard 4.1.3 reads it: a signed
    /// int (Instruction31c unpacks "BBi"), used as a Python list index, so
    /// 0xFFFFFFFF is the last string. (const-string's is 16-bit, never
    /// negative.) Out of range either way stays out of range.
    fn signed_string_index(&self, idx: u32) -> u32 {
        signed_string_index(idx, self.dex.string_count())
    }

    pub fn type_name(&self, idx: u32) -> String {
        match self.dex.type_string_idx(idx) {
            Some(s) => self.string(s),
            None => "AG:ITI: invalid type".into(),
        }
    }

    pub fn method(&self, idx: u32) -> String {
        let Ok((class_idx, proto_idx, name_idx)) = self.dex.method_id(idx) else {
            return "AG:IMI:invalid_class_name;->AG:IMI:invalid_name(AG:IMI:invalid_descriptor)".into();
        };
        format!("{}->{}{}", self.type_name(class_idx), self.string(name_idx), self.proto(proto_idx))
    }

    /// EncodedMethod's `get_name()` and `get_descriptor()` ("(P1 P2)R"),
    /// with androguard's placeholders for a bad method id.
    pub fn method_name_and_desc(&self, idx: u32) -> (String, String) {
        match self.dex.method_id(idx) {
            Ok((_, proto_idx, name_idx)) => (self.string(name_idx), self.proto(proto_idx)),
            Err(_) => ("AG:IMI:invalid_name".into(), "()AG:IMI:invalid_proto".into()),
        }
    }

    /// `Lcls;->name(P1P2)R` — the method key both parity dumps use (no
    /// descriptor spaces, names MUTF-8 decoded like androguard's).
    pub fn method_key(&self, idx: u32) -> String {
        let Ok((class_idx, proto_idx, name_idx)) = self.dex.method_id(idx) else {
            return String::from("?");
        };
        format!("{}->{}{}", self.type_name(class_idx), self.string(name_idx), self.proto_with(proto_idx, ""))
    }

    /// androguard's MethodIdItem.get_descriptor(): "(P1 P2)R", space-separated.
    fn proto(&self, proto_idx: u32) -> String {
        self.proto_with(proto_idx, " ")
    }

    fn proto_with(&self, proto_idx: u32, sep: &str) -> String {
        match self.dex.proto(proto_idx) {
            Some((ret, params)) => {
                let params: Vec<String> = params.into_iter().map(|t| self.type_name(t)).collect();
                format!("({}){}", params.join(sep), self.type_name(ret))
            }
            None => "AG:IPI:invalid_params;(AG:IPI:invalid_return_type)".into(),
        }
    }

    pub fn field(&self, idx: u32) -> String {
        match self.dex.field_id(idx) {
            Some((class_idx, type_idx, name_idx)) => format!(
                "{}->{} {}",
                self.type_name(class_idx),
                self.string(name_idx),
                self.type_name(type_idx)
            ),
            None => "AG:IFI:invalid_class_name;->AG:IFI:invalid_name (AG:IFI:invalid_type)".into(),
        }
    }
}

impl ResolveRef for AgResolver<'_> {
    fn resolve(&self, kind: RefKind, index: u32) -> Option<String> {
        Some(match kind {
            RefKind::String => self.string(self.signed_string_index(index)),
            RefKind::Type => self.type_name(index),
            RefKind::Field => self.field(index),
            RefKind::Method => self.method(index),
            // androguard 4.1.3's get_kind() has no branch for these and returns None.
            _ => "None".into(),
        })
    }
}

// Raw accessors the resolver needs beyond what the index uses.
impl Dex {
    pub fn type_string_idx(&self, idx: u32) -> Option<u32> {
        let (off, size) = self.table_type_ids();
        if idx as usize >= size {
            return None;
        }
        u32_at(&self.data, off + 4 * idx as usize).ok()
    }

    /// (return type idx, param type idxs) of proto_ids[idx].
    pub fn proto(&self, idx: u32) -> Option<(u32, Vec<u32>)> {
        let (off, size) = self.table_proto_ids();
        if idx as usize >= size {
            return None;
        }
        let o = off + 12 * idx as usize;
        let ret = u32_at(&self.data, o + 4).ok()?;
        // An undeclared parameters type_list: androguard raises KeyError.
        let params = self.type_list(u32_at(&self.data, o + 8).ok()?).ok()?;
        Some((ret, params))
    }

    /// (class_idx, type_idx, name_idx) of field_ids[idx].
    pub fn field_id(&self, idx: u32) -> Option<(u32, u32, u32)> {
        let (off, size) = self.table_field_ids();
        if idx as usize >= size {
            return None;
        }
        let o = off + 8 * idx as usize;
        Some((
            u16_at(&self.data, o).ok()? as u32,
            u16_at(&self.data, o + 2).ok()? as u32,
            u32_at(&self.data, o + 4).ok()?,
        ))
    }
}

/// androguard 4.1.3's LinearSweepAlgorithm re-raises any inner error as
/// `InvalidInstruction(TEMPLATE, idx, inner)`; these are those three args.
pub const INVALID_INSTRUCTION_TEMPLATE: &str =
    "Invalid instruction encountered! Stop parsing bytecode at idx %s. Message: %s";

/// `str()` of that exception. With three args, Python's str() is
/// the tuple's repr, so the inner exception shows as its repr.
pub fn invalid_instruction_str(e: &dex_bytecode::DexError) -> String {
    format!(
        "({}, {}, InvalidInstruction({}))",
        crate::classes::py_str_repr(INVALID_INSTRUCTION_TEMPLATE),
        e.offset.unwrap_or(0),
        crate::classes::py_str_repr(e.message())
    )
}

/// Python's `str.lower()`, exactly: CPython's algorithm over tables
/// generated from that Python (`py_lower_tables.rs`). Rust's own
/// `to_lowercase` uses a newer Unicode and lower-cases characters Python
/// 3.12 leaves alone. python/tests/test_text.py checks every code point.
pub fn py_lower(s: &str) -> String {
    use crate::py_lower_tables::LOWER;
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    for (i, &c) in chars.iter().enumerate() {
        if c == '\u{3A3}' {
            out.push(if final_sigma(&chars, i) { '\u{3C2}' } else { '\u{3C3}' });
            continue;
        }
        match LOWER.binary_search_by_key(&(c as u32), |&(k, _)| k) {
            Ok(j) => out.push_str(LOWER[j].1),
            Err(_) => out.push(c),
        }
    }
    out
}

fn in_ranges(table: &[(u32, u32)], c: char) -> bool {
    let cp = c as u32;
    table
        .binary_search_by(|&(a, b)| {
            if b < cp {
                std::cmp::Ordering::Less
            } else if a > cp {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// CPython's handle_capital_sigma: U+03A3 lowers to final sigma when
/// \p{cased}\p{case-ignorable}* precedes it and \p{case-ignorable}*\p{cased}
/// doesn't follow it.
fn final_sigma(chars: &[char], i: usize) -> bool {
    use crate::py_lower_tables::{CASED, IGNORABLE};
    let Some(&before) = chars[..i].iter().rev().find(|&&c| !in_ranges(&IGNORABLE, c)) else {
        return false;
    };
    if !in_ranges(&CASED, before) {
        return false;
    }
    match chars[i + 1..].iter().find(|&&c| !in_ranges(&IGNORABLE, c)) {
        Some(&after) => !in_ranges(&CASED, after),
        None => true,
    }
}
