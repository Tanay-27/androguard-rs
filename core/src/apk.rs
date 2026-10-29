//! Reading the DEX files out of an APK, as androguard 4.1.3's `AnalyzeAPK`
//! does: `APK.get_all_dex()`, i.e. `get_file(name)` for each name in
//! `get_dex_names()`, which is `get_files()` (apkInspector's `namelist()`:
//! central directory order, a repeated name at its first position) filtered
//! by `re.match(r"^classes(\d*).dex$", name)`. Entries are read with
//! `zipapk`, the apkInspector-compatible reader, so a DEX's bytes are what
//! `get_file()` returns, tampered zips included. The DEX order matters: a
//! class defined in several DEX files is the last one loaded (androguard's
//! `Analysis.add()` overwrites), and `get_classes()` follows load order.

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use rayon::prelude::*;

use crate::dex::Dex;
use crate::py_decimal::DECIMAL;
use crate::zipapk::{ApkZip, MemSource, ReadError};

/// Largest single DEX we'll read. Real ones are tens of MiB; the cap only
/// exists so a crafted APK can't exhaust memory.
pub const MAX_DEX_BYTES: u64 = 256 << 20;
/// Largest total of all DEX files in one APK.
pub const MAX_TOTAL_DEX_BYTES: u64 = 2 << 30;

/// Python `re`'s `\d` on a str pattern: a Unicode decimal digit.
fn py_decimal(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_digit();
    }
    let cp = c as u32;
    DECIMAL
        .binary_search_by(|&(lo, hi)| {
            if hi < cp {
                std::cmp::Ordering::Less
            } else if lo > cp {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// `re.match(r"^classes(\d*).dex$", name)` (androguard's
/// `get_dex_names()` filter): "classes", then any decimal digits, then any
/// one character but a newline (the `.` is unescaped), then "dex", at the
/// end or before a final newline.
pub fn is_dex_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("classes") else { return false };
    let Some(mid) = rest.strip_suffix("dex\n").or_else(|| rest.strip_suffix("dex")) else { return false };
    let mut chars = mid.chars();
    match chars.next_back() {
        Some(c) if c != '\n' => chars.all(py_decimal),
        _ => false,
    }
}

/// `get_dex_names()`: the matching names, in `get_files()` order.
pub fn dex_names(zip: &ApkZip<'_>) -> Vec<String> {
    zip.names().iter().filter(|n| is_dex_name(n)).cloned().collect()
}

/// `get_dex_names()` of the APK at `apk`.
pub fn dex_entries(apk: &str) -> Result<Vec<String>> {
    Ok(dex_names(&ApkZip::open_path(apk)?))
}

/// `get_dex_names()` of an APK held in memory.
pub fn dex_entries_bytes(apk: &[u8]) -> Result<Vec<String>> {
    Ok(dex_names(&ApkZip::open(Box::new(MemSource(apk)))?))
}

/// The named entries of the APK at `apk`, in the order given.
pub fn load(apk: &str, entries: &[String]) -> Result<Vec<Dex>> {
    Ok(load_zip(&ApkZip::open_path(apk)?, entries, false)?.0)
}

/// Every DEX of an APK held in memory, in `get_all_dex()` order.
pub fn load_bytes(apk: &[u8]) -> Result<Vec<Dex>> {
    Ok(load_bytes_tolerant(apk, false)?.dexes)
}

/// What `load_tolerant()` read: every selected name (`get_dex_names()`),
/// the DEX files parsed, in that order, and those left out.
pub struct Loaded {
    pub names: Vec<String>,
    pub dexes: Vec<Dex>,
    pub skipped: Vec<SkippedDex>,
    /// Position in `names` of each of `dexes`.
    pub positions: Vec<usize>,
    /// Under `HeaderMode::Record`: what androguard 4.1.3's `AnalyzeAPK`
    /// raises for this APK (the first DEX, in load order, that `DEX()` or
    /// `Analysis.add()` fails on, else what `create_xref()` raises), if
    /// anything.
    pub load_error: Option<crate::agload::AgErr>,
}

/// A DEX file left out of the index, and androguard's error for it.
#[derive(Clone, Debug)]
pub struct SkippedDex {
    pub name: String,
    pub message: String,
    /// Position in `get_dex_names()`.
    pub pos: usize,
    /// androguard raises NotImplementedError (else ValueError).
    pub not_implemented: bool,
}

/// Python frames androguard may go deeper than `DEX.__init__` before
/// RecursionError, when the caller doesn't say (the recursion limit, 1000,
/// minus a typical call depth).
pub const DEFAULT_MAX_DEPTH: i64 = 970;

/// C recursion units left at androguard's `DEX.__init__` when the caller
/// doesn't say (CPython 3.12's limit, measured at shallow depth).
pub const DEFAULT_C_BUDGET: i64 = 6650;


/// What to do with a DEX that androguard's `DEX()` header checks reject.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HeaderMode {
    /// Fail the APK on "Header too small" / wrong or byte-swapped endian
    /// tag (the checks the loader has always made); later header checks
    /// aren't made.
    Strict,
    /// As `Strict`, but leave out a DEX with "Header too small" or "Wrong
    /// endian tag", as callers that skip a DEX `DEX()` rejects with those see it.
    Tolerant,
    /// Make every `HeaderItem` check androguard 4.1.3 makes, and leave out
    /// (recording the error) any DEX that fails one, so the caller can
    /// raise androguard's exception in androguard's order.
    Record,
}

/// One of androguard 4.1.3's `HeaderItem` errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderError {
    /// "Header too small" or "Wrong endian tag": what `Tolerant` skips.
    pub skippable: bool,
    /// NotImplementedError (byte-swapped tag), else ValueError.
    pub not_implemented: bool,
    pub message: String,
}

/// zlib.adler32
pub(crate) fn adler32(b: &[u8]) -> u32 {
    let (mut a, mut s) = (1u32, 0u32);
    for chunk in b.chunks(5552) {
        for &c in chunk {
            a += c as u32;
            s += a;
        }
        a %= 65521;
        s %= 65521;
    }
    (s << 16) | a
}

/// Every check androguard 4.1.3's `HeaderItem` makes, in its order:
/// the size, the endian tag (byte-swapped is NotImplementedError), the
/// magic ("dex"/"dey", a newline, a NUL at 7), the Adler-32 checksum of
/// everything after it, header_size, and the type_ids/proto_ids counts.
/// With `full` false only the first two (what the loader always checked).
pub fn androguard_header_check(data: &[u8], full: bool) -> Option<HeaderError> {
    let value = |skippable, message: String| Some(HeaderError { skippable, not_implemented: false, message });
    if data.len() < 0x70 {
        return value(true, "Not a DEX file, Header too small.".to_string());
    }
    let u32_at = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
    match u32_at(40) {
        0x1234_5678 => {}
        0x7856_3412 => {
            return Some(HeaderError {
                skippable: false,
                not_implemented: true,
                message: "Byte swapped endian tag encountered!".to_string(),
            });
        }
        t => return value(true, format!("This is not a DEX file! Wrong endian tag: '0x{t:08x}'")),
    }
    if !full {
        return None;
    }
    let magic = &data[..8];
    if &magic[..2] != b"de" || !matches!(magic[2], 0x78 | 0x79) || magic[3] != 0x0a || magic[7] != 0 {
        return value(false, format!("This is not a DEX file! Wrong magic: {}", crate::render::py_bytes_repr(magic)));
    }
    if adler32(&data[12..]) != u32_at(8) {
        return value(false, "Wrong Adler32 checksum for DEX file!".to_string());
    }
    let header_size = u32_at(36);
    if header_size != 0x70 {
        return value(false, format!("This is not a DEX file! Wrong header size: '{header_size}'"));
    }
    let type_ids = u32_at(64);
    if type_ids > 65535 {
        return value(false, format!("DEX file contains too many ({type_ids}) TYPE_IDs to be valid!"));
    }
    let proto_ids = u32_at(72);
    if proto_ids > 65535 {
        return value(false, format!("DEX file contains too many ({proto_ids}) PROTO_IDs to be valid!"));
    }
    None
}

/// Every DEX of the APK at `apk`, in `get_all_dex()` order. With
/// `tolerant`, a DEX androguard's `DEX()` rejects with "Not a DEX file,
/// Header too small." or "This is not a DEX file! Wrong endian tag: ..."
/// (a ValueError a caller looping over `get_all_dex()` can catch and skip) is
/// left out instead of failing the APK. Any other error still fails it, and
/// so do a missing entry (androguard's `FileNotPresent`) and the size caps.
pub fn load_tolerant(apk: &str, tolerant: bool) -> Result<Loaded> {
    load_mode(apk, if tolerant { HeaderMode::Tolerant } else { HeaderMode::Strict })
}

/// `load_tolerant()` for an APK held in memory (not copied).
pub fn load_bytes_tolerant(apk: &[u8], tolerant: bool) -> Result<Loaded> {
    load_bytes_mode(apk, if tolerant { HeaderMode::Tolerant } else { HeaderMode::Strict })
}

/// Every DEX of the APK at `apk`, header errors handled as `mode` says.
pub fn load_mode(apk: &str, mode: HeaderMode) -> Result<Loaded> {
    load_all(&ApkZip::open_path(apk)?, mode, (DEFAULT_MAX_DEPTH, DEFAULT_C_BUDGET))
}

/// `load_mode()`; under `HeaderMode::Record`, `max_depth` is how many
/// Python frames androguard's `DEX()` may go deeper than its own frame and
/// how many C recursion units are left there (`agload::load`).
pub fn load_mode_depth(apk: &str, mode: HeaderMode, max_depth: (i64, i64)) -> Result<Loaded> {
    load_all(&ApkZip::open_path(apk)?, mode, max_depth)
}

/// `load_mode_depth()` for an APK held in memory (not copied).
pub fn load_bytes_mode_depth(apk: &[u8], mode: HeaderMode, max_depth: (i64, i64)) -> Result<Loaded> {
    load_all(&ApkZip::open(Box::new(MemSource(apk)))?, mode, max_depth)
}

/// `load_mode()` for an APK held in memory (not copied).
pub fn load_bytes_mode(apk: &[u8], mode: HeaderMode) -> Result<Loaded> {
    load_all(&ApkZip::open(Box::new(MemSource(apk)))?, mode, (DEFAULT_MAX_DEPTH, DEFAULT_C_BUDGET))
}

fn load_all(zip: &ApkZip<'_>, mode: HeaderMode, max_depth: (i64, i64)) -> Result<Loaded> {
    let names = dex_names(zip);
    let (dexes, skipped, positions, load_error) = load_zip_inner(zip, &names, mode, max_depth)?;
    Ok(Loaded { names, dexes, skipped, positions, load_error })
}

/// androguard's first two `DEX()` header checks (`HeaderItem`): the error
/// message, or `None` if they pass. The byte-swapped tag is androguard's
/// `NotImplementedError`, not the ValueError `Tolerant` skips.
pub fn androguard_header_error(data: &[u8]) -> Option<(bool, String)> {
    androguard_header_check(data, false).map(|e| (e.skippable, e.message))
}

/// Read and parse `entries` of `zip` in parallel, keeping their order.
///
/// The APK is untrusted, so every read is bounded: an entry may not produce
/// more than MAX_DEX_BYTES (checked while inflating, whatever it declares),
/// nor more than what is left of MAX_TOTAL_DEX_BYTES when its read starts,
/// and the running total is checked after each read. Peak memory is thus
/// at most MAX_TOTAL_DEX_BYTES plus one entry per rayon thread.
pub fn load_zip(zip: &ApkZip<'_>, entries: &[String], tolerant: bool) -> Result<(Vec<Dex>, Vec<SkippedDex>)> {
    let mode = if tolerant { HeaderMode::Tolerant } else { HeaderMode::Strict };
    load_zip_mode(zip, entries, mode).map(|(d, s, _)| (d, s))
}

/// `load_zip()` with header errors handled as `mode` says; also gives each
/// loaded DEX's position in `entries`.
pub fn load_zip_mode(
    zip: &ApkZip<'_>,
    entries: &[String],
    mode: HeaderMode,
) -> Result<(Vec<Dex>, Vec<SkippedDex>, Vec<usize>)> {
    load_zip_inner(zip, entries, mode, (DEFAULT_MAX_DEPTH, DEFAULT_C_BUDGET)).map(|(d, s, p, _)| (d, s, p))
}

type Inner = (Vec<Dex>, Vec<SkippedDex>, Vec<usize>, Option<crate::agload::AgErr>);

fn load_zip_inner(zip: &ApkZip<'_>, entries: &[String], mode: HeaderMode, max_depth: (i64, i64)) -> Result<Inner> {
    use crate::agload::{self, AgErr};
    let used = AtomicU64::new(0);
    // Ok(Ok((dex, add error, create_xref error))) or Ok(Err((left out, its DEX() error))).
    type One = std::result::Result<(Dex, Option<AgErr>, Option<AgErr>), (SkippedDex, Option<AgErr>)>;
    let loaded: Vec<One> = entries
        .par_iter()
        .enumerate()
        .map(|(pos, name)| {
            let budget = MAX_TOTAL_DEX_BYTES.saturating_sub(used.load(Ordering::Relaxed));
            let buf = match zip.read_capped(name, budget.min(MAX_DEX_BYTES)) {
                Ok(b) => b,
                Err(ReadError::NotPresent) => bail!("{name}: not present (androguard: FileNotPresent)"),
                Err(ReadError::Failed(e)) => return Err(e.context(format!("reading {name}"))),
            };
            let total = used.fetch_add(buf.len() as u64, Ordering::Relaxed) + buf.len() as u64;
            if total > MAX_TOTAL_DEX_BYTES {
                bail!("DEX files total over the {MAX_TOTAL_DEX_BYTES}-byte limit");
            }
            if mode == HeaderMode::Record {
                // Every check androguard's DEX() makes, then Analysis.add()'s
                // and create_xref()'s.
                let st = match agload::load(&buf, max_depth.0, max_depth.1) {
                    Ok(st) => st,
                    Err(e) => {
                        let (message, not_implemented) = match &e {
                            AgErr::Header { message, not_implemented } => (message.clone(), *not_implemented),
                            other => (format!("{other:?}"), false),
                        };
                        return Ok(Err((SkippedDex { name: name.clone(), message, pos, not_implemented }, Some(e))));
                    }
                };
                if st.no_map {
                    // Analysis.add() fails on it; nothing to index.
                    let e = agload::add_error_no_map();
                    let s = SkippedDex { name: name.clone(), message: format!("{e:?}"), pos, not_implemented: false };
                    return Ok(Err((s, Some(e))));
                }
                let dex = Dex::parse(buf).with_context(|| format!("parsing {name}"))?;
                let add = agload::add_error(&st, &dex);
                let xref = if add.is_none() { agload::xref_error(&st, &dex) } else { None };
                return Ok(Ok((dex, add, xref)));
            }
            if let Some(e) = androguard_header_check(&buf, false) {
                if mode == HeaderMode::Tolerant && e.skippable {
                    return Ok(Err((SkippedDex { name: name.clone(), message: e.message, pos, not_implemented: e.not_implemented }, None)));
                }
                bail!("parsing {name}: {}", e.message);
            }
            Ok(Ok((Dex::parse(buf).with_context(|| format!("parsing {name}"))?, None, None)))
        })
        .collect::<Result<_>>()?;
    let mut dexes = Vec::new();
    let mut skipped = Vec::new();
    let mut positions = Vec::new();
    // androguard: DEX() then add() for each file in turn, create_xref() at
    // the end.
    let mut first: Option<AgErr> = None;
    let mut xref: Option<AgErr> = None;
    for (pos, r) in loaded.into_iter().enumerate() {
        match r {
            Ok((d, add, x)) => {
                dexes.push(d);
                positions.push(pos);
                if first.is_none() {
                    first = add;
                }
                if xref.is_none() {
                    xref = x;
                }
            }
            Err((s, e)) => {
                if first.is_none() {
                    first = e;
                }
                skipped.push(s);
            }
        }
    }
    Ok((dexes, skipped, positions, first.or(xref)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zipapk::tests::zip_of;

    #[test]
    fn dex_name_filter_is_androguards_regex() {
        // re.match(r"^classes(\d*).dex$", name), checked against Python.
        for n in [
            "classes.dex",
            "classes2.dex",
            "classes10.dex",
            "classes1.dex",
            "classesXdex",
            "classes1dex",
            "classes3odex",
            "classes2.dex\n",
            "classes\u{663}.dex",
            "classes\u{663}\u{664}Xdex\n",
            "classes0.dex",
        ] {
            assert!(is_dex_name(n), "{n:?}");
        }
        for n in [
            "classes.dex.bak",
            "sub/classes4.dex",
            "Classes5.dex",
            "classes-1.dex",
            "classes6.dex\n\n",
            "classes7.dex\nx",
            "classesdex",
            "classes\ndex",
            "classes",
            "classes.de",
            "classes\u{b2}.dex", // superscript two: a digit, not decimal
            "xclasses.dex",
        ] {
            assert!(!is_dex_name(n), "{n:?}");
        }
    }

    #[test]
    fn order_is_central_directory_order() {
        let short = b"dex\n035\0".as_slice();
        let z = zip_of(
            &[
                ("classes10.dex", 0, short),
                ("AndroidManifest.xml", 0, b"x"),
                ("classes2.dex", 8, short),
                ("classes.dex", 0, short),
                ("classesXdex", 0, short),
                ("classes2.dex", 0, short),
            ],
            b"",
        );
        assert_eq!(dex_entries_bytes(&z).unwrap(), ["classes10.dex", "classes2.dex", "classes.dex", "classesXdex"]);
        let l = load_bytes_tolerant(&z, true).unwrap();
        assert!(l.dexes.is_empty());
        assert_eq!(l.names, ["classes10.dex", "classes2.dex", "classes.dex", "classesXdex"]);
        let names: Vec<_> = l.skipped.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, l.names);
        assert!(l.skipped.iter().all(|s| s.message == "Not a DEX file, Header too small."));
        // Not tolerant: the first one fails the APK.
        assert!(load_bytes(&z).is_err());
    }

    #[test]
    fn missing_local_header_fails_even_when_tolerant() {
        let mut z = zip_of(&[("classes.dex", 0, b"dex\n035\0".as_slice())], b"");
        z[0] = b'Q'; // local header signature
        let e = load_bytes_tolerant(&z, true).err().unwrap();
        assert!(e.to_string().contains("not present"), "{e}");
    }

    #[test]
    fn total_cap_counts_what_was_read() {
        // Each entry is within the per-entry cap; the budget left for later
        // reads shrinks with what earlier ones produced.
        let zip = ApkZip::open(Box::new(MemSource(zip_of(&[("classes.dex", 0, &[0u8; 200])], b"")))).unwrap();
        assert!(zip.read_capped("classes.dex", 100).is_err());
        assert_eq!(zip.read_capped("classes.dex", 200).unwrap().len(), 200);
    }
}
