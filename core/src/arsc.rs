//! `resources.arsc`, read the way androguard 4.1.3's `ARSCParser` reads it,
//! for its query methods: `get_packages_names()`,
//! `get_public_resources()`, `get_resolved_strings()`,
//! `get_resolved_res_configs()` and `get_resource_xml_name()`.
//!
//! androguard builds a Python object per chunk, entry and value (about
//! 650 MiB for a 28 MB table). Here the table bytes stay as they are, each
//! entry is a 24-byte record, and strings are decoded only when a query
//! returns them.
//!
//! Parity is with androguard's quirks as well as its results, including
//! where it fails: a short read is an error (`struct.error`), an offset past
//! the end reads nothing, and an error in `_analyse()` aborts the first query
//! but leaves what it had collected for later ones (`Arsc::analysis_error`).
//!
//! The file is untrusted. Every read is bounds-checked, nothing is
//! preallocated from a declared count, complex entries shared by many offsets
//! are parsed once, and queries have output, decoding and reference-chasing
//! budgets (see `MAX_*`), past which they fail instead of running away.
//!
//! androguard 4.1.4 changed five things here; each is confined to one spot
//! marked "4.1.4:" so that version's behaviour is a local change:
//! sparse entries (`entry_offsets`), compact entries' key/value fields
//! (`Ate::key_index`/`Ate::compact_value_index`), unterminated UTF-8 strings
//! (`Pool::locate`), the type chunk's reserved field (`parse_type_chunk`) and
//! chunk-header scanning (`Header::read`).

use std::collections::HashMap;
use std::ops::Range;
use std::sync::OnceLock;

use anyhow::{Result, anyhow, bail};

use crate::zipapk::{ApkZip, MemSource, ReadError};

/// Largest `resources.arsc` `from_apk*` will decompress (real ones are tens
/// of MiB).
pub const MAX_ARSC_BYTES: u64 = 256 << 20;
/// Largest `get_public_resources()` document. Real ones are a few MiB; without a tight cap a ~2 MB crafted table, where every
/// entry names one huge key, makes us build hundreds of MiB before failing.
pub const MAX_XML_BYTES: usize = 64 << 20;
/// Most string bytes one query may decode (each distinct string counts once).
pub const MAX_DECODED_BYTES: usize = 256 << 20;
/// Most work one `get_resolved_res_configs()` call may do.
/// (Each value and each reference followed counts as one step.)
pub const MAX_RESOLVE_STEPS: usize = 1 << 20;
/// Deepest chain of references `get_resolved_res_configs()` follows.
/// androguard recurses until Python's recursion limit (1000 frames, three
/// per reference), so a chain this long fails there too.
pub const MAX_REFERENCE_DEPTH: usize = 300;

const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_TABLE_TYPE: u16 = 0x0002;
const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
const RES_TABLE_TYPE_TYPE: u16 = 0x0201;
const RES_TABLE_TYPE_SPEC_TYPE: u16 = 0x0202;

const FLAG_COMPLEX: u16 = 1;
const FLAG_WEAK: u16 = 4;
const FLAG_COMPACT: u16 = 8;
const FLAG_OFFSET16: u8 = 2;

const TYPE_REFERENCE: u8 = 0x01;
const TYPE_ATTRIBUTE: u8 = 0x02;
const TYPE_STRING: u8 = 0x03;
const TYPE_FLOAT: u8 = 0x04;
const TYPE_DIMENSION: u8 = 0x05;
const TYPE_FRACTION: u8 = 0x06;
const TYPE_FIRST_INT: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const TYPE_INT_BOOLEAN: u8 = 0x12;
const TYPE_FIRST_COLOR_INT: u8 = 0x1C;
const TYPE_LAST_INT: u8 = 0x1F;

const RADIX_MULTS: [f64; 4] = [0.00390625, 3.051758e-005, 1.192093e-007, 4.656613e-010];
const DIMENSION_UNITS: [&str; 6] = ["px", "dip", "sp", "pt", "in", "mm"];
const FRACTION_UNITS: [&str; 2] = ["%", "%p"];

/// androguard's name for the default locale.
pub const DEFAULT_LOCALE: &str = "\x00\x00";

/// A position in the table, as androguard's `BufferedReader` sees it: reads
/// past the end come back short, seeks past the end are allowed, and a
/// `struct.unpack` of a short read is an error.
pub(crate) struct Cur<'a> {
    pub(crate) b: &'a [u8],
    pub(crate) pos: u64,
}

impl<'a> Cur<'a> {
    pub(crate) fn len(&self) -> u64 {
        self.b.len() as u64
    }

    /// `read(n)` that must return all `n` bytes (it feeds `unpack`). A short
    /// read still consumes what was there.
    pub(crate) fn take(&mut self, n: u64) -> Result<&'a [u8]> {
        if self.pos.checked_add(n).is_some_and(|e| e <= self.len()) {
            let s = &self.b[self.pos as usize..(self.pos + n) as usize];
            self.pos += n;
            return Ok(s);
        }
        self.pos = self.pos.max(self.len());
        bail!("unpack requires a buffer of {n} bytes")
    }

    /// `read(n)` whose result may be short.
    pub(crate) fn take_lenient(&mut self, n: u64) -> Range<usize> {
        let start = self.pos.min(self.len());
        self.pos = if self.pos >= self.len() { self.pos } else { self.pos.saturating_add(n).min(self.len()) };
        start as usize..self.pos.min(self.len()) as usize
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
}

/// `ARSCHeader`: a `ResChunk_header`.
#[derive(Clone, Copy)]
pub(crate) struct Header {
    pub(crate) start: u64,
    pub(crate) ty: u16,
    pub(crate) header_size: u16,
    pub(crate) size: u32,
}

impl Header {
    /// 4.1.4: scans forward byte by byte past "dummy data" when the header
    /// sizes are inconsistent, instead of failing.
    pub(crate) fn read(cur: &mut Cur, expected: Option<u16>) -> Result<Header> {
        let start = cur.pos;
        if cur.len() < start.saturating_add(8) {
            bail!("Can not read over the buffer size! Offset={start}");
        }
        let (ty, header_size, size) = (cur.u16()?, cur.u16()?, cur.u32()?);
        if let Some(e) = expected {
            if ty != e {
                bail!("Header type is not equal the expected type: Got 0x{ty:04x}, wanted 0x{e:04x}");
            }
        }
        if header_size < 8 {
            bail!("declared header size is smaller than required size of 8! Offset={start}");
        }
        if size < 8 {
            bail!("declared chunk size is smaller than required size of 8! Offset={start}");
        }
        if size < header_size as u32 {
            bail!("declared chunk size ({size}) is smaller than header size ({header_size})! Offset={start}");
        }
        Ok(Header { start, ty, header_size, size })
    }

    pub(crate) fn end(&self) -> u64 {
        self.start + self.size as u64
    }
}

/// `StringBlock`, reduced to where its pieces are in the table.
pub(crate) struct Pool {
    utf8: bool,
    /// androguard's `stringCount`, recomputed from the strings offset; may be
    /// negative, in which case there are no strings.
    count: i64,
    /// Where the `count` u32 string offsets are.
    offsets_at: usize,
    /// `m_charbuff`.
    chars: Range<usize>,
}

/// Where a string's bytes are, or `None` for androguard's silent "".
pub(crate) type Located = Option<(bool, Range<usize>)>;

impl Pool {
    pub(crate) fn parse(cur: &mut Cur, h: &Header) -> Result<Pool> {
        let _string_count = cur.u32()?;
        let style_count = cur.u32()? as i64;
        let flags = cur.u32()?;
        let strings_offset = cur.u32()? as i64;
        let styles_offset = cur.u32()? as i64;
        // androguard trusts stringsOffset over stringCount:
        // int((stringsOffset - (styleCount * 4 + 28)) / 4), truncating.
        let count = (strings_offset - (style_count * 4 + 28)) / 4;
        let offsets_at = cur.pos.min(cur.len()) as usize;
        if count > 0 {
            cur.take(count as u64 * 4)?;
        }
        if style_count > 0 {
            cur.take(style_count as u64 * 4)?;
        }
        let has_styles = styles_offset != 0 && style_count != 0;
        let size = if has_styles { styles_offset - strings_offset } else { h.size as i64 - strings_offset };
        let chars = match size {
            -1 => cur.take_lenient(u64::MAX),
            s if s < 0 => bail!("read length must be non-negative or -1"),
            s => cur.take_lenient(s as u64),
        };
        if has_styles {
            let n = (h.size as i64 - styles_offset).div_euclid(4);
            if n > 0 {
                cur.take(n as u64 * 4)?;
            }
        }
        Ok(Pool { utf8: flags & 0x100 != 0, count, offsets_at, chars })
    }

    /// `getString(idx)` up to decoding: where the string is, or why
    /// androguard raises.
    pub(crate) fn locate(&self, b: &[u8], idx: i64) -> Result<Located> {
        if idx < 0 || self.count <= 0 || idx >= self.count {
            return Ok(None);
        }
        let at = self.offsets_at + idx as usize * 4;
        let offset = u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize;
        let cb = &b[self.chars.clone()];
        // _decode_length(): always unpacks two chars' worth of bytes.
        let length = |o: usize, w: usize| -> Result<(usize, usize)> {
            let s = cb.get(o..).and_then(|s| s.get(..2 * w)).ok_or_else(|| anyhow!("unpack requires a buffer of {} bytes", 2 * w))?;
            let (l1, l2) = if w == 1 { (s[0] as usize, s[1] as usize) } else { (u16::from_le_bytes([s[0], s[1]]) as usize, u16::from_le_bytes([s[2], s[3]]) as usize) };
            let high = 0x80 << (8 * (w - 1));
            Ok(if l1 & high != 0 { (((l1 & !high) << (8 * w)) | l2, 2 * w) } else { (l1, w) })
        };
        let start = self.chars.start;
        if self.utf8 {
            let (_chars, skip) = length(offset, 1)?;
            let o = offset + skip;
            let (n, skip) = length(o, 1)?;
            let o = o + skip;
            if cb.len() < o + n {
                return Ok(None);
            }
            // 4.1.4: an unterminated string is "" instead of an error.
            match cb.get(o + n) {
                None => bail!("index out of range"),
                Some(0) => {}
                Some(_) => bail!("UTF-8 String is not null terminated! At offset={o}"),
            }
            Ok(Some((true, start + o..start + o + n)))
        } else {
            let (units, skip) = length(offset, 2)?;
            let o = offset + skip;
            let n = units * 2;
            if cb.len() < o + n {
                return Ok(None);
            }
            if cb.get(o + n..o + n + 2) != Some(&[0, 0][..]) {
                bail!("UTF-16 String is not null terminated! At offset={o}");
            }
            Ok(Some((false, start + o..start + o + n)))
        }
    }

    /// Where the string's bytes start, as a cache key: two indices sharing
    /// an offset decode the same.
    pub(crate) fn offset_of(&self, b: &[u8], idx: i64) -> Option<u32> {
        if idx < 0 || self.count <= 0 || idx >= self.count {
            return None;
        }
        let at = self.offsets_at + idx as usize * 4;
        Some(u32::from_le_bytes(b[at..at + 4].try_into().unwrap()))
    }
}

/// `bytes.decode("utf-8", "replace")` / `bytes.decode("utf-16", "replace")`
/// (the latter honours a leading BOM and is otherwise little-endian).
pub fn py_decode(data: &[u8], utf8: bool) -> String {
    if utf8 {
        return String::from_utf8_lossy(data).into_owned();
    }
    let (be, body) = match data {
        [0xFF, 0xFE, rest @ ..] => (false, rest),
        [0xFE, 0xFF, rest @ ..] => (true, rest),
        _ => (false, data),
    };
    let units = body.chunks_exact(2).map(|c| if be { u16::from_be_bytes([c[0], c[1]]) } else { u16::from_le_bytes([c[0], c[1]]) });
    let mut s: String = char::decode_utf16(units).map(|r| r.unwrap_or('\u{FFFD}')).collect();
    // An odd trailing byte is one more U+FFFD, unless it follows a high
    // surrogate, which Python reports together with it.
    let last = body.len().checked_sub(3).map(|i| if be { body[i] } else { body[i + 1] });
    if body.len() % 2 == 1 && !last.is_some_and(|b| (0xD8..=0xDB).contains(&b)) {
        s.push('\u{FFFD}');
    }
    s
}

/// A `Res_value`. `complete` is false when the file ended inside it:
/// androguard then has no `data` attribute, and any use of it raises.
#[derive(Clone, Copy)]
struct Value {
    ty: u8,
    data: u32,
    complete: bool,
}

impl Value {
    fn parse(cur: &mut Cur) -> Result<Value> {
        cur.u16()?;
        cur.u8()?;
        // androguard reads the rest inside try/except and carries on.
        let (ty, data) = match (cur.u8(), cur.u32()) {
            (Ok(t), Ok(d)) => (t, d),
            _ => return Ok(Value { ty: 0, data: 0, complete: false }),
        };
        Ok(Value { ty, data, complete: true })
    }

    fn get(&self) -> Result<Value> {
        if self.complete { Ok(*self) } else { bail!("'ARSCResStringPoolRef' object has no attribute 'data'") }
    }
}

#[derive(Clone, Copy)]
enum Body {
    Simple(Value),
    Compact,
    /// Index into `Arsc::complex`.
    Complex(u32),
}

/// `ARSCResTableEntry`.
#[derive(Clone, Copy)]
struct Ate {
    size: u16,
    index: u32,
    body: Body,
    /// FLAG_COMPACT. androguard tests it separately from the body it
    /// parsed, which is complex if both flags are set.
    compact: bool,
}

impl Ate {
    /// The key-string index (`get_value()`). 4.1.4: compact entries use
    /// `size` instead.
    fn key_index(&self) -> i64 {
        self.index as i64
    }

    /// The value-string index of a compact entry, as `get_key_data()` uses
    /// it. 4.1.4: `index` instead.
    fn compact_key_data_index(&self) -> i64 {
        self.size as i64
    }

    /// The value-string index a compact entry resolves to in
    /// `get_resolved_res_configs()` (`ate.data`, which is `index`).
    fn compact_value_index(&self) -> i64 {
        self.index as i64
    }
}

struct Entry {
    rid: u32,
    ate: Ate,
}

/// The string pools one package chunk resolves against (`PackageContext`).
#[derive(Clone, Copy)]
struct Ctx {
    /// The table's main pool as of when the package was read.
    main: Option<u32>,
    types: u32,
    keys: u32,
}

/// `ARSCResTableConfig`'s identity: `_get_tuple()` (imsi, locale,
/// screenType, input, screenSize, version, screenConfig, screenSizeDp,
/// screenConfig2). Script and variant aren't part of it.
pub type ConfigKey = [u32; 9];

/// A `RES_TABLE_TYPE_TYPE` chunk.
struct TypeChunk {
    ctx: u32,
    type_id: u8,
    config: u32,
    entries: Range<u32>,
}

/// What `_analyse()` collected for one locale of one package.
struct LocaleValues {
    locale: String,
    /// The `public` list, as (chunk, entry): every entry, despite the name.
    public: Vec<(u32, u32)>,
    /// The `string` list, as (chunk, entry).
    strings: Vec<(u32, u32)>,
}

/// `resource_values`: per rid, (config, chunk, entry) in first-seen config
/// order, a later entry for the same config replacing the earlier one.
struct ResourceValues {
    /// Sorted by rid, then config order within it.
    items: Vec<(u32, u32, u32, u32)>,
}

impl ResourceValues {
    fn of(&self, rid: u32) -> &[(u32, u32, u32, u32)] {
        let lo = self.items.partition_point(|x| x.0 < rid);
        let hi = self.items.partition_point(|x| x.0 <= rid);
        &self.items[lo..hi]
    }
}

/// A parsed `resources.arsc`.
pub struct Arsc {
    buf: Vec<u8>,
    pools: Vec<Pool>,
    ctxs: Vec<Ctx>,
    configs: Vec<ConfigKey>,
    config_ids: HashMap<ConfigKey, u32>,
    complex: Vec<Box<[(u32, Value)]>>,
    entries: Vec<Entry>,
    chunks: Vec<TypeChunk>,
    /// Distinct package names in first-seen order, with their type chunks.
    packages: Vec<(String, Vec<u32>)>,
    /// `values`: per package (only those `_analyse()` reached), its locales.
    values: Vec<Vec<LocaleValues>>,
    resource_values: ResourceValues,
    analysis_error: Option<String>,
    /// Per package, rid -> position of its first default-locale public item.
    public_ids: OnceLock<Vec<HashMap<u32, u32>>>,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    String,
    Id,
    Bool,
    Integer,
    Color,
    Dimen,
    Other,
}

impl Arsc {
    /// `ARSCParser(raw)` followed by `_analyse()`. An error here is what the
    /// constructor (so `APK.get_android_resources()`) raises; an error in the
    /// analysis is kept in `analysis_error()` instead.
    pub fn parse(buf: Vec<u8>) -> Result<Arsc> {
        let mut a = Arsc {
            buf: Vec::new(),
            pools: Vec::new(),
            ctxs: Vec::new(),
            configs: Vec::new(),
            config_ids: HashMap::new(),
            complex: Vec::new(),
            entries: Vec::new(),
            chunks: Vec::new(),
            packages: Vec::new(),
            values: Vec::new(),
            resource_values: ResourceValues { items: Vec::new() },
            analysis_error: None,
            public_ids: OnceLock::new(),
        };
        a.read_table(&buf)?;
        a.buf = buf;
        a.config_ids = HashMap::new();
        if let Err(e) = a.analyse() {
            a.analysis_error = Some(format!("{e:#}"));
        }
        Ok(a)
    }

    /// The `resources.arsc` of the APK at `path`, or `None` if it has none.
    pub fn from_apk(path: &str) -> Result<Option<Arsc>> {
        read_arsc(&ApkZip::open_path(path)?)?.map(Arsc::parse).transpose()
    }

    /// Same as `from_apk`, for an APK held in memory.
    pub fn from_apk_bytes(apk: &[u8]) -> Result<Option<Arsc>> {
        read_arsc(&ApkZip::open(Box::new(MemSource(apk)))?)?.map(Arsc::parse).transpose()
    }

    /// The exception `_analyse()` raised, if any. androguard raises it from
    /// the first query that analyses, and later queries see the partial
    /// results.
    pub fn analysis_error(&self) -> Option<&str> {
        self.analysis_error.as_deref()
    }

    fn read_table(&mut self, b: &[u8]) -> Result<()> {
        let len = b.len() as u64;
        if len < 8 || len > 0xFFFF_FFFF {
            bail!("Invalid file size {len} for a resources.arsc file!");
        }
        let mut cur = Cur { b, pos: 0 };
        let table = Header::read(&mut cur, Some(RES_TABLE_TYPE))?;
        if table.size as u64 > len {
            bail!("The file seems to be truncated. Refuse to parse the file! Filesize: {len}, declared size: {}", table.size);
        }
        let package_count = cur.u32()?;
        cur.pos = table.start + table.header_size as u64;
        let mut main: Option<u32> = None;
        let mut by_name: HashMap<String, usize> = HashMap::new();
        while cur.pos + 8 <= table.end() {
            let h = Header::read(&mut cur, None)?;
            if h.end() > table.end() {
                break;
            }
            match h.ty {
                RES_STRING_POOL_TYPE => {
                    // `if self.stringpool_main:` is len(), i.e. stringCount.
                    let have = match main {
                        Some(m) if self.pools[m as usize].count < 0 => bail!("__len__() should return >= 0"),
                        Some(m) => self.pools[m as usize].count != 0,
                        None => false,
                    };
                    if !have {
                        self.pools.push(Pool::parse(&mut cur, &h)?);
                        main = Some(self.pools.len() as u32 - 1);
                    }
                }
                RES_TABLE_PACKAGE_TYPE => {
                    if by_name.len() as u64 > package_count as u64 {
                        bail!("Got more packages ({}) than expected ({package_count})", by_name.len());
                    }
                    self.read_package(&mut cur, &h, main, &mut by_name)?;
                }
                _ => {}
            }
            cur.pos = h.end();
        }
        Ok(())
    }

    fn read_package(&mut self, cur: &mut Cur, h: &Header, main: Option<u32>, by_name: &mut HashMap<String, usize>) -> Result<()> {
        let id = cur.u32()?;
        let name = cur.take_lenient(256);
        let type_strings = cur.u32()? as u64;
        cur.u32()?;
        let key_strings = cur.u32()? as u64;
        cur.u32()?;
        let mut name = py_decode(&cur.b[name], false);
        // name[:name.find("\x00")]: with no NUL, that drops the last char.
        match name.find('\0') {
            Some(i) => name.truncate(i),
            None => {
                name.pop();
            }
        }
        cur.pos = h.start + type_strings;
        let th = Header::read(cur, Some(RES_STRING_POOL_TYPE))?;
        let types = Pool::parse(cur, &th)?;
        cur.pos = h.start + key_strings;
        let kh = Header::read(cur, Some(RES_STRING_POOL_TYPE))?;
        let keys = Pool::parse(cur, &kh)?;
        self.pools.push(types);
        self.pools.push(keys);
        let n = self.pools.len() as u32;
        self.ctxs.push(Ctx { main, types: n - 2, keys: n - 1 });
        let ctx = self.ctxs.len() as u32 - 1;
        let pkg = *by_name.entry(name.clone()).or_insert_with(|| {
            self.packages.push((name, Vec::new()));
            self.packages.len() - 1
        });

        let mut res_id: u32 = (id & 0xFF) << 24;
        cur.pos = h.start + h.header_size as u64 + th.size as u64 + kh.size as u64;
        let mut complex_at: HashMap<(u64, u64), u32> = HashMap::new();
        while cur.pos + 8 <= h.end() {
            let ch = Header::read(cur, None)?;
            if ch.end() > h.end() {
                break;
            }
            match ch.ty {
                RES_TABLE_TYPE_SPEC_TYPE => {
                    // id, res0, res1; the rest is read inside try/except.
                    cur.take(4)?;
                }
                RES_TABLE_TYPE_TYPE => {
                    let chunk = self.parse_type_chunk(cur, &ch, ctx, &mut res_id, &mut complex_at)?;
                    self.packages[pkg].1.push(chunk);
                }
                _ => {}
            }
            cur.pos = ch.end();
        }
        Ok(())
    }

    fn parse_type_chunk(&mut self, cur: &mut Cur, ch: &Header, ctx: u32, res_id: &mut u32, complex_at: &mut HashMap<(u64, u64), u32>) -> Result<u32> {
        let chunk_end = ch.end();
        let type_id = cur.u8()?;
        let flags = cur.u8()?;
        // 4.1.4: only a warning.
        if cur.u16()? != 0 {
            bail!("reserved must be zero!");
        }
        let entry_count = cur.u32()?;
        let entries_start = cur.u32()?;
        *res_id = (*res_id & 0xFF00_0000) | (type_id as u32) << 16;
        let config = self.intern_config(read_config(cur)?);
        // androguard logs repr(self), eagerly formatted, which decodes the
        // type's name: a bad one fails the parse.
        self.pools[self.ctxs[ctx as usize].types as usize].locate(cur.b, type_id as i64 - 1)?;

        let offsets = entry_offsets(cur, flags, entry_count, res_id)?;
        let base = ch.start + entries_start as u64;
        let first = self.entries.len() as u32;
        for (off, rid) in offsets {
            let ate = self.parse_entry(cur, base + off as u64, chunk_end, complex_at)?;
            self.entries.push(Entry { rid, ate });
        }
        self.chunks.push(TypeChunk { ctx, type_id, config, entries: first..self.entries.len() as u32 });
        Ok(self.chunks.len() as u32 - 1)
    }

    fn parse_entry(&mut self, cur: &mut Cur, at: u64, chunk_end: u64, complex_at: &mut HashMap<(u64, u64), u32>) -> Result<Ate> {
        cur.pos = at;
        let size = cur.u16()?;
        let flags = cur.u16()?;
        let index = cur.u32()?;
        let body = if flags & FLAG_COMPLEX != 0 {
            // Many entries may point at one complex entry; parse it once.
            if let Some(&i) = complex_at.get(&(at, chunk_end)) {
                Body::Complex(i)
            } else {
                cur.u32()?;
                let count = cur.u32()?;
                let mut items = Vec::new();
                for _ in 0..count {
                    if cur.pos + 4 > chunk_end {
                        break;
                    }
                    let key = cur.u32()?;
                    items.push((key, Value::parse(cur)?));
                }
                self.complex.push(items.into_boxed_slice());
                let i = self.complex.len() as u32 - 1;
                complex_at.insert((at, chunk_end), i);
                Body::Complex(i)
            }
        } else if flags & FLAG_COMPACT != 0 {
            Body::Compact
        } else {
            let v = Value::parse(cur)?;
            // A weak entry is logged with an eagerly formatted repr(), which
            // reads the value's fields.
            if flags & FLAG_WEAK != 0 && !v.complete {
                bail!("'ARSCResStringPoolRef' object has no attribute 'data_type'");
            }
            Body::Simple(v)
        };
        Ok(Ate { size, index, body, compact: flags & FLAG_COMPACT != 0 })
    }

    fn intern_config(&mut self, key: ConfigKey) -> u32 {
        let n = self.configs.len() as u32;
        let i = *self.config_ids.entry(key).or_insert(n);
        if i == n {
            self.configs.push(key);
        }
        i
    }

    fn pool(&self, i: u32) -> &Pool {
        &self.pools[i as usize]
    }

    /// `getString()` without decoding, for the checks `_analyse()` makes.
    fn check(&self, pool: Option<u32>, idx: i64) -> Result<()> {
        let pool = pool.ok_or_else(|| anyhow!("'NoneType' object has no attribute 'getString'"))?;
        self.pool(pool).locate(&self.buf, idx).map(|_| ())
    }

    /// `getString()`.
    fn string(&self, pool: u32, idx: i64) -> Result<String> {
        Ok(match self.pool(pool).locate(&self.buf, idx)? {
            Some((utf8, r)) => py_decode(&self.buf[r], utf8),
            None => String::new(),
        })
    }

    /// Which of the types `_analyse()` treats specially `get_type()` names,
    /// without decoding a long string.
    fn kind(&self, chunk: &TypeChunk) -> Result<Kind> {
        let pool = self.pool(self.ctxs[chunk.ctx as usize].types);
        let idx = chunk.type_id as i64 - 1;
        let Some((utf8, r)) = pool.locate(&self.buf, idx)? else { return Ok(Kind::Other) };
        if r.len() > 64 {
            return Ok(Kind::Other);
        }
        Ok(match py_decode(&self.buf[r], utf8).as_str() {
            "string" => Kind::String,
            "id" => Kind::Id,
            "bool" => Kind::Bool,
            "integer" => Kind::Integer,
            "color" => Kind::Color,
            "dimen" => Kind::Dimen,
            _ => Kind::Other,
        })
    }

    /// `_analyse()`: fills `values` and `resource_values`, stopping where
    /// androguard would raise.
    fn analyse(&mut self) -> Result<()> {
        let mut slot: HashMap<(u32, u32), usize> = HashMap::new();
        let mut rv: Vec<(u32, u32, u32, u32)> = Vec::new();
        let result = self.analyse_into(&mut slot, &mut rv);
        // Stable: within a rid, configs stay in first-seen order.
        rv.sort_by_key(|x| x.0);
        self.resource_values = ResourceValues { items: rv };
        result
    }

    fn analyse_into(&mut self, slot: &mut HashMap<(u32, u32), usize>, rv: &mut Vec<(u32, u32, u32, u32)>) -> Result<()> {
        for p in 0..self.packages.len() {
            self.values.push(Vec::new());
            let mut locale_ids: HashMap<String, usize> = HashMap::new();
            for ci in 0..self.packages[p].1.len() {
                let c = self.packages[p].1[ci];
                let chunk = &self.chunks[c as usize];
                let ctx = self.ctxs[chunk.ctx as usize];
                let locale = locale_name(self.configs[chunk.config as usize][1]);
                let locales = self.values.last_mut().unwrap();
                let li = *locale_ids.entry(locale.clone()).or_insert_with(|| {
                    locales.push(LocaleValues { locale, public: Vec::new(), strings: Vec::new() });
                    locales.len() - 1
                });
                let mut kind = None;
                for e in chunk.entries.clone() {
                    let ate = self.entries[e as usize].ate;
                    let rid = self.entries[e as usize].rid;
                    match slot.get(&(rid, chunk.config)) {
                        Some(&i) => rv[i] = (rid, chunk.config, c, e),
                        None => {
                            slot.insert((rid, chunk.config), rv.len());
                            rv.push((rid, chunk.config, c, e));
                        }
                    }
                    // resource_keys[pkg][get_type()][get_value()] = rid
                    let k = match kind {
                        Some(k) => k,
                        None => {
                            let k = self.kind(chunk)?;
                            kind = Some(k);
                            k
                        }
                    };
                    self.check(Some(ctx.keys), ate.key_index())?;
                    let lv = &mut self.values[p][li];
                    lv.public.push((c, e));
                    let no_key = || anyhow!("'ARSCResTableEntry' object has no attribute 'key'");
                    match (k, ate.body) {
                        (Kind::String, Body::Compact) => self.check(ctx.main, ate.compact_key_data_index())?,
                        (Kind::String, Body::Complex(_)) => return Err(no_key()),
                        (Kind::String, Body::Simple(v)) => self.check(ctx.main, v.get()?.data as i64)?,
                        (Kind::Id | Kind::Bool, Body::Simple(v)) => {
                            v.get()?;
                        }
                        // integer: ate.data or ate.key; color, dimen: ate.key unless compact.
                        (Kind::Integer, Body::Complex(_)) => return Err(no_key()),
                        (Kind::Color | Kind::Dimen, Body::Complex(_)) if !ate.compact => return Err(no_key()),
                        (Kind::Integer | Kind::Color | Kind::Dimen, Body::Simple(v)) => {
                            v.get()?;
                        }
                        _ => {}
                    }
                    if k == Kind::String {
                        self.values[p][li].strings.push((c, e));
                    }
                }
            }
        }
        Ok(())
    }

    /// `get_packages_names()`.
    pub fn package_names(&self) -> Vec<&str> {
        self.packages.iter().map(|p| p.0.as_str()).collect()
    }

    /// `get_locales(package_name)` (as far as `_analyse()` got).
    pub fn locales(&self, package: &str) -> Vec<&str> {
        let p = self.packages.iter().position(|p| p.0 == package);
        p.and_then(|p| self.values.get(p)).map(|v| v.iter().map(|l| l.locale.as_str()).collect()).unwrap_or_default()
    }

    fn locale_values(&self, package: &str, locale: &str) -> Option<&LocaleValues> {
        let p = self.packages.iter().position(|p| p.0 == package)?;
        self.values.get(p)?.iter().find(|l| l.locale == locale)
    }

    fn type_name(&self, chunk: &TypeChunk) -> Result<String> {
        self.string(self.ctxs[chunk.ctx as usize].types, chunk.type_id as i64 - 1)
    }

    fn key_name(&self, chunk: &TypeChunk, ate: &Ate) -> Result<String> {
        self.string(self.ctxs[chunk.ctx as usize].keys, ate.key_index())
    }

    /// `get_public_resources(package_name, locale)`, the UTF-8 bytes.
    pub fn public_resources(&self, package: &str, locale: &str) -> Result<Vec<u8>> {
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<resources>\n");
        if let Some(lv) = self.locale_values(package, locale) {
            let mut last: Option<(u32, String)> = None;
            for &(c, e) in &lv.public {
                let chunk = &self.chunks[c as usize];
                let entry = &self.entries[e as usize];
                if last.as_ref().is_none_or(|l| l.0 != c) {
                    last = Some((c, self.type_name(chunk)?));
                }
                let ty = &last.as_ref().unwrap().1;
                let name = self.key_name(chunk, &entry.ate)?;
                out.push_str("<public type=\"");
                out.push_str(ty);
                out.push_str("\" name=\"");
                out.push_str(&name);
                out.push_str(&format!("\" id=\"0x{:08x}\" />\n", entry.rid));
                if out.len() > MAX_XML_BYTES {
                    bail!("public resources XML exceeds {MAX_XML_BYTES} bytes");
                }
            }
        }
        out.push_str("</resources>\n");
        Ok(out.into_bytes())
    }

    /// `get_resolved_strings()`: per package, per locale ("DEFAULT" for the
    /// default one), rid -> string, or None for a public string with no value
    /// in that locale. Strings are indices into the returned arena.
    pub fn resolved_strings(&self) -> Result<ResolvedStrings> {
        let mut d = Decoder::new(self);
        let mut packages = Vec::new();
        for (p, (pname, _)) in self.packages.iter().enumerate() {
            let Some(locales) = self.values.get(p) else { bail!("KeyError: {pname:?}") };
            let mut k: HashMap<u32, u32> = HashMap::new();
            let mut out_locales = Vec::new();
            for lv in locales {
                let v_locale = if lv.locale == DEFAULT_LOCALE { "DEFAULT".to_string() } else { lv.locale.clone() };
                let mut map = OrderedMap::default();
                let mut last: Option<(u32, Kind)> = None;
                for &(c, e) in &lv.public {
                    let chunk = &self.chunks[c as usize];
                    if last.is_none_or(|l| l.0 != c) {
                        last = Some((c, self.kind(chunk)?));
                    }
                    if last.unwrap().1 != Kind::String {
                        continue;
                    }
                    let entry = &self.entries[e as usize];
                    map.set(entry.rid, None);
                    let name = d.get(self.ctxs[chunk.ctx as usize].keys, entry.ate.key_index())?;
                    k.insert(d.canonical(name), entry.rid);
                }
                for &(c, e) in &lv.strings {
                    let chunk = &self.chunks[c as usize];
                    let ctx = self.ctxs[chunk.ctx as usize];
                    let ate = self.entries[e as usize].ate;
                    let name = d.get(ctx.keys, ate.key_index())?;
                    if let Some(&rid) = k.get(&d.canonical(name)) {
                        let value = match ate.body {
                            Body::Compact => d.get_opt(ctx.main, ate.compact_key_data_index())?,
                            Body::Simple(v) => d.get_opt(ctx.main, v.get()?.data as i64)?,
                            Body::Complex(_) => bail!("'ARSCResTableEntry' object has no attribute 'key'"),
                        };
                        map.set(rid, Some(value));
                    }
                }
                out_locales.push((v_locale, map.items));
            }
            packages.push((pname.clone(), out_locales));
        }
        Ok(ResolvedStrings { packages, strings: d.into_strings() })
    }

    /// `get_resource_xml_name(r_id, package)`: "@package:type/name" (or
    /// "@type/name" when `package` is given), looked up in the default
    /// locale's public list.
    pub fn resource_xml_name(&self, rid: i64, package: Option<&str>) -> Result<Option<String>> {
        let ids = self.public_ids.get_or_init(|| {
            self.values
                .iter()
                .map(|locales| {
                    let mut m = HashMap::new();
                    if let Some(lv) = locales.iter().find(|l| l.locale == DEFAULT_LOCALE) {
                        for (i, &(_, e)) in lv.public.iter().enumerate() {
                            m.entry(self.entries[e as usize].rid).or_insert(i as u32);
                        }
                    }
                    m
                })
                .collect()
        });
        // get_id(): (type, name, rid) of the first match, if rid is truthy.
        let get_id = |p: usize| -> Result<Option<(String, String)>> {
            if rid <= 0 || rid > u32::MAX as i64 {
                return Ok(None);
            }
            let Some(&i) = ids.get(p).and_then(|m| m.get(&(rid as u32))) else { return Ok(None) };
            let lv = self.values[p].iter().find(|l| l.locale == DEFAULT_LOCALE).unwrap();
            let (c, e) = lv.public[i as usize];
            let chunk = &self.chunks[c as usize];
            Ok(Some((self.type_name(chunk)?, self.key_name(chunk, &self.entries[e as usize].ate)?)))
        };
        match package.filter(|p| !p.is_empty()) {
            Some(pkg) => {
                let Some(p) = self.packages.iter().position(|x| x.0 == pkg) else { return Ok(None) };
                Ok(get_id(p)?.map(|(t, n)| format!("@{t}/{n}")))
            }
            None => {
                for (p, (pname, _)) in self.packages.iter().enumerate() {
                    if let Some((t, n)) = get_id(p)? {
                        if pname.is_empty() {
                            return Ok(None);
                        }
                        return Ok(Some(format!("@{pname}:{t}/{n}")));
                    }
                }
                Ok(None)
            }
        }
    }

    /// `get_resolved_res_configs(rid)` (no config filter): every config's
    /// value, with references followed and complex entries as lists.
    /// `rid` must be non-zero (androguard raises ValueError).
    pub fn resolved_res_configs(&self, rid: u32) -> Result<Resolved<'_>> {
        let mut r = Resolver { arsc: self, d: Decoder::new(self), steps: 0, stack: Vec::new() };
        let mut out = Vec::new();
        r.resolve_into(&mut out, rid)?;
        Ok(Resolved { items: out, configs: &self.configs, strings: r.d.into_strings() })
    }

    /// Every rid with at least one entry (`resource_values`' keys), in rid
    /// order.
    pub fn rids(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.resource_values.items.iter().map(|x| x.0).collect();
        v.dedup();
        v
    }

    /// Bytes held: the table itself plus the parsed records.
    pub fn heap_bytes(&self) -> usize {
        self.buf.capacity()
            + self.entries.capacity() * size_of::<Entry>()
            + self.resource_values.items.capacity() * 16
            + self.values.iter().flatten().map(|l| (l.public.capacity() + l.strings.capacity()) * 8).sum::<usize>()
            + self.complex.iter().map(|c| c.len() * size_of::<(u32, Value)>()).sum::<usize>()
    }
}

/// Insertion-ordered rid -> value, as a Python dict behaves.
#[derive(Default)]
struct OrderedMap {
    pos: HashMap<u32, usize>,
    items: Vec<(u32, Option<u32>)>,
}

impl OrderedMap {
    fn set(&mut self, k: u32, v: Option<u32>) {
        match self.pos.get(&k) {
            Some(&i) => self.items[i].1 = v,
            None => {
                self.pos.insert(k, self.items.len());
                self.items.push((k, v));
            }
        }
    }
}

/// Result of `Arsc::resolved_strings`.
pub struct ResolvedStrings {
    /// (package, [(locale, [(rid, value)])]), value indexing `strings`.
    pub packages: Vec<(String, Vec<(String, Vec<(u32, Option<u32>)>)>)>,
    pub strings: Vec<String>,
}

/// One element of a `get_resolved_res_configs()` result.
pub enum Item {
    /// A plain string inside a complex entry's list.
    Str(u32),
    /// (config, value).
    Pair(u32, Val),
}

pub enum Val {
    Str(u32),
    List(Vec<Item>),
}

/// Result of `Arsc::resolved_res_configs`: strings and configs are indices
/// into `strings` and `configs`.
pub struct Resolved<'a> {
    pub items: Vec<Item>,
    pub configs: &'a [ConfigKey],
    pub strings: Vec<String>,
}

/// Decodes pool strings for one query, each distinct one once, within
/// `MAX_DECODED_BYTES`.
struct Decoder<'a> {
    arsc: &'a Arsc,
    memo: HashMap<(u32, u32), u32>,
    by_text: HashMap<String, u32>,
    strings: Vec<String>,
    decoded: usize,
}

impl<'a> Decoder<'a> {
    fn new(arsc: &'a Arsc) -> Self {
        Decoder { arsc, memo: HashMap::new(), by_text: HashMap::new(), strings: vec![String::new()], decoded: 0 }
    }

    /// `getString(idx)` of `pool`, as an index into `strings` (0 is "").
    fn get(&mut self, pool: u32, idx: i64) -> Result<u32> {
        let p = self.arsc.pool(pool);
        let Some(offset) = p.offset_of(&self.arsc.buf, idx) else { return Ok(0) };
        let Some((utf8, r)) = p.locate(&self.arsc.buf, idx)? else { return Ok(0) };
        if let Some(&i) = self.memo.get(&(pool, offset)) {
            return Ok(i);
        }
        self.decoded += r.len();
        if self.decoded > MAX_DECODED_BYTES {
            bail!("resource strings exceed {MAX_DECODED_BYTES} decoded bytes");
        }
        let i = self.push(py_decode(&self.arsc.buf[r], utf8));
        self.memo.insert((pool, offset), i);
        Ok(i)
    }

    fn get_opt(&mut self, pool: Option<u32>, idx: i64) -> Result<u32> {
        let pool = pool.ok_or_else(|| anyhow!("'NoneType' object has no attribute 'getString'"))?;
        self.get(pool, idx)
    }

    fn push(&mut self, s: String) -> u32 {
        self.strings.push(s);
        self.strings.len() as u32 - 1
    }

    /// The first string index with the same text, for comparing by value.
    fn canonical(&mut self, i: u32) -> u32 {
        let s = &self.strings[i as usize];
        if let Some(&j) = self.by_text.get(s) {
            return j;
        }
        self.by_text.insert(s.clone(), i);
        i
    }

    fn into_strings(self) -> Vec<String> {
        self.strings
    }
}

/// `ARSCParser.ResourceResolver` with no wanted config.
struct Resolver<'a> {
    arsc: &'a Arsc,
    d: Decoder<'a>,
    steps: usize,
    stack: Vec<u32>,
}

impl Resolver<'_> {
    fn count(&mut self) -> Result<()> {
        self.steps += 1;
        if self.steps > MAX_RESOLVE_STEPS {
            bail!("resolving took over {MAX_RESOLVE_STEPS} steps");
        }
        Ok(())
    }

    /// `_resolve_into_result()`.
    fn resolve_into(&mut self, out: &mut Vec<Item>, rid: u32) -> Result<()> {
        // androguard only stops a reference to the entry itself; any longer
        // cycle recurses until RecursionError.
        if self.stack.contains(&rid) || self.stack.len() >= MAX_REFERENCE_DEPTH {
            bail!("maximum recursion depth exceeded");
        }
        self.count()?;
        self.stack.push(rid);
        for &(_, cfg, c, e) in self.arsc.resource_values.of(rid) {
            self.put_entry(out, cfg, c, e)?;
        }
        self.stack.pop();
        Ok(())
    }

    /// `put_ate_value()`.
    fn put_entry(&mut self, out: &mut Vec<Item>, cfg: u32, c: u32, e: u32) -> Result<()> {
        let entry = &self.arsc.entries[e as usize];
        let ctx = self.arsc.ctxs[self.arsc.chunks[c as usize].ctx as usize];
        match entry.ate.body {
            Body::Complex(i) => {
                self.count()?;
                let mut list = Vec::new();
                for &(_, v) in self.arsc.complex[i as usize].iter() {
                    self.put_value(&mut list, v, cfg, entry.rid, ctx, true)?;
                }
                out.push(Item::Pair(cfg, Val::List(list)));
            }
            Body::Compact => {
                self.count()?;
                let s = self.d.get_opt(ctx.main, entry.ate.compact_value_index())?;
                out.push(Item::Pair(cfg, Val::Str(s)));
            }
            Body::Simple(v) => self.put_value(out, v, cfg, entry.rid, ctx, false)?,
        }
        Ok(())
    }

    /// `put_item_value()` for a `Res_value`.
    fn put_value(&mut self, out: &mut Vec<Item>, v: Value, cfg: u32, parent: u32, ctx: Ctx, complex: bool) -> Result<()> {
        let v = v.get()?;
        if v.ty == TYPE_REFERENCE {
            if v.data != 0 && v.data != parent {
                self.resolve_into(out, v.data)?;
            }
            return Ok(());
        }
        self.count()?;
        // format_value(..., stringpool_main.getString): the lookup function
        // is fetched whatever the type.
        let Some(main) = ctx.main else { bail!("'NoneType' object has no attribute 'getString'") };
        let s = match v.ty {
            TYPE_STRING => self.d.get(main, v.data as i64)?,
            _ => {
                let s = format_value(v.ty, v.data)?;
                self.d.push(s)
            }
        };
        out.push(if complex { Item::Str(s) } else { Item::Pair(cfg, Val::Str(s)) });
        Ok(())
    }
}

/// `format_value()` for every type but TYPE_STRING.
pub fn format_value(ty: u8, data: u32) -> Result<String> {
    let pkg = if data >> 24 == 1 { "android:" } else { "" };
    let complex = |x: u32| (x & 0xFFFF_FF00) as f64 * RADIX_MULTS[((x >> 4) & 3) as usize];
    let unit = |units: &[&'static str]| units.get((data & 0xF) as usize).copied().ok_or_else(|| anyhow!("list index out of range"));
    Ok(match ty {
        TYPE_ATTRIBUTE => format!("?{pkg}{data:08X}"),
        TYPE_REFERENCE => format!("@{pkg}{data:08X}"),
        TYPE_FLOAT => py_f(f32::from_bits(data) as f64),
        TYPE_INT_HEX => format!("0x{data:08X}"),
        TYPE_INT_BOOLEAN => (if data == 0 { "false" } else { "true" }).to_string(),
        TYPE_DIMENSION => format!("{}{}", py_f(complex(data)), unit(&DIMENSION_UNITS)?),
        TYPE_FRACTION => format!("{}{}", py_f(complex(data) * 100.0), unit(&FRACTION_UNITS)?),
        TYPE_FIRST_COLOR_INT..=TYPE_LAST_INT => format!("#{data:08X}"),
        TYPE_FIRST_INT..=TYPE_LAST_INT => format!("{}", data as i32),
        _ => format!("<0x{data:X}, type 0x{ty:02X}>"),
    })
}

/// Python's `"%f" % x`.
pub fn py_f(x: f64) -> String {
    if x.is_nan() {
        "nan".to_string()
    } else if x.is_infinite() {
        (if x > 0.0 { "inf" } else { "-inf" }).to_string()
    } else {
        format!("{x:.6}")
    }
}

/// `ARSCResTableConfig(buff)`: reads `size` bytes' worth of fields (at least
/// the first four, whatever `size` says) and returns its identity.
fn read_config(cur: &mut Cur) -> Result<ConfigKey> {
    let start = cur.pos;
    let size = cur.u32()?;
    let imsi = cur.u32()?;
    let locale = cur.u32()?;
    let screen_type = cur.u32()?;
    let opt = |min: u32, cur: &mut Cur| -> Result<u32> { if size >= min { cur.u32() } else { Ok(0) } };
    let input = opt(20, cur)?;
    let screen_size = opt(24, cur)?;
    let version = opt(28, cur)?;
    let screen_config = opt(32, cur)?;
    let screen_size_dp = opt(36, cur)?;
    if size >= 40 {
        cur.take_lenient(4);
    }
    if size >= 44 {
        cur.take_lenient(8);
    }
    let screen_config2 = opt(52, cur)?;
    let exceeding = size as i64 - (cur.pos - start) as i64;
    if exceeding > 0 {
        cur.take_lenient(exceeding as u64);
    }
    Ok([imsi, locale, screen_type, input, screen_size, version, screen_config, screen_size_dp, screen_config2])
}

/// The entry offsets array of a type chunk: (offset, rid) for each present
/// entry. `res_id` is the package's running `mResId`, updated per index
/// exactly as androguard does (an index past 0xFFFF bleeds into the type
/// and package bits). 4.1.4: FLAG_SPARSE (0x01) entries are (index, offset/4)
/// u16 pairs; 4.1.3 ignores the flag.
fn entry_offsets(cur: &mut Cur, flags: u8, count: u32, res_id: &mut u32) -> Result<Vec<(u32, u32)>> {
    let mut out = Vec::new();
    for i in 0..count {
        *res_id = (*res_id & 0xFFFF_0000) | i;
        let offset = if flags & FLAG_OFFSET16 != 0 {
            let o = cur.u16()?;
            if o == 0xFFFF {
                continue;
            }
            o as u32 * 4
        } else {
            let o = cur.u32()?;
            if o == 0xFFFF_FFFF {
                continue;
            }
            o
        };
        out.push((offset, *res_id));
    }
    Ok(out)
}

/// `get_language_and_region()` of a config's `locale` field.
pub fn locale_name(locale: u32) -> String {
    if locale == 0 {
        return DEFAULT_LOCALE.to_string();
    }
    let unpack = |b0: u32, b1: u32, base: u32| -> String {
        let mut s = String::new();
        if b0 & 0x80 != 0 {
            let first = b1 & 0x1F;
            let second = ((b1 & 0xE0) >> 5) + ((b0 & 0x03) << 3);
            let third = (b0 & 0x7C) >> 2;
            for c in [first, second, third] {
                s.push(char::from_u32(c + base).unwrap());
            }
        } else {
            if b0 != 0 {
                s.push(char::from_u32(b0).unwrap());
            }
            if b1 != 0 {
                s.push(char::from_u32(b1).unwrap());
            }
        }
        s
    };
    let language = unpack(locale & 0xFF, (locale >> 8) & 0xFF, 'a' as u32);
    let region = unpack((locale >> 16) & 0xFF, locale >> 24, '0' as u32);
    if region.is_empty() { language } else { format!("{language}-r{region}") }
}

/// `resources.arsc` as androguard's `APK.get_android_resources()` reads it:
/// None if the central directory doesn't list it, else
/// `ZipEntry.read("resources.arsc")`, the apkInspector way (`ApkZip`: the
/// local header's method and sizes, a repeated name's last entry, and so
/// on), bounded by `MAX_ARSC_BYTES`. A listed entry without a local header
/// is an error, as androguard's KeyError.
fn read_arsc(zip: &ApkZip) -> Result<Option<Vec<u8>>> {
    if !zip.names().iter().any(|n| n == "resources.arsc") {
        return Ok(None);
    }
    match zip.read_capped("resources.arsc", MAX_ARSC_BYTES) {
        Ok(b) => Ok(Some(b)),
        Err(ReadError::NotPresent) => bail!("resources.arsc: not present (androguard: KeyError)"),
        Err(ReadError::Failed(e)) => Err(e.context("resources.arsc")),
    }
}

// ── `values[package][locale]["string"]`: get_string() and
// get_string_resources(), for androguard's APK._get_res_string_value() and
// direct callers. Kept in their own block, apart from the queries above.

impl Arsc {
    /// `values[package][locale]["string"]` as (key, value) pairs in
    /// `_analyse()` order, or `None` where androguard raises `KeyError` (no
    /// such package or locale). Each pair is `get_resource_string(ate)`:
    /// the key name and `get_key_data()`.
    pub fn string_values(&self, package: &str, locale: &str) -> Result<Option<Vec<(String, String)>>> {
        let Some(lv) = self.locale_values(package, locale) else { return Ok(None) };
        let mut d = Decoder::new(self);
        let mut out = Vec::new();
        for &(c, e) in &lv.strings {
            let chunk = &self.chunks[c as usize];
            let ctx = self.ctxs[chunk.ctx as usize];
            let ate = self.entries[e as usize].ate;
            let name = d.get(ctx.keys, ate.key_index())?;
            let value = match ate.body {
                Body::Compact => d.get_opt(ctx.main, ate.compact_key_data_index())?,
                Body::Simple(v) => d.get_opt(ctx.main, v.get()?.data as i64)?,
                Body::Complex(_) => bail!("'ARSCResTableEntry' object has no attribute 'key'"),
            };
            out.push((name, value));
        }
        let strings = d.into_strings();
        Ok(Some(out.into_iter().map(|(k, v)| (strings[k as usize].clone(), strings[v as usize].clone())).collect()))
    }

    /// `get_string(package_name, name, locale)`: the first `[name, value]`
    /// of that locale's string list, or `None`.
    pub fn get_string(&self, package: &str, name: &str, locale: &str) -> Result<Option<(String, String)>> {
        Ok(self.string_values(package, locale)?.and_then(|v| v.into_iter().find(|(k, _)| k == name)))
    }

    /// `get_string_resources(package_name, locale)`, the UTF-8 bytes. Values
    /// holding `<`, `&` or `>` are wrapped in CDATA; nothing is escaped.
    pub fn string_resources(&self, package: &str, locale: &str) -> Result<Vec<u8>> {
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<resources>\n");
        for (name, value) in self.string_values(package, locale)?.unwrap_or_default() {
            out.push_str("<string name=\"");
            out.push_str(&name);
            out.push_str("\">");
            if value.contains(['<', '&', '>']) {
                out.push_str("<![CDATA[");
                out.push_str(&value);
                out.push_str("]]>");
            } else {
                out.push_str(&value);
            }
            out.push_str("</string>\n");
            if out.len() > MAX_XML_BYTES {
                bail!("string resources XML exceeds {MAX_XML_BYTES} bytes");
            }
        }
        out.push_str("</resources>\n");
        Ok(out.into_bytes())
    }
}
