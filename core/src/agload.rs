//! What androguard 4.1.3 raises while loading a DEX, and where.
//!
//! androguard's `DEX(buff)` parses the whole file up front: the header,
//! then the map list, then every section the map declares, in its
//! dependency order (`TypeMapItem.determine_load_order()`), item after item
//! from the section start, resolving names as it goes. Any exception there
//! (a short read, an unknown map type, an undeclared type_list offset, a
//! method_id whose proto doesn't exist, ...) fails `DEX()`. Then
//! `Analysis.add(vm)` builds a `MethodAnalysis` for every method (which
//! disassembles its code and matches its try/catch handlers), and
//! `create_xref()` walks every instruction.
//!
//! This module follows the same steps over the raw bytes, without building
//! androguard's objects: it keeps only what a later step can fail on (which
//! sections exist, item offsets, list lengths), and reports the first
//! exception androguard raises as an [`AgErr`], which the Python side turns
//! into the same exception (type, args, `str()`).
//!
//! The file position follows `io.BufferedReader` over `io.BytesIO`: a seek
//! may go past the end, a read there returns nothing and leaves the position
//! where it is, and a short read stops at the end. Every unpack of a short
//! read is androguard's `struct.error`.
//!
//! Python recursion: nested encoded values (arrays in arrays, annotations in
//! annotations) recurse in androguard, which hits RecursionError at some
//! depth: Python's recursion limit (frames), or CPython 3.12's separate C
//! recursion limit (each nested instantiation counts). The caller passes
//! how many frames and how many C units are left at the frame of
//! `DEX.__init__`; each function androguard enters on that path is counted,
//! so the RecursionError comes where androguard's does (assuming loguru has
//! no handler, as `set_log` with a level above DEBUG leaves the logging
//! calls on that path).

use dex_bytecode::DexError;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::dex::Dex;

/// An exception androguard 4.1.3 raises while loading.
#[derive(Clone, Debug)]
pub enum AgErr {
    /// `HeaderItem`'s checks: ValueError, or NotImplementedError for a
    /// byte-swapped endian tag.
    Header { not_implemented: bool, message: String },
    /// `struct.error("unpack requires a buffer of N bytes")`.
    Struct(usize),
    /// `KeyError(TypeMapItem(t))`: a section the map doesn't have.
    KeyMap(u16),
    /// `KeyError(off)`: an offset `ClassManager.get_type_list` doesn't know.
    KeyInt(u64),
    /// ValueError from calling the enum `which` ("TypeMapItem",
    /// "RestrictionApiFlag", "DomapiApiFlag") on `value`.
    Enum { which: &'static str, value: u64 },
    /// `IndexError('list index out of range')`.
    IndexList,
    /// `IndexError('string index out of range')`.
    IndexStr,
    /// `AttributeError("'obj' object has no attribute 'name'")`.
    Attr { obj: &'static str, name: &'static str },
    /// `RecursionError('maximum recursion depth exceeded')`.
    Recursion,
    /// androguard never returns: a string_data_item without a terminating
    /// NUL before the end of the file loops forever in
    /// `read_null_terminated_string` (its list grows until MemoryError).
    NoTerminate,
    /// `InvalidInstruction` from the linear sweep.
    Invalid(DexError),
}

type R<T> = Result<T, AgErr>;

pub const HEADER_ITEM: u16 = 0x0;
pub const STRING_ID_ITEM: u16 = 0x1;
pub const TYPE_ID_ITEM: u16 = 0x2;
pub const PROTO_ID_ITEM: u16 = 0x3;
pub const FIELD_ID_ITEM: u16 = 0x4;
pub const METHOD_ID_ITEM: u16 = 0x5;
pub const CLASS_DEF_ITEM: u16 = 0x6;
pub const CALL_SITE_ITEM: u16 = 0x7;
pub const METHOD_HANDLE_ITEM: u16 = 0x8;
pub const MAP_LIST: u16 = 0x1000;
pub const TYPE_LIST: u16 = 0x1001;
pub const ANNOTATION_SET_REF_LIST: u16 = 0x1002;
pub const ANNOTATION_SET_ITEM: u16 = 0x1003;
pub const CLASS_DATA_ITEM: u16 = 0x2000;
pub const CODE_ITEM: u16 = 0x2001;
pub const STRING_DATA_ITEM: u16 = 0x2002;
pub const DEBUG_INFO_ITEM: u16 = 0x2003;
pub const ANNOTATION_ITEM: u16 = 0x2004;
pub const ENCODED_ARRAY_ITEM: u16 = 0x2005;
pub const ANNOTATIONS_DIRECTORY_ITEM: u16 = 0x2006;
pub const HIDDENAPI_CLASS_DATA_ITEM: u16 = 0xF000;

/// `TypeMapItem.determine_load_order()` in androguard 4.1.3; None for a
/// value that isn't a `TypeMapItem` (its constructor raises ValueError).
fn load_order(t: u16) -> Option<u8> {
    Some(match t {
        HEADER_ITEM => 0,
        MAP_LIST => 1,
        STRING_DATA_ITEM => 2,
        STRING_ID_ITEM => 3,
        TYPE_ID_ITEM => 4,
        FIELD_ID_ITEM => 5,
        TYPE_LIST => 6,
        PROTO_ID_ITEM => 7,
        METHOD_ID_ITEM => 8,
        METHOD_HANDLE_ITEM => 9,
        CALL_SITE_ITEM => 10,
        CLASS_DATA_ITEM => 11,
        DEBUG_INFO_ITEM => 12,
        CODE_ITEM => 13,
        ANNOTATION_ITEM => 14,
        ANNOTATION_SET_ITEM => 15,
        ANNOTATION_SET_REF_LIST => 16,
        ENCODED_ARRAY_ITEM => 17,
        ANNOTATIONS_DIRECTORY_ITEM => 18,
        CLASS_DEF_ITEM => 19,
        HIDDENAPI_CLASS_DATA_ITEM => 20,
        _ => return None,
    })
}

/// `io.BufferedReader(io.BytesIO(buff))`, as androguard reads it.
pub(crate) struct Buf<'a> {
    pub(crate) b: &'a [u8],
    pub(crate) pos: u64,
}

impl<'a> Buf<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Buf { b, pos: 0 }
    }

    fn len(&self) -> u64 {
        self.b.len() as u64
    }

    pub(crate) fn seek(&mut self, pos: u64) {
        self.pos = pos;
    }

    pub(crate) fn tell(&self) -> u64 {
        self.pos
    }

    /// `read(n)`: up to n bytes; past the end, nothing (position kept).
    pub(crate) fn read(&mut self, n: u64) -> &'a [u8] {
        if self.pos >= self.len() {
            return &[];
        }
        let start = self.pos as usize;
        let end = self.pos.saturating_add(n).min(self.len());
        self.pos = end;
        &self.b[start..end as usize]
    }

    /// `packer[fmt].unpack(buff.read(n))`: the n bytes, or struct.error.
    pub(crate) fn unpack(&mut self, n: usize) -> R<&'a [u8]> {
        let s = self.read(n as u64);
        if s.len() == n { Ok(s) } else { Err(AgErr::Struct(n)) }
    }

    pub(crate) fn u8(&mut self) -> R<u8> {
        Ok(self.unpack(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> R<u16> {
        let s = self.unpack(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    pub(crate) fn u32(&mut self) -> R<u32> {
        let s = self.unpack(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// androguard's `readuleb128` (up to 5 bytes, the fifth taken whole).
    pub(crate) fn uleb(&mut self) -> R<u64> {
        let mut result = self.u8()? as u64;
        if result > 0x7f {
            let mut cur = self.u8()? as u64;
            result = (result & 0x7f) | ((cur & 0x7f) << 7);
            if cur > 0x7f {
                cur = self.u8()? as u64;
                result |= (cur & 0x7f) << 14;
                if cur > 0x7f {
                    cur = self.u8()? as u64;
                    result |= (cur & 0x7f) << 21;
                    if cur > 0x7f {
                        cur = self.u8()? as u64;
                        result |= cur << 28;
                    }
                }
            }
        }
        Ok(result)
    }

    /// androguard's `readsleb128`.
    pub(crate) fn sleb(&mut self) -> R<i64> {
        let mut result: i64 = 0;
        let mut shift = 0i64;
        for _ in 0..5 {
            let cur = self.u8()? as i64;
            result |= (cur & 0x7f) << shift;
            shift += 7;
            if cur & 0x80 == 0 {
                let bit_left = (32 - shift).max(0);
                result <<= bit_left;
                if result > 0x7fff_ffff {
                    result = (0x7fff_ffff & result) - 0x8000_0000;
                }
                result >>= bit_left;
                break;
            }
        }
        Ok(result)
    }
}

/// A `DalvikCode` as androguard parses it at `off` (after alignment).
pub struct CodeRec {
    /// The insns bytes androguard read (cut short by the end of the file,
    /// so possibly of odd length).
    pub insns: std::ops::Range<usize>,
    /// (start_addr, insn_count, handler_off) of each try_item.
    pub tries: Vec<(u32, u16, u16)>,
    /// Offset of the EncodedCatchHandlerList.
    pub handlers_off: u64,
    /// Each EncodedCatchHandler: (offset, size, its (type_idx, addr) pairs).
    pub handlers: Vec<(u64, i64, Vec<u64>)>,
}

/// Parse the DalvikCode at the current position, as androguard does.
pub(crate) fn parse_code(buf: &mut Buf<'_>) -> R<CodeRec> {
    let h = buf.unpack(16)?;
    let tries_size = u16::from_le_bytes([h[6], h[7]]);
    let insns_size = u32::from_le_bytes([h[12], h[13], h[14], h[15]]) as u64;
    let start = buf.tell().min(buf.len()) as usize;
    let insns = buf.read(insns_size * 2);
    let insns = start..start + insns.len();
    if insns_size % 2 == 1 && tries_size > 0 {
        buf.u16()?;
    }
    let mut tries = Vec::new();
    let mut handlers = Vec::new();
    let mut handlers_off = 0;
    if tries_size > 0 {
        for _ in 0..tries_size {
            let t = buf.unpack(8)?;
            tries.push((
                u32::from_le_bytes([t[0], t[1], t[2], t[3]]),
                u16::from_le_bytes([t[4], t[5]]),
                u16::from_le_bytes([t[6], t[7]]),
            ));
        }
        handlers_off = buf.tell();
        let n = buf.uleb()?;
        // Each handler takes at least one byte, so a bad count runs out of
        // input after at most len() of them.
        for _ in 0..n {
            let off = buf.tell();
            let size = buf.sleb()?;
            let mut types = Vec::new();
            for _ in 0..size.unsigned_abs() {
                types.push(buf.uleb()?);
                buf.uleb()?;
            }
            if size <= 0 {
                buf.uleb()?;
            }
            handlers.push((off, size, types));
        }
    }
    Ok(CodeRec { insns, tries, handlers_off, handlers })
}

/// What androguard's ClassManager holds after `DEX()`, as far as a later
/// step can fail on it.
#[derive(Default)]
pub struct AgState {
    /// `header.map_off == 0`: no map list; `DEX` then has no `classes`
    /// attribute, which `Analysis.add()` reads.
    pub no_map: bool,
    /// Section types the map has (ClassManager's `__manage_item` keys).
    present: FxHashSet<u16>,
    /// The last STRING_ID_ITEM section's string_data_off values.
    pub string_ids: Vec<u32>,
    /// The last TYPE_ID_ITEM section's descriptor_idx values.
    pub type_ids: Vec<u32>,
    /// The last METHOD_ID_ITEM section's class_idx values.
    pub method_classes: Vec<u16>,
    /// Offsets of every string_data_item parsed (`__strings_off`), sorted.
    pub string_data: Vec<u32>,
    /// Offsets of every class_data_item parsed (`__classdata_off`), sorted.
    pub class_data: Vec<u32>,
    /// Offsets of the last CODE_ITEM section's DalvikCodes, sorted.
    pub code: Vec<u32>,
    /// The first CLASS_DEF_ITEM section's class_defs (`DEX.get_classes()`):
    /// class_data_off of each.
    pub classes: Vec<u32>,
    /// Number of flags of the first HIDDENAPI_CLASS_DATA_ITEM section
    /// (`DEX.get_hidden_api()`), if there is one.
    pub hidden_flags: Option<u64>,
}

impl AgState {
    pub fn has(&self, t: u16) -> bool {
        self.present.contains(&t)
    }

    fn need(&self, t: u16) -> R<()> {
        if self.has(t) { Ok(()) } else { Err(AgErr::KeyMap(t)) }
    }

    /// `ClassManager.get_string()`: raises only without a STRING_ID section.
    fn get_string(&self) -> R<()> {
        self.need(STRING_ID_ITEM)
    }

    /// `ClassManager.get_type()`: raises only without a TYPE_ID section
    /// (with one, a type in range resolves its string, and the string_ids
    /// exist, or parsing the types would have failed).
    fn get_type(&self) -> R<()> {
        self.need(TYPE_ID_ITEM)
    }

    pub fn has_code(&self, off: u64) -> bool {
        u32::try_from(off).is_ok_and(|o| self.code.binary_search(&o).is_ok())
    }

    pub fn has_class_data(&self, off: u32) -> bool {
        off != 0 && self.class_data.binary_search(&off).is_ok()
    }
}

/// Parse state while emulating `DEX()`.
struct Load<'a> {
    buf: Buf<'a>,
    st: AgState,
    /// `__typelists_off`: offset -> number of types.
    type_lists: FxHashMap<u64, u32>,
    /// The last PROTO_ID_ITEM section: parameters_off of each.
    protos: Vec<u32>,
    /// Protos whose parameters have been resolved (androguard caches them).
    proto_done: FxHashSet<u32>,
    /// Item offsets of the last ENCODED_ARRAY_ITEM section.
    enc_arrays: FxHashSet<u64>,
    /// Frames left above `DEX.__init__` (its own frame is depth 0).
    max_depth: i64,
    /// C recursion budget left inside `DEX.__init__`, in units of
    /// CPython 3.12's C recursion counter (see `enter`).
    c_budget: i64,
}

/// Steps through androguard 4.1.3's `DEX(buff)` on `data`; `max_depth` is
/// how many Python frames deeper than `DEX.__init__`'s androguard may go
/// (`sys.getrecursionlimit()` minus the depth of that frame), `c_budget`
/// how many C recursion units are left there (see `Load::enter`).
pub fn load(data: &[u8], max_depth: i64, c_budget: i64) -> R<AgState> {
    if let Some(e) = crate::apk::androguard_header_check(data, true) {
        return Err(AgErr::Header { not_implemented: e.not_implemented, message: e.message });
    }
    let map_off = u32::from_le_bytes(data[52..56].try_into().unwrap()) as u64;
    let mut l = Load {
        buf: Buf::new(data),
        st: AgState::default(),
        type_lists: FxHashMap::default(),
        protos: Vec::new(),
        proto_done: FxHashSet::default(),
        enc_arrays: FxHashSet::default(),
        max_depth,
        c_budget,
    };
    if map_off == 0 {
        l.st.no_map = true;
        return Ok(l.st);
    }
    // MapList.__init__
    l.buf.seek(map_off);
    let size = l.buf.u32()?;
    let mut items: Vec<(u16, u32, u32, u8)> = Vec::new();
    for _ in 0..size {
        let idx = l.buf.tell();
        let t = l.buf.u16()?;
        let Some(order) = load_order(t) else {
            return Err(AgErr::Enum { which: "TypeMapItem", value: t as u64 });
        };
        let s = l.buf.unpack(10)?;
        let size = u32::from_le_bytes([s[2], s[3], s[4], s[5]]);
        let offset = u32::from_le_bytes([s[6], s[7], s[8], s[9]]);
        items.push((t, size, offset, order));
        l.buf.seek(idx + 12);
    }
    let mut ordered: Vec<usize> = (0..items.len()).collect();
    ordered.sort_by_key(|&i| items[i].3); // stable, as Python's sorted()
    // DEX._load: `get_item_type` gives the first section of a type, in map
    // order.
    let first_class_defs = items.iter().position(|it| it.0 == CLASS_DEF_ITEM);
    let first_hidden = items.iter().position(|it| it.0 == HIDDENAPI_CLASS_DATA_ITEM);
    for i in ordered {
        let (t, size, offset, _) = items[i];
        l.parse(t, size, offset as u64, Some(i) == first_class_defs, Some(i) == first_hidden)?;
        l.st.present.insert(t);
    }
    let st = &mut l.st;
    for v in [&mut st.string_data, &mut st.class_data, &mut st.code] {
        v.sort_unstable();
        v.dedup();
    }
    Ok(l.st)
}

impl Load<'_> {
    /// `MapItem.parse()` for one section, then what `add_type_item` keeps.
    fn parse(&mut self, t: u16, size: u32, offset: u64, first_class_defs: bool, first_hidden: bool) -> R<()> {
        let aligned = offset + offset % 4;
        match t {
            STRING_ID_ITEM => {
                self.buf.seek(offset);
                let mut v = Vec::new();
                for _ in 0..size {
                    v.push(self.buf.u32()?);
                }
                self.st.string_ids = v;
            }
            CODE_ITEM => {
                self.buf.seek(aligned);
                let mut v = Vec::new();
                for _ in 0..size {
                    let off = self.buf.tell();
                    if off % 4 != 0 {
                        self.buf.seek(off + (4 - off % 4));
                    }
                    let at = self.buf.tell();
                    parse_code(&mut self.buf)?;
                    v.push(at as u32);
                }
                self.st.code = v;
            }
            TYPE_ID_ITEM => {
                self.buf.seek(aligned);
                let mut v = Vec::new();
                for _ in 0..size {
                    v.push(self.buf.u32()?);
                    self.st.get_string()?;
                }
                self.st.type_ids = v;
            }
            PROTO_ID_ITEM => {
                self.buf.seek(aligned);
                let mut v = Vec::new();
                for _ in 0..size {
                    let s = self.buf.unpack(12)?;
                    self.st.get_string()?;
                    self.st.get_type()?;
                    v.push(u32::from_le_bytes([s[8], s[9], s[10], s[11]]));
                }
                self.protos = v;
                self.proto_done.clear();
            }
            FIELD_ID_ITEM => {
                self.buf.seek(aligned);
                for _ in 0..size {
                    self.buf.unpack(8)?;
                    self.st.get_type()?;
                    self.st.get_type()?;
                    self.st.get_string()?;
                }
            }
            METHOD_ID_ITEM => {
                self.buf.seek(aligned);
                let mut v = Vec::new();
                for _ in 0..size {
                    let s = self.buf.unpack(8)?;
                    let class_idx = u16::from_le_bytes([s[0], s[1]]);
                    let proto_idx = u16::from_le_bytes([s[2], s[3]]) as u32;
                    self.st.get_type()?;
                    self.get_proto(proto_idx)?;
                    self.st.get_string()?;
                    v.push(class_idx);
                }
                self.st.method_classes = v;
            }
            CLASS_DEF_ITEM => {
                // Every CLASS_DATA_ITEM section is parsed before any class_def.
                self.st.class_data.sort_unstable();
                self.st.class_data.dedup();
                self.buf.seek(aligned);
                let mut v = Vec::new();
                for _ in 0..size {
                    let idx = self.buf.tell();
                    let s = self.buf.unpack(32)?;
                    let w = |k: usize| u32::from_le_bytes([s[4 * k], s[4 * k + 1], s[4 * k + 2], s[4 * k + 3]]);
                    // ClassDefItem.reload()
                    self.st.get_type()?;
                    self.st.get_type()?;
                    self.get_type_list(w(3) as u64)?;
                    let class_data_off = w(6);
                    let has_data = self.st.has_class_data(class_data_off);
                    if w(5) != 0 {
                        self.st.need(ANNOTATIONS_DIRECTORY_ITEM)?;
                    }
                    if w(7) != 0 {
                        self.st.need(ENCODED_ARRAY_ITEM)?;
                        if has_data && !self.enc_arrays.contains(&(w(7) as u64)) {
                            return Err(AgErr::Attr { obj: "NoneType", name: "get_value" });
                        }
                    }
                    v.push(class_data_off);
                    self.buf.seek(idx + 32);
                }
                if first_class_defs {
                    self.st.classes = v;
                }
            }
            HEADER_ITEM => {
                self.buf.seek(aligned);
                self.header_again()?;
            }
            ANNOTATION_ITEM => {
                self.buf.seek(offset);
                for _ in 0..size {
                    // AnnotationItem (4, 4): get_byte -> packer (6, 5)
                    self.enter(6, 5)?;
                    self.buf.u8()?; // visibility
                    self.enter(5, 6)?;
                    self.encoded_annotation(5, 6)?;
                }
            }
            ANNOTATION_SET_ITEM => {
                self.buf.seek(aligned);
                for _ in 0..size {
                    let n = self.buf.u32()?;
                    for _ in 0..n {
                        self.buf.u32()?;
                    }
                }
            }
            ANNOTATIONS_DIRECTORY_ITEM => {
                self.buf.seek(aligned);
                for _ in 0..size {
                    let s = self.buf.unpack(16)?;
                    let w = |k: usize| u32::from_le_bytes([s[4 * k], s[4 * k + 1], s[4 * k + 2], s[4 * k + 3]]) as u64;
                    for _ in 0..w(1) + w(2) + w(3) {
                        self.buf.unpack(8)?;
                    }
                }
            }
            HIDDENAPI_CLASS_DATA_ITEM => {
                self.buf.seek(offset);
                let n = self.hidden_api()?;
                if first_hidden {
                    self.st.hidden_flags = Some(n);
                }
            }
            ANNOTATION_SET_REF_LIST => {
                self.buf.seek(aligned);
                for _ in 0..size {
                    let n = self.buf.u32()?;
                    for _ in 0..n {
                        self.buf.u32()?;
                    }
                }
            }
            TYPE_LIST => {
                self.buf.seek(aligned);
                for _ in 0..size {
                    let at = self.buf.tell();
                    let n = self.buf.u32()?;
                    for _ in 0..n {
                        self.buf.u16()?;
                    }
                    if n % 2 != 0 {
                        self.buf.read(2);
                    }
                    self.type_lists.insert(at, n);
                }
            }
            STRING_DATA_ITEM => {
                self.buf.seek(offset);
                for _ in 0..size {
                    let at = self.buf.tell();
                    self.buf.uleb()?;
                    // read_null_terminated_string
                    let pos = self.buf.tell();
                    let rest = if pos < self.buf.len() { &self.buf.b[pos as usize..] } else { &[][..] };
                    match memchr::memchr(0, rest) {
                        Some(n) => self.buf.seek(pos + n as u64 + 1),
                        None => return Err(AgErr::NoTerminate),
                    }
                    self.st.string_data.push(at as u32);
                }
            }
            DEBUG_INFO_ITEM => {}
            ENCODED_ARRAY_ITEM => {
                self.buf.seek(offset);
                let mut v = FxHashSet::default();
                for _ in 0..size {
                    let at = self.buf.tell();
                    // EncodedArrayItem (4, 4) -> EncodedArray (5, 6)
                    self.enter(5, 6)?;
                    self.encoded_array(5, 6)?;
                    v.insert(at);
                }
                self.enc_arrays = v;
            }
            CLASS_DATA_ITEM => {
                self.buf.seek(offset);
                for _ in 0..size {
                    let at = self.buf.tell();
                    let mut sizes = [0u64; 4];
                    for s in &mut sizes {
                        *s = self.buf.uleb()?;
                    }
                    for (k, &n) in sizes.iter().enumerate() {
                        for _ in 0..n {
                            for _ in 0..if k < 2 { 2 } else { 3 } {
                                self.buf.uleb()?;
                            }
                        }
                    }
                    self.st.class_data.push(at as u32);
                }
            }
            // MAP_LIST: nothing to parse; METHOD_HANDLE_ITEM, CALL_SITE_ITEM:
            // logged as unknown.
            _ => {}
        }
        Ok(())
    }

    /// Entering a Python frame `r` frames below `DEX.__init__`'s, with `u`
    /// units of C recursion used since. CPython 3.12 counts two units for
    /// an instantiation (`type.__call__`, then the eval loop entered for
    /// `__init__`) and one for a property getter or `__getitem__` run from
    /// C; a plain Python call counts none. Either limit raises the same
    /// RecursionError.
    fn enter(&self, r: i64, u: i64) -> R<()> {
        if r > self.max_depth || u > self.c_budget { Err(AgErr::Recursion) } else { Ok(()) }
    }

    /// A Python-only call (no C units) at depth `r`.
    fn depth(&self, r: i64) -> R<()> {
        if r > self.max_depth { Err(AgErr::Recursion) } else { Ok(()) }
    }

    /// `ClassManager.get_type_list(off)`.
    fn get_type_list(&self, off: u64) -> R<()> {
        if off == 0 {
            return Ok(());
        }
        match self.type_lists.get(&off) {
            None => Err(AgErr::KeyInt(off)),
            Some(&n) if n > 0 => self.st.get_type(),
            Some(_) => Ok(()),
        }
    }

    /// `ClassManager.get_proto(idx)` as `MethodIdItem.reload()` calls it.
    fn get_proto(&mut self, idx: u32) -> R<()> {
        self.st.need(PROTO_ID_ITEM)?;
        let Some(&params) = self.protos.get(idx as usize) else {
            return Err(AgErr::Attr { obj: "ProtoIdItemInvalid", name: "get_parameters_off_value" });
        };
        if self.proto_done.insert(idx) {
            if let Err(e) = self.get_type_list(params as u64) {
                self.proto_done.remove(&idx);
                return Err(e);
            }
        }
        Ok(())
    }

    /// `HeaderItem` again, for a HEADER_ITEM map entry: it unpacks 112
    /// bytes at the entry's position and checks them, but takes the endian
    /// tag from offset 40 and the checksum over everything after its own
    /// position + 12.
    fn header_again(&mut self) -> R<()> {
        let at = self.buf.tell();
        let h = self.buf.unpack(112)?;
        let magic = &h[..8];
        if &magic[..2] != b"de" || !matches!(magic[2], 0x78 | 0x79) || magic[3] != 0x0a || magic[7] != 0 {
            return Err(AgErr::Header {
                not_implemented: false,
                message: format!("This is not a DEX file! Wrong magic: {}", crate::render::py_bytes_repr(magic)),
            });
        }
        let w = |o: usize| u32::from_le_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]);
        let rest = if at + 12 < self.buf.len() { &self.buf.b[(at + 12) as usize..] } else { &[][..] };
        if crate::apk::adler32(rest) != w(8) {
            return Err(AgErr::Header { not_implemented: false, message: "Wrong Adler32 checksum for DEX file!".into() });
        }
        if w(36) != 0x70 {
            return Err(AgErr::Header {
                not_implemented: false,
                message: format!("This is not a DEX file! Wrong header size: '{}'", w(36)),
            });
        }
        if w(64) > 65535 {
            return Err(AgErr::Header {
                not_implemented: false,
                message: format!("DEX file contains too many ({}) TYPE_IDs to be valid!", w(64)),
            });
        }
        if w(72) > 65535 {
            return Err(AgErr::Header {
                not_implemented: false,
                message: format!("DEX file contains too many ({}) PROTO_IDs to be valid!", w(72)),
            });
        }
        Ok(())
    }

    /// `HiddenApiClassDataItem.__init__`; returns the number of flags.
    fn hidden_api(&mut self) -> R<u64> {
        let start = self.buf.tell();
        let section_size = self.buf.u32()? as u64;
        let mut offsets_size: i64 = 0;
        let mut i: i64 = 0;
        while self.buf.tell() - start < section_size {
            if offsets_size != 0 && i >= offsets_size {
                break;
            }
            let offset = self.buf.u32()? as i64;
            if offset != 0 && offsets_size == 0 {
                offsets_size = (offset - 4).div_euclid(4);
            }
            i += 1;
        }
        for _ in 0..offsets_size.max(0) {
            let flag = self.buf.uleb()?;
            if flag & 7 == 7 {
                return Err(AgErr::Enum { which: "RestrictionApiFlag", value: 7 });
            }
            if flag >> 3 > 2 {
                return Err(AgErr::Enum { which: "DomapiApiFlag", value: flag >> 3 });
            }
        }
        Ok(offsets_size.max(0) as u64)
    }

    // Nested values. `r` is the Python depth of the frame being run
    // (DEX.__init__ is 0), `u` its C units (see `enter`); `get_byte` at
    // (d, u) runs the `packer` property and `DalvikPacker.__getitem__` at
    // (d + 1, u + 1); `readuleb128` at d calls `get_byte` at d + 1.

    /// `readuleb128` called from a frame at (`r`, `u`).
    fn uleb_at(&mut self, r: i64, u: i64) -> R<u64> {
        self.enter(r + 3, u + 1)?;
        self.buf.uleb()
    }

    /// `EncodedArray.__init__` running at (`r`, `u`).
    fn encoded_array(&mut self, r: i64, u: i64) -> R<()> {
        let n = self.uleb_at(r, u)?;
        for _ in 0..n {
            self.enter(r + 1, u + 2)?;
            self.encoded_value(r + 1, u + 2)?;
        }
        Ok(())
    }

    /// `EncodedAnnotation.__init__` running at (`r`, `u`).
    fn encoded_annotation(&mut self, r: i64, u: i64) -> R<()> {
        self.uleb_at(r, u)?; // type_idx
        let n = self.uleb_at(r, u)?;
        for _ in 0..n {
            // AnnotationElement at (r + 1, u + 2)
            self.enter(r + 1, u + 2)?;
            self.uleb_at(r + 1, u + 2)?; // name_idx
            self.enter(r + 2, u + 4)?;
            self.encoded_value(r + 2, u + 4)?;
        }
        Ok(())
    }

    /// `EncodedValue.__init__` running at (`r`, `u`).
    fn encoded_value(&mut self, r: i64, u: i64) -> R<()> {
        self.enter(r + 2, u + 1)?; // get_byte -> packer
        let val = self.buf.u8()?;
        let arg = (val >> 5) as u64;
        let ty = val & 0x1f;
        match ty {
            0x02..=0x16 => {
                self.depth(r + 1)?; // _getintvalue
                self.buf.read(arg + 1);
            }
            0x17 => {
                self.buf.read(arg + 1);
                self.depth(r + 1)?;
                // get_raw_string -> StringDataItem.get
                self.depth(r + 2)?;
                self.st.get_string()?;
            }
            0x18 => {
                self.buf.read(arg + 1);
                // get_type -> get_type_ref -> TypeHIdItem.get; get_string ->
                // get_raw_string -> StringDataItem.get
                self.depth(r + 4)?;
                self.st.get_type()?;
            }
            0x19 | 0x1b => {
                self.buf.read(arg + 1);
                // get_field -> get_field_ref -> FieldHIdItem.get; get_list
                // -> get_class_name ...
                self.depth(r + 3)?;
                self.st.need(FIELD_ID_ITEM)?;
            }
            0x1a => {
                self.buf.read(arg + 1);
                self.depth(r + 3)?;
                self.st.need(METHOD_ID_ITEM)?;
            }
            0x1c => {
                self.enter(r + 1, u + 2)?;
                self.encoded_array(r + 1, u + 2)?;
            }
            0x1d => {
                self.enter(r + 1, u + 2)?;
                self.encoded_annotation(r + 1, u + 2)?;
            }
            0x00 => {
                self.enter(r + 2, u + 1)?;
                self.buf.u8()?;
            }
            0x1e | 0x1f => {}
            _ => {
                // logger.warning -> Logger._log (no handler: returns)
                self.depth(r + 2)?;
            }
        }
        Ok(())
    }
}

/// Parse the class_data_item at `off` (known to parse): the
/// (method_idx, code_off) of its direct then virtual methods, as androguard
/// computes them (unbounded Python ints; saturated here).
pub fn class_methods(data: &[u8], off: u32) -> Vec<(u64, u64)> {
    let mut buf = Buf::new(data);
    buf.seek(off as u64);
    let mut out = Vec::new();
    let mut sizes = [0u64; 4];
    for s in &mut sizes {
        *s = buf.uleb().unwrap_or(0);
    }
    for (k, &n) in sizes.iter().enumerate() {
        let mut idx: u64 = 0;
        for _ in 0..n {
            let Ok(diff) = buf.uleb() else { return out };
            idx = idx.saturating_add(diff);
            let _ = buf.uleb();
            if k >= 2 {
                out.push((idx, buf.uleb().unwrap_or(0)));
            }
        }
    }
    out
}

/// What `Analysis.add(vm)` raises for a DEX without a map list (`DEX` then
/// has no `classes` attribute).
pub fn add_error_no_map() -> AgErr {
    AgErr::Attr { obj: "DEX", name: "classes" }
}

/// What `Analysis.add(vm)` raises for this DEX, if anything. `dex` is the
/// native reader over the same bytes (for the instruction decoders).
pub fn add_error(st: &AgState, dex: &Dex) -> Option<AgErr> {
    crate::pool::install(|| {
        if st.no_map {
            return Some(add_error_no_map());
        }
        let data = &dex.data[..];
        // Methods and codes in add() order, each class_data once (shared ones
        // are the same objects, already loaded and analysed).
        let mut seen_data = FxHashSet::default();
        // (class number, code_off) in order, to decode in parallel.
        let mut order: Vec<(usize, u64)> = Vec::new();
        let mut first_err: Option<(usize, AgErr)> = None;
        'classes: for (i, &cd) in st.classes.iter().enumerate() {
            if let Some(n) = st.hidden_flags {
                if i as u64 >= n {
                    first_err = Some((i, AgErr::IndexList));
                    break;
                }
            }
            if !st.has_class_data(cd) || !seen_data.insert(cd) {
                continue;
            }
            for (_, code_off) in class_methods(data, cd) {
                if !st.has(METHOD_ID_ITEM) {
                    first_err = Some((i, AgErr::KeyMap(METHOD_ID_ITEM)));
                    break 'classes;
                }
                if st.has_code(code_off) {
                    order.push((i, code_off));
                }
            }
        }
        // Code errors (instructions, then try/catch) before `first_err`'s class
        // win; within a class, in method order.
        let limit = first_err.as_ref().map(|e| e.0).unwrap_or(usize::MAX);
        let mut seen_code = FxHashSet::default();
        let todo: Vec<(usize, u64)> = order.into_iter().filter(|o| o.0 <= limit && seen_code.insert(o.1)).collect();
        use rayon::prelude::*;
        let code_err = todo.par_iter().find_map_first(|&(i, off)| code_error(st, dex, off).map(|e| (i, e)));
        match (code_err, first_err) {
            (Some(c), Some(f)) => Some(if c.0 < f.0 || (c.0 == f.0 && !matches!(f.1, AgErr::IndexList)) { c.1 } else { f.1 }),
            (Some(c), None) => Some(c.1),
            (None, f) => f.map(|f| f.1),
        }
    })
}

/// What `MethodAnalysis` raises for the code at `off`: the linear sweep
/// (InvalidInstruction, or struct.error on a trailing odd byte), then
/// `determineException` (IndexError for a try whose handler offset matches
/// no handler; KeyError without a TYPE_ID section).
pub fn code_error(st: &AgState, dex: &Dex, off: u64) -> Option<AgErr> {
    let mut buf = Buf::new(&dex.data);
    buf.seek(off);
    let rec = parse_code(&mut buf).ok()?;
    let code = &dex.data[rec.insns.clone()];
    if let Err(e) = sweep(dex, code) {
        return Some(e);
    }
    if rec.tries.is_empty() {
        return None;
    }
    // determineException
    let mut keys: Vec<u64> = Vec::new();
    let mut tries_of: FxHashMap<u64, usize> = FxHashMap::default();
    for &(_, _, h) in &rec.tries {
        let k = h as u64 + rec.handlers_off;
        *tries_of.entry(k).or_insert_with(|| {
            keys.push(k);
            0
        }) += 1;
    }
    let mut handler_at: FxHashMap<u64, usize> = FxHashMap::default();
    for (n, h) in rec.handlers.iter().enumerate() {
        if tries_of.contains_key(&h.0) {
            handler_at.entry(h.0).or_insert(n);
        }
    }
    for k in keys {
        let Some(&n) = handler_at.get(&k) else { return Some(AgErr::IndexList) };
        if !rec.handlers[n].2.is_empty() && !st.has(TYPE_ID_ITEM) {
            return Some(AgErr::KeyMap(TYPE_ID_ITEM));
        }
    }
    None
}

/// androguard's `LinearSweepAlgorithm` over `code` (as read, possibly cut
/// short by the end of the file): InvalidInstruction where the decoders
/// find one, and struct.error for a lone byte at the end.
fn sweep(dex: &Dex, code: &[u8]) -> Result<(), AgErr> {
    let even = &code[..code.len() & !1];
    let mut dec = crate::insn::Decoder::new(even);
    for _ in &mut dec {}
    let invalid = dec.invalid;
    if invalid || code.len() % 2 == 1 {
        match dex_bytecode::decode_all_with_resolver(code, 0, &crate::render::AgResolver { dex }) {
            Err(e) => {
                if code.len() % 2 == 1 && e.offset == Some(code.len() - 1) {
                    return Err(AgErr::Struct(2));
                }
                return Err(AgErr::Invalid(e));
            }
            Ok(_) => {
                if code.len() % 2 == 1 {
                    return Err(AgErr::Struct(2));
                }
            }
        }
    }
    Ok(())
}

/// What `create_xref()` raises walking this DEX's instructions, if
/// anything: IndexError('string index out of range') for a const-class /
/// new-instance of a type, or an invoke of a method of a class, whose name
/// is empty once leading '[' are stripped; KeyError for a field, method or
/// string reference without that section.
pub fn xref_error(st: &AgState, dex: &Dex) -> Option<AgErr> {
    if st.no_map {
        return None;
    }
    let data = &dex.data[..];
    // Type names androguard would index with [0] after lstrip('[').
    let empty_type = |t: u32| -> bool {
        let Some(&s) = st.type_ids.get(t as usize) else { return false };
        let Some(&so) = st.string_ids.get(s as usize) else { return false };
        if st.string_data.binary_search(&so).is_err() {
            return false;
        }
        let mut b = Buf::new(data);
        b.seek(so as u64);
        if b.uleb().is_err() {
            return false;
        }
        let p = b.tell() as usize;
        data.get(p..).map(|r| r.iter().take_while(|&&c| c != 0).all(|&c| c == b'[')).unwrap_or(false)
    };
    let bad_types: FxHashSet<u32> = (0..st.type_ids.len() as u32).filter(|&t| empty_type(t)).collect();
    let need_fields = !st.has(FIELD_ID_ITEM);
    let need_strings = !st.has(STRING_ID_ITEM);
    let need_types = !st.has(TYPE_ID_ITEM);
    if bad_types.is_empty() && !need_fields && !need_strings && !need_types {
        return None;
    }
    let mut seen_data = FxHashSet::default();
    let mut done_code = FxHashSet::default();
    for &cd in &st.classes {
        if !st.has_class_data(cd) || !seen_data.insert(cd) {
            continue;
        }
        for (_, code_off) in class_methods(data, cd) {
            if !st.has_code(code_off) || !done_code.insert(code_off) {
                continue;
            }
            let mut buf = Buf::new(data);
            buf.seek(code_off);
            let Ok(rec) = parse_code(&mut buf) else { continue };
            let code = &data[rec.insns.clone()];
            for ins in crate::insn::Decoder::new(&code[..code.len() & !1]) {
                if ins.payload != 0 {
                    continue;
                }
                let e = match ins.op {
                    0x1c | 0x22 if need_types => Some(AgErr::KeyMap(TYPE_ID_ITEM)),
                    0x1c | 0x22 if bad_types.contains(&ins.idx) => Some(AgErr::IndexStr),
                    0x6e..=0x72 | 0x74..=0x78 => {
                        match st.method_classes.get(ins.idx as usize) {
                            Some(&c) if bad_types.contains(&(c as u32)) => Some(AgErr::IndexStr),
                            _ => None,
                        }
                    }
                    0x1a | 0x1b if need_strings => Some(AgErr::KeyMap(STRING_ID_ITEM)),
                    0x52..=0x6d if need_fields => Some(AgErr::KeyMap(FIELD_ID_ITEM)),
                    _ => None,
                };
                if e.is_some() {
                    return e;
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buf_reads_like_bufferedreader() {
        let mut b = Buf::new(b"abcdef");
        b.seek(4);
        assert_eq!(b.read(5), b"ef");
        assert_eq!(b.tell(), 6);
        b.seek(10);
        assert_eq!(b.read(3), b"");
        assert_eq!(b.tell(), 10);
        assert!(matches!(b.unpack(2), Err(AgErr::Struct(2))));
    }
}
