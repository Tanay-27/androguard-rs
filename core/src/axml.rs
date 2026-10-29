//! Binary XML (AXML), read the way androguard 4.1.3's `AXMLParser` reads it:
//! the same chunk walk, the same "dummy data" header scan, the same string
//! pool (`arsc::Pool`, androguard's `StringBlock`), the same attribute-name
//! lookup through the resource map and the system attribute table, and the
//! same failures. `AXMLPrinter`'s tree building (name fixing, `nsmap`, lxml)
//! stays in Python on top of this parser, so it runs androguard's own code
//! paths over exactly the values androguard's parser would produce.
//!
//! Two kinds of failure, as in androguard:
//! - what `AXMLParser` catches (`ResParserError` from a chunk header) makes
//!   the parser invalid: `is_valid()` turns false and the walk stops;
//! - everything else (a short read, which is `struct.error`, a string that
//!   isn't NUL-terminated, a negative read length...) is an `Err`, which is
//!   what androguard raises from `AXMLPrinter(raw)`.
//!
//! The file is untrusted. Every read is bounds-checked, nothing is sized
//! from a declared count, and there are budgets where androguard would run
//! away: the input is capped at `MAX_AXML_BYTES`, the namespace stack at
//! `MAX_NAMESPACES`, the string bytes handed out at `MAX_SERVED_BYTES`, and a
//! chunk that would make androguard loop forever (a header found by scanning
//! whose declared end points back before it) is an error instead of a hang.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};

use crate::arsc::{Cur, Header, Pool, py_decode};
use crate::axml_attrs::SYSTEM_ATTRS;

/// Largest binary XML we parse. Real manifests and layouts are well under
/// 1 MiB; `resources.arsc` gets the same 64 MiB as its XML output cap.
pub const MAX_AXML_BYTES: usize = 64 << 20;
/// Most namespace mappings open at once (real files have one to five).
/// androguard keeps them in a list it scans on every tag.
pub const MAX_NAMESPACES: usize = 1024;
/// Most string bytes one parser hands out (names, values, text; repeats
/// count every time). A few-KiB file can otherwise name one 32 KiB string
/// from millions of attribute slots.
pub const MAX_SERVED_BYTES: usize = 256 << 20;

pub const END_DOCUMENT: i32 = 1;
pub const START_TAG: i32 = 2;
pub const END_TAG: i32 = 3;
pub const TEXT: i32 = 4;

const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const RES_XML_CDATA_TYPE: u16 = 0x0104;
const RES_XML_LAST_CHUNK_TYPE: u16 = 0x017F;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const POSSIBLE_TYPES: [u16; 6] = [256, 257, 258, 259, 260, 384];
const TYPE_STRING: u32 = 0x03;

/// `ARSCHeader(buff, possible_types=...)` failures: `ResParserError`, which
/// `_do_next()` catches, or a short read (`struct.error`), which it doesn't.
enum HdrErr {
    ResParser,
    Fatal(anyhow::Error),
}

/// A chunk header as `_do_next()` sees it: `start` is where the read began
/// (androguard's `h.start`, so `h.end` counts from there) and `found` where
/// the header actually was after skipping "dummy data".
struct Chunk {
    h: Header,
    found: u64,
}

pub struct AxmlParser {
    buf: Vec<u8>,
    pos: u64,
    valid: bool,
    /// androguard's `axml_tampered`: trailing data or an unusual first type.
    pub axml_tampered: bool,
    /// androguard's `AXMLParser.packerwarning` (set by `getAttributeName`).
    pub packerwarning: bool,
    filesize: u64,
    pool: Option<Pool>,
    resource_ids: Vec<u32>,
    namespaces: Vec<(u32, u32)>,
    /// Bumped whenever `namespaces` changes, so callers can cache `nsmap`.
    ns_version: u64,
    event: i32,
    line: i64,
    m_name: i64,
    ns_uri: i64,
    comment_index: Option<u32>,
    attrs: Vec<u32>,
    attr_count: u32,
    id_attr: i64,
    class_attr: i64,
    style_attr: i64,
    cache: HashMap<u32, Arc<str>>,
    served: usize,
}

impl AxmlParser {
    /// `AXMLParser(raw_buff)`. `Err` is what the constructor raises; a file
    /// it rejects quietly comes back with `is_valid() == false`.
    pub fn new(buf: Vec<u8>) -> Result<AxmlParser> {
        if buf.len() > MAX_AXML_BYTES {
            bail!("binary XML is {} bytes, over the {MAX_AXML_BYTES}-byte limit", buf.len());
        }
        let mut p = AxmlParser {
            buf,
            pos: 0,
            valid: true,
            axml_tampered: false,
            packerwarning: false,
            filesize: 0,
            pool: None,
            resource_ids: Vec::new(),
            namespaces: Vec::new(),
            ns_version: 0,
            event: -1,
            line: -1,
            m_name: -1,
            ns_uri: -1,
            comment_index: None,
            attrs: Vec::new(),
            attr_count: 0,
            id_attr: -1,
            class_attr: -1,
            style_attr: -1,
            cache: HashMap::new(),
            served: 0,
        };
        p.init()?;
        Ok(p)
    }

    fn init(&mut self) -> Result<()> {
        let len = self.buf.len() as u64;
        if len < 8 {
            self.valid = false;
            return Ok(());
        }
        let mut cur = Cur { b: &self.buf, pos: 0 };
        let Ok(axml_header) = Header::read(&mut cur, None) else {
            self.valid = false;
            return Ok(());
        };
        self.filesize = axml_header.size as u64;
        if axml_header.header_size != 8 || self.filesize > len {
            self.valid = false;
            return Ok(());
        }
        if self.filesize < len || axml_header.ty != RES_XML_TYPE {
            self.axml_tampered = true;
        }
        let Ok(header) = Header::read(&mut cur, Some(RES_STRING_POOL_TYPE)) else {
            self.valid = false;
            return Ok(());
        };
        if header.header_size != 0x1C {
            self.valid = false;
            return Ok(());
        }
        self.pool = Some(Pool::parse(&mut cur, &header)?);
        self.pos = axml_header.header_size as u64 + header.size as u64;
        Ok(())
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// `self.sb[idx]`: the string, "" for an index out of range, or the
    /// error androguard's `StringBlock` raises.
    pub fn string(&mut self, idx: u32) -> Result<Arc<str>> {
        let Some(pool) = &self.pool else { bail!("'AXMLParser' object has no attribute 'sb'") };
        let Some(offset) = pool.offset_of(&self.buf, idx as i64) else { return Ok(Arc::from("")) };
        let s = match self.cache.get(&offset) {
            Some(s) => s.clone(),
            None => {
                let s: Arc<str> = match pool.locate(&self.buf, idx as i64)? {
                    None => Arc::from(""),
                    Some((utf8, r)) => {
                        // Charged once more here so decoding can't run away either.
                        self.charge(r.len())?;
                        Arc::from(py_decode(&self.buf[r], utf8))
                    }
                };
                self.cache.insert(offset, s.clone());
                s
            }
        };
        self.charge(s.len())?;
        Ok(s)
    }

    fn charge(&mut self, n: usize) -> Result<()> {
        self.served += n;
        if self.served > MAX_SERVED_BYTES {
            bail!("binary XML strings exceed {MAX_SERVED_BYTES} bytes");
        }
        Ok(())
    }

    /// `next(parser)`: advance one event and return it (`m_event`).
    pub fn next_event(&mut self) -> Result<i32> {
        self.do_next()?;
        Ok(self.event)
    }

    fn reset(&mut self) {
        self.event = -1;
        self.line = -1;
        self.m_name = -1;
        self.ns_uri = -1;
        self.attrs.clear();
        self.id_attr = -1;
        self.class_attr = -1;
        self.style_attr = -1;
    }

    /// `ARSCHeader(self.buff, possible_types={256, 257, 258, 259, 260, 384})`.
    fn read_chunk_header(&mut self) -> std::result::Result<Chunk, HdrErr> {
        let start = self.pos;
        let len = self.buf.len() as u64;
        if len < start.saturating_add(8) {
            return Err(HdrErr::ResParser);
        }
        let mut cur_pos = start;
        let (ty, hs, size) = loop {
            let mut cur = Cur { b: &self.buf, pos: cur_pos };
            let raw = match cur.take(8) {
                Ok(r) => r,
                Err(e) => {
                    self.pos = cur.pos;
                    return Err(HdrErr::Fatal(e));
                }
            };
            let ty = u16::from_le_bytes([raw[0], raw[1]]);
            let hs = u16::from_le_bytes([raw[2], raw[3]]);
            let mut size = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
            // A zero-size END_NAMESPACE at the very end (packers).
            if size < 8 && len == cur_pos + hs as u64 + 8 {
                size = 24;
            }
            if cur_pos == 0 || (POSSIBLE_TYPES.contains(&ty) && hs >= 8 && size > 8) {
                break (ty, hs, size);
            }
            // "dummy data between elements": try one byte further.
            cur_pos += 1;
        };
        self.pos = cur_pos + 8;
        if hs < 8 || size < 8 || size < hs as u32 {
            return Err(HdrErr::ResParser);
        }
        Ok(Chunk { h: Header { start, ty, header_size: hs, size }, found: cur_pos })
    }

    /// `self.buff.seek(h.end)`. If the header was found by scanning and its
    /// end lies at or before where it was found, androguard would scan to
    /// the same header again and loop forever; that is an error here.
    fn seek_end(&mut self, c: &Chunk) -> Result<()> {
        let end = c.h.end();
        if end != self.filesize && end <= c.found {
            bail!("AXML chunk at {} ends at {end}, before itself: androguard 4.1.3 loops forever on this file", c.found);
        }
        self.pos = end;
        Ok(())
    }

    fn u32(&mut self) -> Result<u32> {
        let mut cur = Cur { b: &self.buf, pos: self.pos };
        let r = cur.u32();
        self.pos = cur.pos;
        r
    }

    fn u16(&mut self) -> Result<u16> {
        let mut cur = Cur { b: &self.buf, pos: self.pos };
        let r = cur.u16();
        self.pos = cur.pos;
        r
    }

    /// `self.buff.read(n)` whose result is discarded (n may be negative).
    fn skip(&mut self, n: i64) -> Result<()> {
        let mut cur = Cur { b: &self.buf, pos: self.pos };
        match n {
            -1 => {
                cur.take_lenient(u64::MAX);
            }
            n if n < 0 => bail!("read length must be non-negative or -1"),
            n => {
                cur.take_lenient(n as u64);
            }
        }
        self.pos = cur.pos;
        Ok(())
    }

    fn do_next(&mut self) -> Result<()> {
        if self.event == END_DOCUMENT {
            return Ok(());
        }
        self.reset();
        while self.valid {
            if self.pos == self.filesize {
                self.event = END_DOCUMENT;
                break;
            }
            let c = match self.read_chunk_header() {
                Ok(c) => c,
                Err(HdrErr::ResParser) => {
                    self.valid = false;
                    return Ok(());
                }
                Err(HdrErr::Fatal(e)) => return Err(e),
            };
            let h = c.h;
            if h.ty == RES_XML_RESOURCE_MAP_TYPE {
                if h.size < 8 || h.size % 4 != 0 {
                    self.valid = false;
                    return Ok(());
                }
                // Read right after the 8-byte header, whatever header_size says.
                for _ in 0..(h.size - h.header_size as u32) / 4 {
                    let v = self.u32()?;
                    self.resource_ids.push(v);
                }
                continue;
            }
            if !(RES_XML_START_NAMESPACE_TYPE..=RES_XML_LAST_CHUNK_TYPE).contains(&h.ty) {
                self.seek_end(&c)?;
                continue;
            }
            if h.header_size != 0x10 {
                self.seek_end(&c)?;
                continue;
            }
            self.line = self.u32()? as i64;
            let comment = self.u32()?;
            self.comment_index = Some(comment);
            if comment != 0xFFFF_FFFF && (h.ty == RES_XML_START_NAMESPACE_TYPE || h.ty == RES_XML_END_NAMESPACE_TYPE) {
                // androguard formats a warning with it, which decodes it.
                self.string(comment)?;
            }
            match h.ty {
                RES_XML_START_NAMESPACE_TYPE => {
                    let prefix = self.u32()?;
                    let uri = self.u32()?;
                    self.string(prefix)?;
                    self.string(uri)?;
                    if self.namespaces.len() >= MAX_NAMESPACES {
                        bail!("more than {MAX_NAMESPACES} namespace mappings open at once");
                    }
                    self.namespaces.push((prefix, uri));
                    self.ns_version += 1;
                }
                RES_XML_END_NAMESPACE_TYPE => {
                    let prefix = self.u32()?;
                    let uri = self.u32()?;
                    if let Some(i) = self.namespaces.iter().position(|&x| x == (prefix, uri)) {
                        self.namespaces.remove(i);
                        self.ns_version += 1;
                    }
                }
                RES_XML_START_ELEMENT_TYPE => {
                    self.ns_uri = self.u32()? as i64;
                    self.m_name = self.u32()? as i64;
                    let _at_start = self.u16()?;
                    let at_size = self.u16()?;
                    let attribute_count = self.u32()?;
                    let class_attribute = self.u32()?;
                    self.id_attr = (attribute_count >> 16) as i64 - 1;
                    self.attr_count = attribute_count & 0xFFFF;
                    self.style_attr = (class_attribute >> 16) as i64 - 1;
                    self.class_attr = (class_attribute & 0xFFFF) as i64 - 1;
                    for _ in 0..self.attr_count {
                        for _ in 0..5 {
                            let v = self.u32()?;
                            self.attrs.push(v);
                        }
                        if at_size != 20 {
                            self.skip(at_size as i64 - 20)?;
                        }
                    }
                    for i in (3..self.attrs.len()).step_by(5) {
                        self.attrs[i] >>= 24;
                    }
                    self.event = START_TAG;
                    break;
                }
                RES_XML_END_ELEMENT_TYPE => {
                    self.ns_uri = self.u32()? as i64;
                    self.m_name = self.u32()? as i64;
                    self.event = END_TAG;
                    break;
                }
                RES_XML_CDATA_TYPE => {
                    self.m_name = self.u32()? as i64;
                    let mut cur = Cur { b: &self.buf, pos: self.pos };
                    let r = cur.take(8);
                    self.pos = cur.pos;
                    r?;
                    self.event = TEXT;
                    break;
                }
                _ => self.seek_end(&c)?,
            }
        }
        Ok(())
    }

    pub fn event(&self) -> i32 {
        self.event
    }

    pub fn line_number(&self) -> i64 {
        self.line
    }

    /// `parser.name`.
    pub fn name(&mut self) -> Result<Arc<str>> {
        if self.m_name == -1 || (self.event != START_TAG && self.event != END_TAG) {
            return Ok(Arc::from(""));
        }
        self.string(self.m_name as u32)
    }

    /// `parser.comment`: `None` for no comment.
    pub fn comment(&mut self) -> Result<Option<Arc<str>>> {
        match self.comment_index {
            None => bail!("'AXMLParser' object has no attribute 'm_comment_index'"),
            Some(0xFFFF_FFFF) => Ok(None),
            Some(i) => self.string(i).map(Some),
        }
    }

    /// `parser.namespace`.
    pub fn namespace(&mut self) -> Result<Arc<str>> {
        if self.m_name == -1 || (self.event != START_TAG && self.event != END_TAG) || self.ns_uri == 0xFFFF_FFFF {
            return Ok(Arc::from(""));
        }
        self.string(self.ns_uri as u32)
    }

    /// `parser.text`.
    pub fn text(&mut self) -> Result<Arc<str>> {
        if self.m_name == -1 || self.event != TEXT {
            return Ok(Arc::from(""));
        }
        self.string(self.m_name as u32)
    }

    /// `parser.namespaces`: the open (prefix, uri) string-index pairs, in
    /// order. `nsmap` is computed from these by the caller, exactly as
    /// androguard does (it iterates a Python `set` of them).
    pub fn namespaces(&self) -> &[(u32, u32)] {
        &self.namespaces
    }

    pub fn namespaces_version(&self) -> u64 {
        self.ns_version
    }

    pub fn attribute_count(&self) -> i64 {
        if self.event != START_TAG { -1 } else { self.attr_count as i64 }
    }

    fn attr(&self, index: usize, field: usize) -> Result<u32> {
        index
            .checked_mul(5)
            .and_then(|o| self.attrs.get(o + field))
            .copied()
            .ok_or_else(|| anyhow!("list index out of range"))
    }

    /// `getAttributeNamespace(index)`.
    pub fn attribute_namespace(&mut self, index: usize) -> Result<Arc<str>> {
        let uri = self.attr(index, 0)?;
        if uri == 0xFFFF_FFFF {
            return Ok(Arc::from(""));
        }
        self.string(uri)
    }

    /// `getAttributeName(index)`: the pool's name, replaced by the system
    /// attribute's (with `_` turned into `:`) when the resource map names a
    /// known one, and `android:UNKNOWN_SYSTEM_ATTRIBUTE_xxxxxxxx` if that
    /// leaves nothing.
    pub fn attribute_name(&mut self, index: usize) -> Result<String> {
        let name = self.attr(index, 1)?;
        let from_pool = self.string(name)?;
        let mut res: String = from_pool.to_string();
        let mut attr = None;
        if (name as usize) < self.resource_ids.len() {
            let a = self.resource_ids[name as usize];
            attr = Some(a);
            if let Ok(i) = SYSTEM_ATTRS.binary_search_by_key(&a, |x| x.0) {
                res = SYSTEM_ATTRS[i].1.replace('_', ":");
                if *res != *from_pool {
                    self.packerwarning = true;
                }
            }
        }
        if res.is_empty() || res == ":" {
            return match attr {
                Some(a) => Ok(format!("android:UNKNOWN_SYSTEM_ATTRIBUTE_{a:08x}")),
                None => bail!("cannot access local variable 'attr' where it is not associated with a value"),
            };
        }
        Ok(res)
    }

    /// `getAttributeValueType(index)` (the type byte).
    pub fn attribute_value_type(&self, index: usize) -> Result<u32> {
        self.attr(index, 3)
    }

    /// `getAttributeValueData(index)`.
    pub fn attribute_value_data(&self, index: usize) -> Result<u32> {
        self.attr(index, 4)
    }

    /// `getAttributeValue(index)`: the raw string for a string-typed value,
    /// "" otherwise.
    pub fn attribute_value(&mut self, index: usize) -> Result<Arc<str>> {
        if self.attr(index, 3)? == TYPE_STRING {
            let s = self.attr(index, 2)?;
            return self.string(s);
        }
        Ok(Arc::from(""))
    }
}

/// Walk a whole file the way `AXMLPrinter` drives the parser, touching every
/// accessor it uses. For tests and fuzzing: returns the number of events, or
/// the error androguard would raise.
pub fn walk(data: &[u8]) -> Result<usize> {
    let mut p = AxmlParser::new(data.to_vec())?;
    let mut n = 0;
    while p.is_valid() {
        let ev = p.next_event()?;
        n += 1;
        match ev {
            START_TAG => {
                if p.name()?.is_empty() {
                    continue;
                }
                p.namespace()?;
                p.comment()?;
                for &(k, v) in p.namespaces().to_vec().iter() {
                    p.string(k)?;
                    p.string(v)?;
                }
                for i in 0..p.attribute_count().max(0) as usize {
                    p.attribute_namespace(i)?;
                    p.attribute_name(i)?;
                    p.attribute_value_type(i)?;
                    p.attribute_value_data(i)?;
                    p.attribute_value(i)?;
                }
            }
            END_TAG => {
                p.name()?;
                p.namespace()?;
            }
            TEXT => {
                p.text()?;
            }
            END_DOCUMENT => break,
            _ => {}
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(ty: u16, header_size: u16, body: &[u8]) -> Vec<u8> {
        let mut v = ty.to_le_bytes().to_vec();
        v.extend_from_slice(&header_size.to_le_bytes());
        v.extend_from_slice(&((body.len() + 8) as u32).to_le_bytes());
        v.extend_from_slice(body);
        v
    }

    /// A UTF-16 string pool.
    fn pool(strings: &[&str]) -> Vec<u8> {
        let mut data = Vec::new();
        let mut offs = Vec::new();
        for s in strings {
            offs.push(data.len() as u32);
            let u: Vec<u16> = s.encode_utf16().collect();
            data.extend_from_slice(&(u.len() as u16).to_le_bytes());
            for c in u {
                data.extend_from_slice(&c.to_le_bytes());
            }
            data.extend_from_slice(&[0, 0]);
        }
        while data.len() % 4 != 0 {
            data.push(0);
        }
        let strings_start = 28 + 4 * strings.len() as u32;
        let mut body = Vec::new();
        body.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&strings_start.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        for o in offs {
            body.extend_from_slice(&o.to_le_bytes());
        }
        body.extend_from_slice(&data);
        chunk(RES_STRING_POOL_TYPE, 0x1C, &body)
    }

    fn node(ty: u16, fields: &[u32]) -> Vec<u8> {
        let mut body = vec![1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF];
        for f in fields {
            body.extend_from_slice(&f.to_le_bytes());
        }
        chunk(ty, 0x10, &body)
    }

    /// `<manifest xmlns:android=... android:versionCode="7"
    /// package="com.example"><application android:debuggable="true"/></manifest>`
    /// with string 0 ("versionCode") named through the resource map.
    fn manifest() -> Vec<u8> {
        // 0 versionCode, 1 debuggable, 2 android, 3 uri, 4 manifest, 5 package, 6 com.example, 7 application
        let strings = ["versionCode", "debuggable", "android", "http://schemas.android.com/apk/res/android", "manifest", "package", "com.example", "application"];
        let mut body = pool(&strings);
        let mut rm = Vec::new();
        for id in [0x0101021Bu32, 0x0101000F] {
            rm.extend_from_slice(&id.to_le_bytes());
        }
        body.extend(chunk(RES_XML_RESOURCE_MAP_TYPE, 8, &rm));
        body.extend(node(RES_XML_START_NAMESPACE_TYPE, &[2, 3]));
        let mut start = vec![0xFFFF_FFFF, 4, 0x0014_0014, 2, 0];
        start.extend([3, 0, 0xFFFF_FFFF, 0x1000_0008, 7]); // android:versionCode int 7
        start.extend([0xFFFF_FFFF, 5, 6, 0x0300_0008, 6]); // package string
        body.extend(node(RES_XML_START_ELEMENT_TYPE, &start));
        body.extend(node(RES_XML_START_ELEMENT_TYPE, &[0xFFFF_FFFF, 7, 0x0014_0014, 1, 0, 3, 1, 0xFFFF_FFFF, 0x1200_0008, 0xFFFF_FFFF]));
        body.extend(node(RES_XML_END_ELEMENT_TYPE, &[0xFFFF_FFFF, 7]));
        body.extend(node(RES_XML_END_ELEMENT_TYPE, &[0xFFFF_FFFF, 4]));
        body.extend(node(RES_XML_END_NAMESPACE_TYPE, &[2, 3]));
        chunk(RES_XML_TYPE, 8, &body)
    }

    #[test]
    fn parses_a_manifest() {
        let mut p = AxmlParser::new(manifest()).unwrap();
        assert!(p.is_valid());
        assert_eq!(p.next_event().unwrap(), START_TAG);
        assert_eq!(&*p.name().unwrap(), "manifest");
        assert_eq!(&*p.namespace().unwrap(), "");
        assert_eq!(p.namespaces(), &[(2, 3)]);
        assert_eq!(p.attribute_count(), 2);
        assert_eq!(&*p.attribute_namespace(0).unwrap(), "http://schemas.android.com/apk/res/android");
        assert_eq!(p.attribute_name(0).unwrap(), "versionCode");
        assert_eq!((p.attribute_value_type(0).unwrap(), p.attribute_value_data(0).unwrap()), (0x10, 7));
        assert_eq!(p.attribute_name(1).unwrap(), "package");
        assert_eq!(&*p.attribute_value(1).unwrap(), "com.example");
        assert_eq!(p.next_event().unwrap(), START_TAG);
        assert_eq!(p.attribute_name(0).unwrap(), "debuggable");
        assert_eq!((p.attribute_value_type(0).unwrap(), p.attribute_value_data(0).unwrap()), (0x12, 0xFFFF_FFFF));
        assert_eq!(p.next_event().unwrap(), END_TAG);
        assert_eq!(p.next_event().unwrap(), END_TAG);
        assert_eq!(p.next_event().unwrap(), END_DOCUMENT);
        assert!(p.namespaces().is_empty());
        assert_eq!(walk(&manifest()).unwrap(), 5);
    }

    #[test]
    fn system_names_replace_pool_names() {
        // Pool name "layout_width" for 0x010100f4: androguard returns the
        // table's name with '_' turned into ':' and flags a packer.
        let mut b = manifest();
        let i = b.windows(4).position(|w| w == 0x0101021Bu32.to_le_bytes()).unwrap();
        b[i..i + 4].copy_from_slice(&0x010100F4u32.to_le_bytes());
        let mut p = AxmlParser::new(b).unwrap();
        p.next_event().unwrap();
        assert_eq!(p.attribute_name(0).unwrap(), "layout:width");
        assert!(p.packerwarning);
    }

    #[test]
    fn unknown_empty_name_and_unbound_attr() {
        let mut b = manifest();
        // Empty the pool string "versionCode" by setting its length to 0.
        let pool_strings = 8 + 28 + 4 * 8;
        b[pool_strings..pool_strings + 2].copy_from_slice(&[0, 0]);
        b[pool_strings + 2..pool_strings + 4].copy_from_slice(&[0, 0]);
        let i = b.windows(4).position(|w| w == 0x0101021Bu32.to_le_bytes()).unwrap();
        b[i..i + 4].copy_from_slice(&0x7F010000u32.to_le_bytes());
        let mut p = AxmlParser::new(b).unwrap();
        p.next_event().unwrap();
        assert_eq!(p.attribute_name(0).unwrap(), "android:UNKNOWN_SYSTEM_ATTRIBUTE_7f010000");
    }

    #[test]
    fn invalid_headers_make_it_invalid() {
        assert!(!AxmlParser::new(vec![3, 0, 8]).unwrap().is_valid());
        let mut b = manifest();
        b[2] = 9; // header size
        assert!(!AxmlParser::new(b).unwrap().is_valid());
        let mut b = manifest();
        let n = b.len() as u32 + 1;
        b[4..8].copy_from_slice(&n.to_le_bytes()); // declared size past the end
        assert!(!AxmlParser::new(b).unwrap().is_valid());
        // Garbage instead of the string pool header.
        let mut b = manifest();
        b[8] = 7;
        assert!(!AxmlParser::new(b).unwrap().is_valid());
    }

    #[test]
    fn truncation_is_an_error_or_invalid_never_a_panic() {
        let m = manifest();
        for cut in 0..m.len() {
            let mut b = m[..cut].to_vec();
            if b.len() >= 8 {
                let n = b.len() as u32;
                b[4..8].copy_from_slice(&n.to_le_bytes());
            }
            let _ = walk(&b);
        }
        // Every single-byte change too.
        for i in 0..m.len() {
            for v in [0u8, 0x7F, 0xFF] {
                let mut b = m.clone();
                b[i] = v;
                let _ = walk(&b);
            }
        }
    }

    #[test]
    fn dummy_data_between_chunks_is_skipped() {
        let mut b = manifest();
        // Insert 3 junk bytes before the first element chunk.
        let start = b.windows(4).position(|w| w == [0x02, 0x01, 0x10, 0x00]).unwrap();
        b.splice(start..start, [0xAA, 0xBB, 0xCC]);
        let n = b.len() as u32;
        b[4..8].copy_from_slice(&n.to_le_bytes());
        let mut p = AxmlParser::new(b).unwrap();
        assert_eq!(p.next_event().unwrap(), START_TAG);
        assert_eq!(&*p.name().unwrap(), "manifest");
    }

    #[test]
    fn a_chunk_ending_before_itself_is_an_error_not_a_hang() {
        let mut b = manifest();
        let start = b.windows(4).position(|w| w == [0x02, 0x01, 0x10, 0x00]).unwrap();
        // Junk, then an element-typed header whose header size isn't 16:
        // androguard seeks back to start+size and scans to it again forever.
        let mut junk = vec![0xAA; 40];
        junk.extend_from_slice(&[0x02, 0x01, 0x20, 0x00, 0x20, 0x00, 0x00, 0x00]);
        b.splice(start..start, junk);
        let n = b.len() as u32;
        b[4..8].copy_from_slice(&n.to_le_bytes());
        let e = walk(&b).unwrap_err();
        assert!(e.to_string().contains("loops forever"), "{e}");
    }

    #[test]
    fn oversized_input_is_rejected() {
        assert!(AxmlParser::new(vec![0; MAX_AXML_BYTES + 1]).is_err());
    }
}
