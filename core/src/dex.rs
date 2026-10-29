//! Minimal DEX reader: just the id tables, class_data and code_item.
//!
//! Nothing here builds per-instruction or per-string objects. Strings, type
//! names and code are read in place from the DEX bytes on demand. Every read
//! from the (untrusted) input is bounds-checked and returns an error instead
//! of panicking.

use anyhow::{Result, anyhow, bail};

pub struct Dex {
    pub data: Vec<u8>,
    string_ids: Table,
    type_ids: Table,
    proto_ids: Table,
    field_ids: Table,
    method_ids: Table,
    class_defs: Table,
    /// Item offsets the map list declares (see maplist.rs).
    pub(crate) declared: crate::maplist::Declared,
    /// class_info results shared between class_defs (see classes.rs).
    pub(crate) memo: crate::classes::Memo,
}

#[derive(Clone, Copy)]
struct Table {
    off: usize,
    size: usize,
}

/// One method that has code, as listed in a class_def's class_data.
#[derive(Clone, Copy)]
pub struct MethodDef {
    pub method_idx: u32,
    pub code_off: u32,
}

pub struct ClassDef {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

/// A field or method entry of a class_data_item (code_off is 0 for fields).
/// androguard's ulebs reach 36 bits: an idx or code_off past u32 is stored
/// as u32::MAX, which never resolves, as in androguard.
#[derive(Clone, Copy)]
pub struct Member {
    pub idx: u32,
    pub access_flags: u64,
    pub code_off: u32,
    /// code_off as read (androguard's `get_code_off()`, up to 36 bits).
    pub code_off_raw: u64,
}

pub struct ClassData {
    pub static_fields: Vec<Member>,
    pub instance_fields: Vec<Member>,
    pub direct_methods: Vec<Member>,
    pub virtual_methods: Vec<Member>,
}

#[inline]
pub fn slice(b: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    off.checked_add(len)
        .and_then(|end| b.get(off..end))
        .ok_or_else(|| anyhow!("read of {len} bytes at {off:#x} is out of bounds"))
}

#[inline]
pub fn u16_at(b: &[u8], off: usize) -> Result<u16> {
    let s = slice(b, off, 2)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
pub fn u32_at(b: &[u8], off: usize) -> Result<u32> {
    let s = slice(b, off, 4)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Decode a uleb128 at `*pos`, advancing it. At most 5 bytes, per the spec.
pub fn uleb128(b: &[u8], pos: &mut usize) -> Result<u32> {
    let mut result: u32 = 0;
    for i in 0..5 {
        let byte = *b.get(*pos).ok_or_else(|| anyhow!("uleb128 out of bounds"))?;
        *pos += 1;
        result |= ((byte & 0x7f) as u32) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok(result);
        }
    }
    bail!("uleb128 longer than 5 bytes")
}

impl Dex {
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        // "dex\n" or "dey\n", as androguard's HeaderItem accepts (it also
        // wants a NUL at 7; `apk::androguard_header_check` makes that check).
        let magic = slice(&data, 0, 4)?;
        if &magic[..2] != b"de" || !matches!(magic[2], b'x' | b'y') || magic[3] != b'\n' {
            bail!("not a DEX file");
        }
        let table = |size_at: usize, entry: usize| -> Result<Table> {
            let size = u32_at(&data, size_at)? as usize;
            let off = u32_at(&data, size_at + 4)? as usize;
            // Validate the whole table up front so per-entry reads can't run off the end.
            slice(&data, off, size.checked_mul(entry).ok_or_else(|| anyhow!("table size overflow"))?)?;
            Ok(Table { off, size })
        };
        let mut dex = Dex {
            string_ids: table(56, 4)?,
            type_ids: table(64, 4)?,
            proto_ids: table(72, 12)?,
            field_ids: table(80, 8)?,
            method_ids: table(88, 8)?,
            class_defs: table(96, 32)?,
            declared: crate::maplist::Declared::parse(&data),
            memo: Default::default(),
            data,
        };
        dex.memo = crate::classes::Memo::build(&dex);
        Ok(dex)
    }

    pub(crate) fn table_type_ids(&self) -> (usize, usize) {
        (self.type_ids.off, self.type_ids.size)
    }

    pub(crate) fn table_proto_ids(&self) -> (usize, usize) {
        (self.proto_ids.off, self.proto_ids.size)
    }

    pub(crate) fn table_field_ids(&self) -> (usize, usize) {
        (self.field_ids.off, self.field_ids.size)
    }

    pub fn method_count(&self) -> usize {
        self.method_ids.size
    }

    pub fn type_count(&self) -> usize {
        self.type_ids.size
    }

    pub fn string_count(&self) -> usize {
        self.string_ids.size
    }

    pub fn class_count(&self) -> usize {
        self.class_defs.size
    }

    /// Raw MUTF-8 bytes of string `idx`, read in place.
    pub fn string(&self, idx: u32) -> Result<&[u8]> {
        if idx as usize >= self.string_ids.size {
            bail!("string idx {idx} out of range");
        }
        let mut pos = u32_at(&self.data, self.string_ids.off + 4 * idx as usize)? as usize;
        uleb128(&self.data, &mut pos)?; // utf16 length, unused
        let rest = self.data.get(pos..).ok_or_else(|| anyhow!("string data out of bounds"))?;
        let len = memchr::memchr(0, rest).ok_or_else(|| anyhow!("unterminated string"))?;
        Ok(&rest[..len])
    }

    pub fn type_desc(&self, idx: u32) -> Result<&[u8]> {
        if idx as usize >= self.type_ids.size {
            bail!("type idx {idx} out of range");
        }
        self.string(u32_at(&self.data, self.type_ids.off + 4 * idx as usize)?)
    }

    /// (class_idx, proto_idx, name_idx) of method_ids[idx].
    pub fn method_id(&self, idx: u32) -> Result<(u32, u32, u32)> {
        if idx as usize >= self.method_ids.size {
            bail!("method idx {idx} out of range");
        }
        let o = self.method_ids.off + 8 * idx as usize;
        Ok((
            u16_at(&self.data, o)? as u32,
            u16_at(&self.data, o + 2)? as u32,
            u32_at(&self.data, o + 4)?,
        ))
    }

    /// Calls `f` with each byte chunk of the method's signature
    /// `Lcls;->name(params)ret`, without allocating. Used both to render it
    /// and to hash it, so the two can never disagree.
    pub fn method_sig_parts(&self, idx: u32, f: &mut dyn FnMut(&[u8])) -> Result<()> {
        let (class_idx, proto_idx, name_idx) = self.method_id(idx)?;
        // androguard keys array-receiver calls (e.g. [Lfoo;->clone) on the
        // element class name with the '[' stripped; match its identity.
        let cls = self.type_desc(class_idx)?;
        f(&cls[cls.iter().take_while(|&&c| c == b'[').count()..]);
        self.tail_parts(proto_idx, name_idx, f)
    }

    /// The part of `method_sig_parts` after the class: `->name(params)ret`.
    pub fn method_tail_parts(&self, idx: u32, f: &mut dyn FnMut(&[u8])) -> Result<()> {
        let (_, proto_idx, name_idx) = self.method_id(idx)?;
        self.tail_parts(proto_idx, name_idx, f)
    }

    fn tail_parts(&self, proto_idx: u32, name_idx: u32, f: &mut dyn FnMut(&[u8])) -> Result<()> {
        f(b"->");
        f(self.string(name_idx)?);
        f(b"(");
        if proto_idx as usize >= self.proto_ids.size {
            bail!("proto idx {proto_idx} out of range");
        }
        let po = self.proto_ids.off + 12 * proto_idx as usize;
        let ret_idx = u32_at(&self.data, po + 4)?;
        for t in self.type_list(u32_at(&self.data, po + 8)?)? {
            f(self.type_desc(t)?);
        }
        f(b")");
        f(self.type_desc(ret_idx)?);
        Ok(())
    }

    pub fn method_sig(&self, idx: u32) -> Result<String> {
        let mut out = Vec::new();
        self.method_sig_parts(idx, &mut |p| out.extend_from_slice(p))?;
        Ok(crate::render::mutf8_decode(&out).unwrap_or_else(|| String::from_utf8_lossy(&out).into_owned()))
    }

    /// Class descriptor of the method's declaring class (as referenced).
    pub fn method_class_desc(&self, idx: u32) -> Result<&[u8]> {
        self.type_desc(self.method_id(idx)?.0)
    }

    /// Every method with code, across all class_defs, in class_def order.
    ///
    /// Each class_data_item is read once and each method_idx kept once (first
    /// wins). A valid DEX never shares either, but a hostile one can point
    /// thousands of class_defs at one large class_data and turn a few MB into
    /// billions of entries; this keeps the result bounded by the file itself.
    pub fn methods_with_code(&self) -> Result<Vec<MethodDef>> {
        self.methods_with_code_except(|_| false)
    }

    /// `methods_with_code()`, leaving out the class_defs `skip` names.
    pub fn methods_with_code_except(&self, skip: impl Fn(usize) -> bool) -> Result<Vec<MethodDef>> {
        let mut out: Vec<MethodDef> = Vec::new();
        let mut seen_data = rustc_hash::FxHashSet::default();
        // Position in `out` of each method_idx already seen. A repeat keeps
        // the first position but takes the later definition, like the
        // androguard dicts it mirrors (only a hostile DEX repeats one).
        let mut slot: Vec<u32> = vec![u32::MAX; self.method_ids.size];
        for c in 0..self.class_defs.size {
            if skip(c) {
                continue;
            }
            let cd = self.class_def(c)?;
            if !self.has_class_data(cd.class_data_off) || !seen_data.insert(cd.class_data_off) {
                continue;
            }
            let data = self.class_data(cd.class_data_off)?;
            for m in data.direct_methods.iter().chain(&data.virtual_methods) {
                let Some(pos) = slot.get_mut(m.idx as usize) else { continue };
                if !self.has_code_item(m.code_off) {
                    continue;
                }
                let def = MethodDef { method_idx: m.idx, code_off: m.code_off };
                if *pos == u32::MAX {
                    *pos = out.len() as u32;
                    out.push(def);
                } else {
                    out[*pos as usize] = def;
                }
            }
        }
        Ok(out)
    }

    pub fn class_def(&self, i: usize) -> Result<ClassDef> {
        if i >= self.class_defs.size {
            bail!("class_def {i} out of range");
        }
        let o = self.class_defs.off + 32 * i;
        let w = |k: usize| u32_at(&self.data, o + 4 * k);
        Ok(ClassDef {
            class_idx: w(0)?,
            access_flags: w(1)?,
            superclass_idx: w(2)?,
            interfaces_off: w(3)?,
            annotations_off: w(5)?,
            class_data_off: w(6)?,
            static_values_off: w(7)?,
        })
    }

    /// Parse a class_data_item, as androguard does (its uleb128 reader, and
    /// each of the four lists delta-encoded from 0). Callers check
    /// `has_class_data` first: androguard only parses declared ones.
    pub fn class_data(&self, off: u32) -> Result<ClassData> {
        use crate::maplist::ag_uleb128;
        let b = &self.data;
        let mut pos = off as usize;
        let sizes = [
            ag_uleb128(b, &mut pos)?,
            ag_uleb128(b, &mut pos)?,
            ag_uleb128(b, &mut pos)?,
            ag_uleb128(b, &mut pos)?,
        ];
        let narrow = |v: u64| u32::try_from(v).unwrap_or(u32::MAX);
        let mut lists: [Vec<Member>; 4] = Default::default();
        for (k, &n) in sizes.iter().enumerate() {
            let mut idx: u64 = 0;
            // Every entry takes at least 2 bytes, so a bad count runs out of
            // input (an error) after at most data.len() / 2 entries.
            for _ in 0..n {
                idx = idx.saturating_add(ag_uleb128(b, &mut pos)?);
                let access_flags = ag_uleb128(b, &mut pos)?;
                let code_off_raw = if k >= 2 { ag_uleb128(b, &mut pos)? } else { 0 };
                lists[k].push(Member { idx: narrow(idx), access_flags, code_off: narrow(code_off_raw), code_off_raw });
            }
        }
        let [static_fields, instance_fields, direct_methods, virtual_methods] = lists;
        Ok(ClassData { static_fields, instance_fields, direct_methods, virtual_methods })
    }

    /// Type indices of a type_list (e.g. a class's interfaces); empty for
    /// offset 0. An offset the map doesn't declare is an error, where
    /// androguard raises KeyError.
    pub fn type_list(&self, off: u32) -> Result<Vec<u32>> {
        if off == 0 {
            return Ok(Vec::new());
        }
        if !self.type_list_declared(off) {
            bail!("type_list at {off:#x} is not declared in the map list");
        }
        let n = u32_at(&self.data, off as usize)? as usize;
        (0..n).map(|i| Ok(u16_at(&self.data, off as usize + 4 + 2 * i)? as u32)).collect()
    }

    /// registers_size of the code_item at `code_off` (androguard's
    /// `DalvikCode.get_registers_size()`), if the map declares one there.
    pub fn registers_size(&self, code_off: u32) -> Option<u16> {
        if !self.has_code_item(code_off) {
            return None;
        }
        u16_at(&self.data, code_off as usize).ok()
    }

    /// The instruction bytes (insns) of the code_item at `code_off`, if the
    /// map declares one there (androguard sees no code otherwise).
    pub fn code(&self, code_off: u32) -> Result<&[u8]> {
        if !self.has_code_item(code_off) {
            bail!("no code_item declared at {code_off:#x}");
        }
        let o = code_off as usize;
        let insns_units = u32_at(&self.data, o + 12)? as usize;
        slice(&self.data, o + 16, insns_units.checked_mul(2).ok_or_else(|| anyhow!("insns overflow"))?)
    }
}
