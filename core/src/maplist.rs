//! The DEX map list, read the way androguard 4.1.3 reads it.
//!
//! androguard never follows a raw offset to a code_item, class_data_item,
//! type_list or encoded_array_item. It parses every section the map list
//! declares, item after item from the section start, and later looks
//! offsets up in what it parsed: an offset that isn't the start of one of
//! those items isn't there. This module computes the same sets of item
//! offsets (just the offsets, not the items), with androguard's sizing
//! rules, so lookups agree with it on malformed files too:
//!
//! - code_item (`ClassManager.get_code`): only the *last* CODE_ITEM entry
//!   counts, because `add_type_item` overwrites the section per type.
//!   Undeclared means no code.
//! - class_data_item (`get_class_data_item`): every CLASS_DATA_ITEM entry
//!   adds to one offset table. Undeclared means no methods or fields.
//! - type_list (`get_type_list`): likewise one table for every TYPE_LIST
//!   entry. androguard raises KeyError on an undeclared one.
//! - encoded_array_item (`get_encoded_array_item`): searched in the last
//!   ENCODED_ARRAY_ITEM entry only; with no such entry at all it raises.
//!
//! Where androguard would raise while parsing a section (a short read, an
//! unknown map type), it fails to load the whole DEX. Here the items parsed
//! before that point stay declared and the rest of the section doesn't.

use rustc_hash::FxHashMap;

use crate::dex::{Dex, slice, u16_at, u32_at};

const TYPE_LIST: u16 = 0x1001;
const CLASS_DATA_ITEM: u16 = 0x2000;
const CODE_ITEM: u16 = 0x2001;
const ENCODED_ARRAY_ITEM: u16 = 0x2005;
const ANNOTATIONS_DIRECTORY_ITEM: u16 = 0x2006;

/// Deepest encoded_array/encoded_annotation nesting we follow. androguard
/// recurses in Python and dies with RecursionError (failing the whole DEX)
/// well before this; it only has to keep our own stack bounded.
const MAX_DEPTH: u32 = 1000;

/// Item offsets the map list declares, sorted, per lookup table.
#[derive(Default)]
pub struct Declared {
    code: Vec<u32>,
    class_data: Vec<u32>,
    type_lists: Vec<u32>,
    /// None when the map has no ENCODED_ARRAY_ITEM entry.
    encoded_arrays: Option<Vec<u32>>,
    pub(crate) has_annotations_dir: bool,
}

fn has(v: &[u32], off: u32) -> bool {
    v.binary_search(&off).is_ok()
}

impl Declared {
    pub fn parse(data: &[u8]) -> Declared {
        let mut d = Declared::default();
        let mut by_type: FxHashMap<u16, Vec<(u32, u32)>> = FxHashMap::default();
        let map_off = u32_at(data, 52).unwrap_or(0) as usize;
        if map_off != 0 {
            let n = u32_at(data, map_off).unwrap_or(0) as usize;
            // Each entry is 12 bytes; stop at the first one that runs off the end.
            for i in 0..n {
                let o = map_off + 4 + 12 * i;
                let (Ok(ty), Ok(size), Ok(off)) = (u16_at(data, o), u32_at(data, o + 4), u32_at(data, o + 8)) else {
                    break;
                };
                by_type.entry(ty).or_default().push((size, off));
            }
        }
        let entries = |ty| by_type.get(&ty).map(Vec::as_slice).unwrap_or(&[]);
        d.has_annotations_dir = !entries(ANNOTATIONS_DIRECTORY_ITEM).is_empty();

        // CODE_ITEM: MapItem.parse seeks to `offset + offset % 4` (not an
        // align-up), then CodeItem aligns each item up to 4.
        if let Some(&(size, off)) = entries(CODE_ITEM).last() {
            let start = off as usize + off as usize % 4;
            d.code = walk(data, &[(size, start)], true, code_item_end);
        }
        // TYPE_LIST: same seek, no per-item alignment (each list pads itself).
        let tl: Vec<(u32, usize)> = entries(TYPE_LIST).iter().map(|&(s, o)| (s, o as usize + o as usize % 4)).collect();
        d.type_lists = walk(data, &tl, false, type_list_end);
        let cd: Vec<(u32, usize)> = entries(CLASS_DATA_ITEM).iter().map(|&(s, o)| (s, o as usize)).collect();
        d.class_data = walk(data, &cd, false, class_data_end);
        if let Some(&(size, off)) = entries(ENCODED_ARRAY_ITEM).last() {
            d.encoded_arrays = Some(walk(data, &[(size, off as usize)], false, |b, p| {
                let mut p = p;
                skip_encoded_array(b, &mut p, 0).ok().map(|()| p)
            }));
        }
        d
    }
}

/// Offsets of the items in each (count, start) section, parsed back to back
/// with `end` (None where androguard would raise). Sections are parsed in
/// order and their offsets merged.
///
/// The first item androguard couldn't parse ends the walk for every section
/// of the kind: androguard raises there and loads nothing, so there's no
/// behaviour left to match, and stopping keeps a crafted map from making us
/// re-scan the same bad bytes once per entry.
///
/// A map can also declare many overlapping sections over good bytes. Each
/// item's successor depends only on its own offset, so a walk that reaches
/// an item already reached with at least as many items left would only
/// repeat known work, and stops there. Overlaps can still be arranged to
/// defeat that, so the bytes parsed per kind are capped at twice the file
/// size, which no valid file comes near (its sections don't overlap); past
/// the cap, items count as undeclared.
fn walk(data: &[u8], sections: &[(u32, usize)], align: bool, end: impl Fn(&[u8], usize) -> Option<usize>) -> Vec<u32> {
    let mut out = Vec::new();
    // Only needed when sections can overlap.
    let mut reached: FxHashMap<usize, u32> = FxHashMap::default();
    let mut budget = 2 * data.len();
    'sections: for &(count, start) in sections {
        let mut pos = start;
        for left in (1..=count).rev() {
            if align {
                pos = pos.next_multiple_of(4);
            }
            if sections.len() > 1 {
                match reached.get_mut(&pos) {
                    Some(prev) if *prev >= left => break,
                    Some(prev) => *prev = left,
                    None => {
                        reached.insert(pos, left);
                    }
                }
            }
            if budget == 0 {
                break 'sections;
            }
            let Some(next) = end(data, pos) else { break 'sections };
            budget = budget.saturating_sub(next.saturating_sub(pos));
            if let Ok(o) = u32::try_from(pos) {
                out.push(o);
            }
            pos = next;
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// androguard's readuleb128: at most 5 bytes, the 5th taken whole (so values
/// reach 36 bits), and no error for a 5th byte with its high bit set.
pub(crate) fn ag_uleb128(b: &[u8], pos: &mut usize) -> anyhow::Result<u64> {
    let mut next = || -> anyhow::Result<u64> {
        let v = *b.get(*pos).ok_or_else(|| anyhow::anyhow!("uleb128 out of bounds"))?;
        *pos += 1;
        Ok(v as u64)
    };
    let mut result = next()?;
    if result > 0x7f {
        let mut cur = next()?;
        result = (result & 0x7f) | (cur & 0x7f) << 7;
        if cur > 0x7f {
            cur = next()?;
            result |= (cur & 0x7f) << 14;
            if cur > 0x7f {
                cur = next()?;
                result |= (cur & 0x7f) << 21;
                if cur > 0x7f {
                    result |= next()? << 28;
                }
            }
        }
    }
    Ok(result)
}

/// androguard's readsleb128 (5 bytes at most; sign-extended from 32 bits
/// only when a byte ends the number).
fn ag_sleb128(b: &[u8], pos: &mut usize) -> Option<i64> {
    let mut result: i64 = 0;
    let mut shift = 0;
    for _ in 0..5 {
        let cur = *b.get(*pos)? as i64;
        *pos += 1;
        result |= (cur & 0x7f) << shift;
        shift += 7;
        if cur & 0x80 == 0 {
            let bit_left = 32i64.saturating_sub(shift).max(0);
            result <<= bit_left;
            if result > 0x7fff_ffff {
                result = (0x7fff_ffff & result) - 0x8000_0000;
            }
            return Some(result >> bit_left);
        }
    }
    Some(result)
}

/// End of the DalvikCode at `pos`. Like androguard, the insns read may come
/// up short at the end of the file (the item is still parsed), but the
/// padding, try_items and handlers after it may not.
fn code_item_end(b: &[u8], pos: usize) -> Option<usize> {
    let tries = u16_at(b, pos + 6).ok()? as usize;
    let insns = u32_at(b, pos + 12).ok()? as usize;
    let mut p = pos + 16 + 2 * insns;
    if p > b.len() {
        return if tries == 0 { Some(b.len()) } else { None };
    }
    if tries == 0 {
        return Some(p);
    }
    if insns % 2 == 1 {
        p += 2;
    }
    p += 8 * tries;
    if p > b.len() {
        return None;
    }
    for _ in 0..ag_uleb128(b, &mut p).ok()? {
        let size = ag_sleb128(b, &mut p)?;
        for _ in 0..size.unsigned_abs() {
            ag_uleb128(b, &mut p).ok()?;
            ag_uleb128(b, &mut p).ok()?;
        }
        if size <= 0 {
            ag_uleb128(b, &mut p).ok()?;
        }
    }
    Some(p)
}

fn class_data_end(b: &[u8], pos: usize) -> Option<usize> {
    let mut p = pos;
    let mut sizes = [0u64; 4];
    for s in &mut sizes {
        *s = ag_uleb128(b, &mut p).ok()?;
    }
    for (k, &n) in sizes.iter().enumerate() {
        // Each entry takes at least 2 bytes, so the loop ends by running out.
        for _ in 0..n {
            for _ in 0..if k < 2 { 2 } else { 3 } {
                ag_uleb128(b, &mut p).ok()?;
            }
        }
    }
    Some(p)
}

/// A TypeList: the 2-byte pad after an odd count may be cut short by the
/// end of the file (androguard reads it without unpacking it).
fn type_list_end(b: &[u8], pos: usize) -> Option<usize> {
    let n = u32_at(b, pos).ok()? as usize;
    let end = pos + 4 + 2 * n;
    slice(b, pos, end - pos).ok()?;
    Some(if n % 2 == 1 { (end + 2).min(b.len()) } else { end })
}

/// Skip an encoded_array with androguard's EncodedValue sizing: numeric,
/// string, type, field, method and enum values read `arg + 1` bytes and
/// accept a short read at the end of the file; VALUE_BYTE always reads one
/// byte; unknown types read nothing.
pub(crate) fn skip_encoded_array(b: &[u8], pos: &mut usize, depth: u32) -> anyhow::Result<()> {
    if depth > MAX_DEPTH {
        anyhow::bail!("encoded values nested too deeply");
    }
    for _ in 0..ag_uleb128(b, pos)? {
        skip_encoded_value(b, pos, depth)?;
    }
    Ok(())
}

pub(crate) fn skip_encoded_value(b: &[u8], pos: &mut usize, depth: u32) -> anyhow::Result<()> {
    let header = *b.get(*pos).ok_or_else(|| anyhow::anyhow!("encoded_value out of bounds"))?;
    *pos += 1;
    let arg = (header >> 5) as usize;
    match header & 0x1f {
        0x02..=0x1b => *pos = (*pos + arg + 1).min(b.len().max(*pos)),
        0x1c => skip_encoded_array(b, pos, depth + 1)?,
        0x1d => {
            if depth + 1 > MAX_DEPTH {
                anyhow::bail!("encoded values nested too deeply");
            }
            ag_uleb128(b, pos)?; // type_idx
            for _ in 0..ag_uleb128(b, pos)? {
                ag_uleb128(b, pos)?; // name_idx
                skip_encoded_value(b, pos, depth + 1)?;
            }
        }
        0x00 => {
            slice(b, *pos, 1)?;
            *pos += 1;
        }
        _ => {}
    }
    Ok(())
}

impl Dex {
    /// Whether androguard has a code_item at `off` (`ClassManager.get_code`).
    pub fn has_code_item(&self, off: u32) -> bool {
        has(&self.declared.code, off)
    }

    /// Whether a class_def's class_data_off gives it a class_data_item:
    /// nonzero and declared (else androguard shows no methods or fields).
    pub fn has_class_data(&self, off: u32) -> bool {
        off != 0 && has(&self.declared.class_data, off)
    }

    /// Whether `get_type_list(off)` succeeds: 0 (empty) or a declared type_list.
    pub fn type_list_declared(&self, off: u32) -> bool {
        off == 0 || has(&self.declared.type_lists, off)
    }

    /// `get_encoded_array_item(off)`: Some(found), or None when the map has
    /// no ENCODED_ARRAY_ITEM section (androguard raises KeyError).
    pub fn encoded_array_declared(&self, off: u32) -> Option<bool> {
        self.declared.encoded_arrays.as_deref().map(|v| has(v, off))
    }
}
