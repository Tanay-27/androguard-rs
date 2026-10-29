//! Classes whose methods androguard 4.1.3's object model doesn't map
//! one-to-one onto signatures ("irregular"): a class defined more than once
//! (in one DEX or across DEX files), a class_data shared by several
//! class_defs, a class_data listing a method_id of another class, or one
//! listing the same signature twice. Only crafted or unusual files have
//! them; without any, nothing here is allocated and the index answers by
//! signature alone.
//!
//! What androguard does (analysis.py), and what is kept here to answer the
//! same:
//! - `Analysis.add()` makes, for every class_def `j` in load order, a new
//!   ClassAnalysis (the last of a name wins, at the first one's position)
//!   and a new MethodAnalysis `Own(j, e)` for every EncodedMethod `e` of its
//!   class_data. A class_data shared by several class_defs is the same
//!   EncodedMethods each time. `dx.methods[e]` keeps the last class_def's,
//!   `MA*(e) = Own(L(e), e)`. The table calls resolve through, `H`, is keyed
//!   by (the class_def's name, method name, descriptor): last write wins.
//! - `create_xref()` visits every class_def, and for each invoke in `e`'s
//!   code: creates an ExternalMethod if `H` has no such key; appends `MA*(e)`
//!   to the winner of the class_def's name if it doesn't hold `e` yet
//!   (`add_method_xref_to`), and adds the call to the MethodAnalysis that
//!   winner holds for `e`; appends the resolved callee to the winner of the
//!   callee's class if it doesn't hold that EncodedMethod yet
//!   (`add_method_xref_from`), and adds `(caller's class, MA*(e), offset)`
//!   to the one it holds.
//!
//! So a MethodAnalysis's `get_xref_to()` is its EncodedMethod's calls if any
//! class lists it, else empty; its `get_xref_from()` gathers the calls to
//! every (class, EncodedMethod) slot it is held under; and a call from a
//! shared class_data is reported once per distinct class name using it.
//! The index keeps one node per EncodedMethod with code (its calls) and one
//! per resolved (class, EncodedMethod) slot (the calls to it); `Model`
//! replays which object each class holds, and the queries expand the rest.

use rustc_hash::{FxHashMap, FxHashSet};

use crate::dex::Dex;
use crate::index::sig_hash;

pub const NONE: u32 = u32::MAX;

/// An irregular class_def, in AnalyzeAPK order.
pub struct RDef {
    pub name: u32,
    pub dex: u16,
    pub ci: u32,
    /// Index in `Irr::blocks`, or NONE without class_data.
    pub block: u32,
}

/// A class_data used by irregular class_defs.
pub struct RBlock {
    pub dex: u16,
    pub off: u32,
    /// Its EncodedMethods (direct, then virtual) are `ems[em_start..em_start + em_len]`.
    pub em_start: u32,
    pub em_len: u32,
    /// The last class_def using it: `MA*(e)` is `Own(last_user, e)`.
    pub last_user: u32,
    /// Distinct names of the class_defs using it, in first-use order.
    pub names: Vec<u32>,
    /// `->name(params)ret` hash -> last position with it.
    tails: FxHashMap<u64, u32>,
}

/// An EncodedMethod of an irregular class_data.
pub struct REm {
    pub block: u32,
    pub dex: u16,
    pub midx: u32,
    pub flags: u64,
    pub code_off: u32,
    /// The node holding its calls (index edges from it), or NONE if it has
    /// no code androguard can disassemble.
    pub node: u32,
    /// It makes at least one call create_xref() follows.
    pub calls: bool,
    /// Hash of its method_id's signature, as the index keys methods.
    pub sig: u64,
}

pub struct RName {
    pub hash: u64,
    pub defs: Vec<u32>,
    pub winner: u32,
    /// (block, last class_def of this name using it), latest first: where `H`
    /// lookups for this name look.
    by_last_use: Vec<(u32, u32)>,
}

/// A resolved callee: `H[(name, method)]` is `Own(j, em)`. Calls to it are
/// index edges into `node`.
pub struct Slot {
    pub name: u32,
    pub em: u32,
    pub j: u32,
    pub node: u32,
}

#[derive(Clone, Copy)]
pub enum RNode {
    Em(u32),
    Slot(u32),
}

/// A MethodAnalysis of an irregular class: `Own(j, e)`, as one integer.
pub fn key(j: u32, e: u32) -> u64 {
    (j as u64) << 32 | e as u64
}

pub fn unkey(k: u64) -> (u32, u32) {
    ((k >> 32) as u32, k as u32)
}

#[derive(Default)]
pub struct Irr {
    pub defs: Vec<RDef>,
    pub blocks: Vec<RBlock>,
    pub ems: Vec<REm>,
    pub names: Vec<RName>,
    pub slots: Vec<Slot>,
    name_idx: FxHashMap<u64, u32>,
    /// Per DEX: class_def index -> def.
    def_of: Vec<FxHashMap<u32, u32>>,
    block_of: FxHashMap<(u16, u32), u32>,
    /// Per DEX, per type_idx: an invoke on this type resolves through an
    /// irregular class (its name, '[' stripped), or NONE.
    type_name: Vec<Vec<u32>>,
    slot_of: FxHashMap<(u32, u32), u32>,
    node_kind: FxHashMap<u32, RNode>,
    ems_by_sig: FxHashMap<u64, Vec<u32>>,
    /// Per DEX: method_idx -> resolution of a call to it (see `resolve`).
    resolved: Vec<FxHashMap<u32, Option<u32>>>,
}

/// Hash of `->name(params)ret` of method_id `idx`, or 0 if unreadable.
pub fn tail_hash(dex: &Dex, idx: u32) -> u64 {
    let mut h = std::hash::DefaultHasher::new();
    use std::hash::Hasher;
    match dex.method_tail_parts(idx, &mut |p| h.write(p)) {
        Ok(()) => h.finish().max(1),
        Err(_) => 0,
    }
}

/// Names (descriptor hashes) of the classes in one DEX that make it
/// irregular by themselves: a class_data shared by several class_defs, one
/// listing a method_id of another class, or one listing a signature twice.
/// (A name defined more than once is found from the class lists.)
pub fn flagged(dex: &Dex, classes: &[(u64, u32)], mhash: &[u64]) -> Vec<u64> {
    let mut users: FxHashMap<u32, Vec<u64>> = FxHashMap::default();
    for &(h, ci) in classes {
        let Ok(cd) = dex.class_def(ci as usize) else { continue };
        if dex.has_class_data(cd.class_data_off) {
            users.entry(cd.class_data_off).or_default().push(h);
        }
    }
    let mut out = Vec::new();
    let mut sigs: Vec<u64> = Vec::new();
    for &(h, ci) in classes {
        let Ok(cd) = dex.class_def(ci as usize) else { continue };
        let Some(u) = users.get(&cd.class_data_off) else { continue };
        if u.len() > 1 {
            out.push(h);
            continue;
        }
        let Ok(data) = dex.class_data(cd.class_data_off) else { continue };
        let own = dex.type_desc(cd.class_idx).ok();
        sigs.clear();
        let mut odd = false;
        for m in data.direct_methods.iter().chain(&data.virtual_methods) {
            if let Ok((c, _, _)) = dex.method_id(m.idx)
                && c != cd.class_idx
                && dex.type_desc(c).ok() != own
            {
                odd = true;
                break;
            }
            sigs.push(mhash.get(m.idx as usize).copied().unwrap_or(0));
        }
        if !odd {
            sigs.sort_unstable();
            odd = sigs.windows(2).any(|w| w[0] == w[1] && w[0] != 0);
        }
        if odd {
            out.push(h);
        }
    }
    out
}

impl Irr {
    pub fn active(&self) -> bool {
        !self.defs.is_empty()
    }

    /// The class_defs, blocks and EncodedMethods of the irregular names `r`.
    pub fn build(dexes: &[Dex], class_lists: &[Vec<(u64, u32)>], r: &FxHashSet<u64>) -> Irr {
        let mut irr = Irr { def_of: dexes.iter().map(|_| FxHashMap::default()).collect(), ..Default::default() };
        let mut name_blocks: FxHashSet<(u32, u32)> = FxHashSet::default();
        for (d, list) in class_lists.iter().enumerate() {
            let dex = &dexes[d];
            for &(h, ci) in list {
                if !r.contains(&h) {
                    continue;
                }
                let j = irr.defs.len() as u32;
                let name = *irr.name_idx.entry(h).or_insert_with(|| {
                    irr.names.push(RName { hash: h, defs: Vec::new(), winner: NONE, by_last_use: Vec::new() });
                    (irr.names.len() - 1) as u32
                });
                irr.names[name as usize].defs.push(j);
                irr.names[name as usize].winner = j;
                irr.def_of[d].insert(ci, j);
                let off = dex.class_def(ci as usize).ok().map(|cd| cd.class_data_off).filter(|&o| dex.has_class_data(o));
                let block = match off {
                    None => NONE,
                    Some(off) => match irr.block_of.get(&(d as u16, off)) {
                        Some(&b) => b,
                        None => {
                            let b = irr.blocks.len() as u32;
                            let em_start = irr.ems.len() as u32;
                            let mut tails = FxHashMap::default();
                            if let Ok(data) = dex.class_data(off) {
                                for (pos, m) in data.direct_methods.iter().chain(&data.virtual_methods).enumerate() {
                                    let t = tail_hash(dex, m.idx);
                                    if t != 0 {
                                        tails.insert(t, pos as u32);
                                    }
                                    irr.ems.push(REm {
                                        block: b,
                                        dex: d as u16,
                                        midx: m.idx,
                                        flags: m.access_flags,
                                        code_off: m.code_off,
                                        node: NONE,
                                        calls: false,
                                        sig: 0,
                                    });
                                }
                            }
                            let em_len = irr.ems.len() as u32 - em_start;
                            irr.blocks.push(RBlock { dex: d as u16, off, em_start, em_len, last_user: j, names: Vec::new(), tails });
                            irr.block_of.insert((d as u16, off), b);
                            b
                        }
                    },
                };
                if block != NONE {
                    let blk = &mut irr.blocks[block as usize];
                    blk.last_user = j;
                    if name_blocks.insert((name, block)) {
                        blk.names.push(name);
                    }
                }
                irr.defs.push(RDef { name, dex: d as u16, ci, block });
            }
        }
        for n in &mut irr.names {
            let mut last: FxHashMap<u32, u32> = FxHashMap::default();
            for &j in &n.defs {
                let b = irr.defs[j as usize].block;
                if b != NONE {
                    last.insert(b, j);
                }
            }
            let mut v: Vec<(u32, u32)> = last.into_iter().collect();
            v.sort_unstable_by_key(|&(_, j)| std::cmp::Reverse(j));
            n.by_last_use = v;
        }
        irr.type_name = dexes
            .iter()
            .map(|dex| {
                (0..dex.type_count() as u32)
                    .map(|t| match dex.type_desc(t) {
                        Ok(desc) => {
                            let s = &desc[desc.iter().take_while(|&&c| c == b'[').count()..];
                            irr.name_idx.get(&sig_hash(s)).copied().unwrap_or(NONE)
                        }
                        Err(_) => NONE,
                    })
                    .collect()
            })
            .collect();
        irr.resolved = dexes.iter().map(|_| FxHashMap::default()).collect();
        irr
    }

    pub fn name_of_hash(&self, h: u64) -> Option<u32> {
        self.name_idx.get(&h).copied()
    }

    pub fn def_at(&self, dex: u16, ci: u32) -> Option<u32> {
        self.def_of.get(dex as usize)?.get(&ci).copied()
    }

    pub fn block_at(&self, dex: u16, off: u32) -> Option<u32> {
        self.block_of.get(&(dex, off)).copied()
    }

    /// The winner's class_data of a name, or NONE.
    pub fn winner_block(&self, name: u32) -> u32 {
        self.defs[self.names[name as usize].winner as usize].block
    }

    pub fn em_range(&self, block: u32) -> std::ops::Range<u32> {
        let b = &self.blocks[block as usize];
        b.em_start..b.em_start + b.em_len
    }

    /// `MA*(e)`: dx.methods[e], the last class_def's MethodAnalysis for it.
    pub fn ma_star(&self, e: u32) -> u64 {
        key(self.blocks[self.ems[e as usize].block as usize].last_user, e)
    }

    /// The irregular name an invoke of method_idx `midx` in DEX `d` goes
    /// through (its class, '[' stripped), if any.
    pub fn invoke_name(&self, dexes: &[Dex], d: u16, midx: u32) -> Option<u32> {
        let (c, _, _) = dexes[d as usize].method_id(midx).ok()?;
        let n = *self.type_name.get(d as usize)?.get(c as usize)?;
        (n != NONE).then_some(n)
    }

    /// `H[(name, ->name(params)ret of method_idx)]`: (class_def, EncodedMethod).
    pub fn lookup(&self, name: u32, tail: u64) -> Option<(u32, u32)> {
        if tail == 0 {
            return None;
        }
        for &(b, j) in &self.names[name as usize].by_last_use {
            let blk = &self.blocks[b as usize];
            if let Some(&pos) = blk.tails.get(&tail) {
                return Some((j, blk.em_start + pos));
            }
        }
        None
    }

    /// A call to method_idx `midx` of DEX `d` whose class is irregular:
    /// Some(slot) where it resolves, None where androguard makes an
    /// ExternalMethod. (Calls to other classes aren't asked about.)
    pub fn resolved(&self, d: u16, midx: u32) -> Option<Option<u32>> {
        self.resolved.get(d as usize)?.get(&midx).copied()
    }

    pub fn slot(&self, name: u32, em: u32) -> Option<u32> {
        self.slot_of.get(&(name, em)).copied()
    }

    pub fn node_kind(&self, node: u32) -> Option<RNode> {
        self.node_kind.get(&node).copied()
    }

    pub fn ems_with_sig(&self, sig: u64) -> &[u32] {
        self.ems_by_sig.get(&sig).map(Vec::as_slice).unwrap_or_default()
    }

    /// Resolve (and remember) a call to method_idx `midx` of DEX `d` through
    /// irregular name `name`; a new slot gets its node from `new_node`.
    pub fn resolve_call(
        &mut self,
        dexes: &[Dex],
        d: u16,
        midx: u32,
        name: u32,
        new_node: &mut dyn FnMut(u16, u32) -> u32,
    ) -> Option<u32> {
        if let Some(&r) = self.resolved[d as usize].get(&midx) {
            return r;
        }
        let r = self.lookup(name, tail_hash(&dexes[d as usize], midx)).map(|(j, e)| match self.slot_of.get(&(name, e)) {
            Some(&s) => s,
            None => {
                let em = &self.ems[e as usize];
                let node = new_node(em.dex, em.midx);
                let s = self.slots.len() as u32;
                self.slots.push(Slot { name, em: e, j, node });
                self.slot_of.insert((name, e), s);
                self.node_kind.insert(node, RNode::Slot(s));
                s
            }
        });
        self.resolved[d as usize].insert(midx, r);
        r
    }

    pub fn set_em_node(&mut self, e: u32, node: u32, calls: bool, sig: u64) {
        let em = &mut self.ems[e as usize];
        em.node = node;
        em.calls = calls;
        em.sig = sig;
        self.node_kind.insert(node, RNode::Em(e));
    }

    pub fn set_em_sig(&mut self, e: u32, sig: u64) {
        self.ems[e as usize].sig = sig;
        if sig != 0 {
            self.ems_by_sig.entry(sig).or_default().push(e);
        }
    }

    pub fn bytes(&self) -> usize {
        self.defs.len() * 16
            + self.blocks.iter().map(|b| 48 + b.names.len() * 4 + b.tails.capacity() * 16).sum::<usize>()
            + self.ems.len() * std::mem::size_of::<REm>()
            + self.names.iter().map(|n| 48 + n.defs.len() * 4 + n.by_last_use.len() * 8).sum::<usize>()
            + self.slots.len() * 16
            + (self.slot_of.capacity() + self.node_kind.capacity()) * 16
            + self.type_name.iter().map(|v| v.len() * 4).sum::<usize>()
            + self.resolved.iter().map(|m| m.capacity() * 12).sum::<usize>()
    }
}
