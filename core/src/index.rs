//! Whole-APK cross-reference index.
//!
//! Each DEX is scanned independently (in parallel) into flat integer edges,
//! then merged into one method table keyed by a 64-bit hash of
//! `Lcls;->name(params)ret` — the same identity androguard's _resolve_method
//! uses, so a call into another DEX resolves to the same method. Edges live
//! in two CSR arrays (by caller, by callee); nothing per-instruction is kept.

use std::hash::{DefaultHasher, Hasher};
use std::sync::{Arc, OnceLock};

use anyhow::Result;
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::dex::Dex;
use crate::irregular::{self, Irr, NONE};
use crate::render::{AgResolver, py_lower};
use crate::insn::{Decoder, Ref};

#[derive(Default, Clone, Copy, Debug)]
pub struct Stats {
    pub classes: u64,
    pub methods_with_code: u64,
    pub instructions: u64,
    pub payloads: u64,
    pub truncated_methods: u64,
    /// Methods androguard 4.1.3 would reject as invalid bytecode (no xrefs).
    pub invalid_methods: u64,
    pub bad_method_refs: u64,
    pub invoke_edges: u64,
    pub string_refs: u64,
    pub field_refs: u64,
    pub type_refs: u64,
}

impl Stats {
    fn add(&mut self, o: &Stats) {
        self.classes += o.classes;
        self.methods_with_code += o.methods_with_code;
        self.instructions += o.instructions;
        self.payloads += o.payloads;
        self.truncated_methods += o.truncated_methods;
        self.invalid_methods += o.invalid_methods;
        self.bad_method_refs += o.bad_method_refs;
        self.invoke_edges += o.invoke_edges;
        self.string_refs += o.string_refs;
        self.field_refs += o.field_refs;
        self.type_refs += o.type_refs;
    }
}

/// One DEX's contribution, in that DEX's own method_idx space.
struct DexScan {
    /// Signature hash per method_idx; 0 if the method_id is unreadable or
    /// its class isn't an object type (androguard skips those calls too).
    mhash: Vec<u64>,
    /// (method_idx, code_off) of each method with code.
    defs: Vec<(u32, u32)>,
    /// (caller method_idx, callee method_idx, byte offset)
    edges: Vec<[u32; 3]>,
    /// (string_idx, caller method_idx), sorted by string_idx.
    string_refs: Vec<[u32; 2]>,
    stats: Stats,
}

/// How a `search_instruction_text` hit (or a get_methods() row) names its
/// MethodAnalysis beyond its signature: not at all (a regular class), by
/// its EncodedMethod (an irregular class's own method, completed by the
/// class it is listed under), or as a whole irregular key.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HitKey {
    Sig,
    Pos(u32),
    Full(u64),
}

/// A stretch of what create_xref() appended to an irregular class's
/// get_methods(): (EncodedMethod, key) entries, or every calling method of
/// a class_data (`Index::run_ems`), as `MA*(e)`, which several classes can
/// share.
#[derive(Clone, Debug, PartialEq)]
pub enum TailSeg {
    Ems(Vec<(u32, u64)>),
    Block(u32),
}

/// A `search_instruction_text` hit: (signature, key).
pub type Hit = (String, HitKey);

/// A class's (dex, class_def) and its `search_instruction_text` hits, in chunks.
pub type ClassHits = ((u16, u32), Vec<Arc<Vec<Hit>>>);

/// What a method key resolves to: a node (gid), or an irregular key.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Resolved {
    Node(u32),
    Key(u64),
}

pub fn sig_hash(bytes: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    h.write(bytes);
    h.finish()
}

/// Whether the text androguard gives string `sidx` contains the needle.
fn string_text_contains(dex: &Dex, sidx: u32, finder: &memchr::memmem::Finder<'_>) -> bool {
    match dex.string(sidx) {
        // ASCII without NUL decodes to itself.
        Ok(raw) if raw.iter().all(|&c| c != 0 && c < 0x80) => finder.find(raw).is_some(),
        _ => finder.find(&crate::render::wtf8(&AgResolver { dex }.string(sidx))).is_some(),
    }
}

fn method_hash(dex: &Dex, idx: u32) -> u64 {
    let Ok(cls) = dex.method_class_desc(idx) else { return 0 };
    if cls.iter().find(|&&c| c != b'[') != Some(&b'L') {
        return 0;
    }
    let mut h = DefaultHasher::new();
    match dex.method_sig_parts(idx, &mut |p| h.write(p)) {
        Ok(()) => h.finish().max(1),
        Err(_) => 0,
    }
}

/// The class_defs of one DEX as (hash of class descriptor, class_def index).
fn class_list(dex: &Dex) -> Vec<(u64, u32)> {
    (0..dex.class_count())
        .filter_map(|i| {
            let cd = dex.class_def(i).ok()?;
            Some((sig_hash(dex.type_desc(cd.class_idx).ok()?), i as u32))
        })
        .collect()
}

/// One method's share of androguard's create_xref(): its invoke edges
/// ([caller, callee method_idx, byte offset]) and const-string refs
/// ([string_idx, caller]), appended only if androguard would accept the
/// bytecode (a rejected method has no instructions, hence no xrefs).
fn scan_code(
    code: &[u8],
    caller: u32,
    n_strings: usize,
    mhash: &[u64],
    edges: &mut Vec<[u32; 3]>,
    string_refs: &mut Vec<[u32; 2]>,
    stats: &mut Stats,
) {
    let (edges_start, strings_start) = (edges.len(), string_refs.len());
    let mut s = Stats::default();
    let mut dec = Decoder::new(code);
    for ins in &mut dec {
        s.instructions += 1;
        if ins.payload != 0 {
            s.payloads += 1;
            continue;
        }
        match ins.kind {
            // androguard only xrefs invoke-{virtual..interface}[/range], not
            // invoke-polymorphic/custom; match it for parity.
            Ref::Method if matches!(ins.op, 0x6e..=0x72 | 0x74..=0x78) => match mhash.get(ins.idx as usize) {
                Some(&h) if h != 0 => {
                    edges.push([caller, ins.idx, ins.off]);
                    s.invoke_edges += 1;
                }
                Some(_) => {}
                None => s.bad_method_refs += 1,
            },
            Ref::String => {
                // const-string/jumbo's index is signed in androguard (see
                // render::signed_string_index): the string its create_xref()
                // records the use of.
                let sidx = if ins.op == 0x1b { crate::render::signed_string_index(ins.idx, n_strings) } else { ins.idx };
                string_refs.push([sidx, caller]);
                s.string_refs += 1;
            }
            Ref::Field => s.field_refs += 1,
            Ref::Type => s.type_refs += 1,
            _ => {}
        }
    }
    if dec.invalid {
        edges.truncate(edges_start);
        string_refs.truncate(strings_start);
        stats.invalid_methods += 1;
        return;
    }
    stats.add(&s);
    if dec.truncated {
        stats.truncated_methods += 1;
    }
}

/// Every method with code outside the class_defs in `skip` (those of
/// irregular classes, which `scan_irregular` handles).
fn scan(dex: &Dex, skip: &FxHashSet<u32>, mhash: Vec<u64>) -> Result<DexScan> {
    let mut stats = Stats { classes: dex.class_count() as u64, ..Default::default() };
    let mut defs = Vec::new();
    let mut edges = Vec::new();
    let mut string_refs = Vec::new();

    for m in dex.methods_with_code_except(|c| skip.contains(&(c as u32)))? {
        // A class_data entry naming a method_id that doesn't exist or can't
        // be read (only in a corrupt/hostile DEX): skip it, so every method
        // index recorded below is guaranteed to resolve.
        if mhash.get(m.method_idx as usize).is_none_or(|&h| h == 0) {
            stats.bad_method_refs += 1;
            continue;
        }
        let Ok(code) = dex.code(m.code_off) else {
            stats.truncated_methods += 1;
            continue;
        };
        defs.push((m.method_idx, m.code_off));
        stats.methods_with_code += 1;
        scan_code(code, m.method_idx, dex.string_count(), &mhash, &mut edges, &mut string_refs, &mut stats);
    }
    string_refs.sort_unstable();
    Ok(DexScan { mhash, defs, edges, string_refs, stats })
}

/// The global method table: signature hash -> gid, and per node what to
/// render it from and where its code is. Nodes past the signatures are an
/// earlier definition's methods that a later definition overrides.
struct Gids {
    map: FxHashMap<u64, u32>,
    rep: Vec<(u16, u32)>,
    def: Vec<Option<(u16, u32)>>,
}

impl Gids {
    fn get(&mut self, h: u64, dex: u16, midx: u32) -> u32 {
        *self.map.entry(h).or_insert_with(|| {
            self.rep.push((dex, midx));
            self.def.push(None);
            (self.rep.len() - 1) as u32
        })
    }

    fn node(&mut self, dex: u16, midx: u32, def: Option<(u16, u32)>) -> u32 {
        self.rep.push((dex, midx));
        self.def.push(def);
        (self.rep.len() - 1) as u32
    }
}

/// The node a call to method_idx `callee` of DEX `d` goes to: an
/// irregular slot where its class is irregular and `H` has the method,
/// else the signature's gid (an ExternalMethod if nothing defines it).
fn callee_node(dexes: &[Dex], irr: &mut Irr, g: &mut Gids, mhash: &[u64], d: u16, callee: u32) -> u32 {
    if irr.active()
        && let Some(name) = irr.invoke_name(dexes, d, callee)
        && let Some(s) = irr.resolve_call(dexes, d, callee, name, &mut |dd, m| g.node(dd, m, None))
    {
        return irr.slots[s as usize].node;
    }
    g.get(mhash[callee as usize], d, callee)
}

/// create_xref() over the irregular classes' class_data, each once: a node
/// per EncodedMethod with code, holding its calls (see `irregular`).
fn scan_irregular(
    dexes: &[Dex],
    scans: &[DexScan],
    irr: &mut Irr,
    g: &mut Gids,
    edges: &mut Vec<[u32; 3]>,
    strings: &mut [Vec<[u32; 2]>],
    stats: &mut Stats,
) {
    let mut local = Vec::new();
    for e in 0..irr.ems.len() as u32 {
        let (d, midx, code_off) = {
            let em = &irr.ems[e as usize];
            (em.dex, em.midx, em.code_off)
        };
        let dex = &dexes[d as usize];
        let mhash = &scans[d as usize].mhash;
        let sig = mhash.get(midx as usize).copied().unwrap_or(0);
        irr.set_em_sig(e, sig);
        if !dex.has_code_item(code_off) {
            continue;
        }
        let Ok(code) = dex.code(code_off) else {
            stats.truncated_methods += 1;
            continue;
        };
        stats.methods_with_code += 1;
        let node = g.node(d, midx, Some((d, code_off)));
        local.clear();
        scan_code(code, node, dex.string_count(), mhash, &mut local, &mut strings[d as usize], stats);
        irr.set_em_node(e, node, !local.is_empty(), sig);
        for &[caller, callee, off] in &local {
            let ge = callee_node(dexes, irr, g, mhash, d, callee);
            edges.push([caller, ge, off]);
        }
    }
}

/// Compressed sparse rows: neighbours of node `n` are `items[off[n]..off[n+1]]`.
pub struct Csr {
    off: Vec<u32>,
    items: Vec<[u32; 2]>,
}

impl Csr {
    fn build(n: usize, edges: &[[u32; 3]], key: usize, other: usize) -> Csr {
        let mut off = vec![0u32; n + 1];
        for e in edges {
            off[e[key] as usize + 1] += 1;
        }
        for i in 0..n {
            off[i + 1] += off[i];
        }
        let mut fill = off.clone();
        let mut items = vec![[0u32; 2]; edges.len()];
        for e in edges {
            let slot = &mut fill[e[key] as usize];
            items[*slot as usize] = [e[other], e[2]];
            *slot += 1;
        }
        Csr { off, items }
    }

    /// (neighbour gid, byte offset) pairs.
    pub fn get(&self, n: u32) -> &[[u32; 2]] {
        &self.items[self.off[n as usize] as usize..self.off[n as usize + 1] as usize]
    }

    fn bytes(&self) -> usize {
        self.off.len() * 4 + self.items.len() * 8
    }
}

pub struct Index {
    pub dexes: Vec<Dex>,
    sig_to_gid: FxHashMap<u64, u32>,
    /// (dex number, method_idx) to render each node from.
    rep: Vec<(u16, u32)>,
    /// Where each node's code lives: (dex number, code_off), or None for a
    /// method only ever referenced (external) or without code. A
    /// signature's gid stands for its last definition, as androguard's
    /// method-hash table (overwritten by each later class_def) resolves
    /// calls; irregular classes (see `irregular`) have nodes of their own.
    def: Vec<Option<(u16, u32)>>,
    /// Class descriptor hash -> (dex number, class_def index); last wins.
    class_defs: FxHashMap<u64, (u16, u32)>,
    /// Classes in androguard's dx.get_classes() order: first appearance of
    /// each name (dict insertion order), pointing at its last definition.
    class_order: Vec<u64>,
    pub irr: Irr,
    callees: Csr,
    callers: Csr,
    string_refs: Vec<Vec<[u32; 2]>>,
    pub stats: Stats,
}

impl Index {
    pub fn build(dexes: Vec<Dex>) -> Result<Index> {
        let class_lists: Vec<Vec<(u64, u32)>> = dexes.par_iter().map(class_list).collect();
        let mhashes: Vec<Vec<u64>> =
            dexes.par_iter().map(|dex| (0..dex.method_count() as u32).map(|i| method_hash(dex, i)).collect()).collect();
        let mut class_defs: FxHashMap<u64, (u16, u32)> = FxHashMap::default();
        let mut class_order: Vec<u64> = Vec::new();
        let mut irregular: FxHashSet<u64> = FxHashSet::default();
        for (d, list) in class_lists.iter().enumerate() {
            for &(h, ci) in list {
                if class_defs.insert(h, (d as u16, ci)).is_none() {
                    class_order.push(h);
                } else {
                    irregular.insert(h);
                }
            }
        }
        let flagged: Vec<Vec<u64>> = dexes
            .par_iter()
            .zip(&class_lists)
            .zip(&mhashes)
            .map(|((dex, list), mhash)| irregular::flagged(dex, list, mhash))
            .collect();
        irregular.extend(flagged.into_iter().flatten());
        let mut irr = if irregular.is_empty() { Irr::default() } else { Irr::build(&dexes, &class_lists, &irregular) };
        // Irregular classes are scanned apart, per class_data (scan_irregular).
        let skip: Vec<FxHashSet<u32>> = class_lists
            .iter()
            .map(|l| l.iter().filter(|(h, _)| irregular.contains(h)).map(|&(_, ci)| ci).collect())
            .collect();
        let scans: Vec<DexScan> = dexes
            .par_iter()
            .zip(&skip)
            .zip(mhashes)
            .map(|((dex, skip), mhash)| scan(dex, skip, mhash))
            .collect::<Result<_>>()?;
        drop(skip);

        let mut g = Gids { map: FxHashMap::default(), rep: Vec::new(), def: Vec::new() };
        let mut stats = Stats::default();
        let n_edges: usize = scans.iter().map(|s| s.edges.len()).sum();
        let mut edges: Vec<[u32; 3]> = Vec::with_capacity(n_edges);
        for (d, s) in scans.iter().enumerate() {
            stats.add(&s.stats);
            for &(midx, code_off) in &s.defs {
                let n = g.get(s.mhash[midx as usize], d as u16, midx) as usize;
                // Render from the defining DEX, not wherever it was first referenced.
                g.rep[n] = (d as u16, midx);
                g.def[n] = Some((d as u16, code_off));
            }
            for &[caller, callee, off] in &s.edges {
                let gc = g.get(s.mhash[caller as usize], d as u16, caller);
                let ge = callee_node(&dexes, &mut irr, &mut g, &s.mhash, d as u16, callee);
                edges.push([gc, ge, off]);
            }
        }
        // Remap string refs' callers to gids too, so string search answers in gids.
        let mut string_refs: Vec<Vec<[u32; 2]>> = scans
            .iter()
            .map(|s| s.string_refs.iter().map(|&[sidx, caller]| [sidx, g.map[&s.mhash[caller as usize]]]).collect())
            .collect();
        if irr.active() {
            let mut extra: Vec<Vec<[u32; 2]>> = dexes.iter().map(|_| Vec::new()).collect();
            scan_irregular(&dexes, &scans, &mut irr, &mut g, &mut edges, &mut extra, &mut stats);
            for (refs, extra) in string_refs.iter_mut().zip(extra) {
                if !extra.is_empty() {
                    refs.extend(extra);
                    refs.sort_unstable();
                }
            }
        }
        drop(scans);
        drop(class_lists);

        let Gids { map: sig_to_gid, rep, def } = g;
        let n = rep.len();
        let callees = Csr::build(n, &edges, 0, 1);
        let callers = Csr::build(n, &edges, 1, 0);
        drop(edges);
        Ok(Index { dexes, sig_to_gid, rep, def, class_defs, class_order, irr, callees, callers, string_refs, stats })
    }

    pub fn method_count(&self) -> usize {
        self.rep.len()
    }

    pub fn internal_count(&self) -> usize {
        self.def.iter().filter(|d| d.is_some()).count()
    }

    pub fn sig(&self, gid: u32) -> String {
        let (d, midx) = self.rep[gid as usize];
        self.dexes[d as usize].method_sig(midx).unwrap_or_default()
    }

    pub fn gid_of(&self, sig: &str) -> Option<u32> {
        self.sig_to_gid.get(&sig_hash(sig.as_bytes())).copied()
    }

    /// (dex, method_idx, code_off) of a method defined in the APK with code.
    pub fn code_of(&self, gid: u32) -> Option<(&Dex, u32, u32)> {
        let (d, code_off) = (*self.def.get(gid as usize)?)?;
        let (_, midx) = self.rep[gid as usize];
        Some((&self.dexes[d as usize], midx, code_off))
    }

    /// (dex, class_def index) of a class defined in the APK, by descriptor.
    pub fn class_def_of(&self, desc: &str) -> Option<(&Dex, usize)> {
        let &(d, ci) = self.class_defs.get(&sig_hash(desc.as_bytes()))?;
        Some((&self.dexes[d as usize], ci as usize))
    }

    /// (dex, method_idx) a method is rendered from: its defining DEX if it
    /// has code here, else where it was first referenced.
    pub fn rep_of(&self, gid: u32) -> (&Dex, u32) {
        let (d, midx) = self.rep[gid as usize];
        (&self.dexes[d as usize], midx)
    }

    /// (dex number, dex, class_def index) of a defined class, by `sig_hash`
    /// of its raw descriptor.
    pub fn class_def_by_hash(&self, h: u64) -> Option<(u16, &Dex, usize)> {
        let &(d, ci) = self.class_defs.get(&h)?;
        Some((d, &self.dexes[d as usize], ci as usize))
    }

    /// Number of defined classes (the first part of dx.get_classes()).
    pub fn defined_class_count(&self) -> usize {
        self.class_order.len()
    }

    /// The `i`th defined class in dx.get_classes() order.
    pub fn defined_class_at(&self, i: usize) -> Option<(u16, &Dex, usize)> {
        self.class_def_by_hash(*self.class_order.get(i)?)
    }

    /// Defined classes in dx.get_classes() order, as (dex number, dex, class_def index).
    pub fn classes_in_order(&self) -> impl Iterator<Item = (u16, &Dex, usize)> + '_ {
        self.class_order.iter().filter_map(|&h| self.class_def_by_hash(h))
    }

    /// Code of an irregular class's EncodedMethod: (dex, method_idx, code_off).
    pub fn em_code(&self, e: u32) -> Option<(&Dex, u32, u32)> {
        let em = self.irr.ems.get(e as usize)?;
        (em.node != NONE).then(|| (&self.dexes[em.dex as usize], em.midx, em.code_off))
    }

    /// The node that resolves signature `sig` ("Lcls;->name(params)ret", as
    /// a call to it does): a gid, or for an irregular class, the
    /// MethodAnalysis `H` holds, as an irregular key.
    ///
    /// A class name may itself contain "->" (crafted files), so every "->"
    /// is tried as the separator, in order, and the first that splits off
    /// an irregular class name holding such a method wins.
    pub fn resolve_sig(&self, sig: &str) -> Option<Resolved> {
        if self.irr.active() {
            for (at, _) in sig.match_indices("->") {
                let Some(name) = self.irr.name_of_hash(sig_hash(&sig.as_bytes()[..at])) else { continue };
                let mut h = std::hash::DefaultHasher::new();
                h.write(&sig.as_bytes()[at..]);
                if let Some((j, e)) = self.irr.lookup(name, h.finish().max(1)) {
                    return Some(Resolved::Key(irregular::key(j, e)));
                }
            }
        }
        self.gid_of(sig).map(Resolved::Node)
    }

    pub fn callers_of(&self, gid: u32) -> &[[u32; 2]] {
        self.callers.get(gid)
    }

    pub fn callees_of(&self, gid: u32) -> &[[u32; 2]] {
        self.callees.get(gid)
    }

    /// Methods referencing (via const-string) any string containing `needle`,
    /// as nodes (several irregular EncodedMethods can share a signature).
    /// The string is matched as androguard's `StringAnalysis.get_value()`
    /// has it (`get_cm_string()`): MUTF-8 decoded as mutf8 1.1.0 does,
    /// "ANDROGUARD[INVALID_STRING] ..." for undecodable data, "AG:IS:
    /// invalid string" for an index past the table; `needle` is that text
    /// as UTF-8 (lone surrogates as WTF-8), so a byte match is a code-point
    /// substring match.
    pub fn methods_using_string(&self, needle: &[u8]) -> (usize, Vec<u32>) {
        let finder = memchr::memmem::Finder::new(needle);
        let per_dex: Vec<(usize, Vec<u32>)> = self
            .dexes
            .par_iter()
            .zip(self.string_refs.par_iter())
            .map(|(dex, refs)| {
                let mut hits = 0;
                let mut methods = Vec::new();
                let mut i = 0;
                while i < refs.len() {
                    let sidx = refs[i][0];
                    let j = i + refs[i..].partition_point(|r| r[0] == sidx);
                    if string_text_contains(dex, sidx, &finder) {
                        hits += 1;
                        methods.extend(refs[i..j].iter().map(|r| r[1]));
                    }
                    i = j;
                }
                (hits, methods)
            })
            .collect();
        let mut methods: Vec<u32> = per_dex.iter().flat_map(|(_, m)| m.iter().copied()).collect();
        methods.sort_unstable();
        methods.dedup();
        (per_dex.iter().map(|(h, _)| h).sum(), methods)
    }

    /// Methods whose instruction text contains any of `needles`, in
    /// androguard's class/method order, as (signature, key) (see `HitKey`).
    ///
    /// The same as this walk over androguard's objects: dx.get_classes() order
    /// (see `class_order`), each class's methods in get_methods() order;
    /// for each method androguard can disassemble, lower-case every
    /// non-empty `get_output()` and match if any needle is a substring of
    /// any one instruction's text (never across instructions). Needles are
    /// used as given (callers lower-case them). For an irregular
    /// class, get_methods() goes on after its own methods with those
    /// create_xref() appends: `extra(class hash)` gives them (see
    /// `Model::r_segments`); it is only asked about such classes. Runs in parallel; nothing is cached between calls, so memory
    /// stays flat. Within a call, a class_data shared by several classes
    /// (only in crafted files) is searched once, and those classes share its
    /// hits, as do the classes listing one class_data's calling methods: the
    /// result is, per class with hits, its (dex, class_def) and its chunks,
    /// to be read in order, never copied per class.
    pub fn search_instruction_text(
        &self,
        needles: &[String],
        extra: &(dyn Fn(u64) -> Vec<TailSeg> + Sync),
    ) -> Vec<ClassHits> {
        let hit = |dex: &Dex, code: &[u8]| -> bool {
            let resolver = AgResolver { dex };
            // A method androguard can't disassemble contributes nothing.
            let Ok(insns) = dex_bytecode::decode_all_with_resolver(code, 0, &resolver) else { return false };
            insns.iter().any(|i| {
                if i.output_is_none || i.operands.is_empty() {
                    return false;
                }
                let text = py_lower(&i.operands);
                needles.iter().any(|n| text.contains(n.as_str()))
            })
        };
        let search = |d: u16, dex: &Dex, off: u32| -> Vec<Hit> {
            let mut hits = Vec::new();
            let Ok(data) = dex.class_data(off) else { return hits };
            let block = self.irr.block_at(d, off);
            for (pos, m) in data.direct_methods.iter().chain(&data.virtual_methods).enumerate() {
                // No declared code_item: no code.
                let Ok(code) = dex.code(m.code_off) else { continue };
                if hit(dex, code) {
                    let key = match block {
                        Some(b) => HitKey::Pos(self.irr.em_range(b).start + pos as u32),
                        None => HitKey::Sig,
                    };
                    hits.push((dex.method_sig(m.idx).unwrap_or_default(), key));
                }
            }
            hits
        };
        let ems_hits = |ems: &mut dyn Iterator<Item = (u32, u64)>| -> Vec<Hit> {
            let mut out = Vec::new();
            for (e, key) in ems {
                let Some((dex, midx, code_off)) = self.em_code(e) else { continue };
                if dex.code(code_off).is_ok_and(|code| hit(dex, code)) {
                    out.push((dex.method_sig(midx).unwrap_or_default(), HitKey::Full(key)));
                }
            }
            out
        };
        let shared: FxHashMap<(usize, u32), OnceLock<Arc<Vec<Hit>>>> = self
            .dexes
            .iter()
            .enumerate()
            .flat_map(|(d, dex)| dex.memo.shared_class_data().map(move |off| ((d, off), OnceLock::new())))
            .collect();
        // What create_xref() appended to each irregular class, and a cell per
        // class_data appended whole (searched once for every class it is in).
        let tails: FxHashMap<u64, Vec<TailSeg>> = if self.irr.active() {
            self.class_order.iter().filter(|h| self.irr.name_of_hash(**h).is_some()).map(|&h| (h, extra(h))).collect()
        } else {
            FxHashMap::default()
        };
        let runs: FxHashMap<u32, OnceLock<Arc<Vec<Hit>>>> = tails
            .values()
            .flatten()
            .filter_map(|s| match s {
                TailSeg::Block(b) => Some((*b, OnceLock::new())),
                TailSeg::Ems(_) => None,
            })
            .collect();
        self.class_order
            .par_iter()
            .filter_map(|h| {
                let &(d, ci) = self.class_defs.get(h)?;
                let dex = &self.dexes[d as usize];
                let cd = dex.class_def(ci as usize).ok()?;
                let mut chunks = Vec::new();
                if dex.has_class_data(cd.class_data_off) {
                    chunks.push(match shared.get(&(d as usize, cd.class_data_off)) {
                        Some(cell) => cell.get_or_init(|| Arc::new(search(d, dex, cd.class_data_off))).clone(),
                        None => Arc::new(search(d, dex, cd.class_data_off)),
                    });
                }
                for seg in tails.get(h).map(Vec::as_slice).unwrap_or_default() {
                    chunks.push(match seg {
                        TailSeg::Ems(ems) => Arc::new(ems_hits(&mut ems.iter().copied())),
                        TailSeg::Block(b) => runs[b]
                            .get_or_init(|| Arc::new(ems_hits(&mut self.run_ems(*b).map(|e| (e, self.irr.ma_star(e))))))
                            .clone(),
                    });
                }
                chunks.retain(|c| !c.is_empty());
                (!chunks.is_empty()).then_some(((d, ci), chunks))
            })
            .collect()
    }

    /// The EncodedMethods of irregular class_data `b` that make calls (what a
    /// `TailSeg::Block` lists).
    pub fn run_ems(&self, b: u32) -> impl Iterator<Item = u32> + '_ {
        self.irr.em_range(b).filter(|&e| self.irr.ems[e as usize].calls)
    }

    /// Bytes held by the index structures (excluding the DEX bytes themselves).
    pub fn index_bytes(&self) -> usize {
        self.sig_to_gid.capacity() * 16
            + self.rep.len() * 8
            + self.def.len() * 8
            + self.class_defs.capacity() * 24
            + self.callees.bytes()
            + self.callers.bytes()
            + self.string_refs.iter().map(|v| v.len() * 8).sum::<usize>()
            + self.irr.bytes()
    }

    pub fn dex_bytes(&self) -> usize {
        self.dexes.iter().map(|d| d.data.len()).sum()
    }
}
