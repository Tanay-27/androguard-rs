//! androguard 4.1.3's analysis object model, as plain
//! data: `dx.get_classes()` (internal classes, then the external ones its
//! create_xref() invents), each `ClassAnalysis.get_methods()` (the class's
//! EncodedMethods, then the ExternalMethods created for calls it can't
//! resolve), xrefs with their endpoints spelled out, the class hierarchy, and
//! const-string instruction text.
//!
//! Classes and methods that androguard creates during create_xref() are
//! ordered by first reference, so `Model::build` replays that pass: every
//! DEX in order, every class_def, its methods (direct then virtual), every
//! instruction, noting const-class/new-instance types and invoke targets.
//! Only first references are kept, so memory is bounded by the number of
//! distinct classes and methods referenced, not by instruction count.
//!
//! The same pass notes the fields each class_data's code reads or writes,
//! which `ClassAnalysis.get_fields()` lists after the class's own (see
//! `Model::class_fields`).
//!
//! A crafted DEX can point thousands of class_defs at one class_data_item.
//! androguard then shows every one of those classes with all its methods,
//! so the answers here do too, but what is rendered from one class_data is
//! rendered once and shared (`Arc`), never stored per class.

use std::hash::{DefaultHasher, Hasher};
use std::sync::{Arc, OnceLock};

use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};

use anyhow::Result;

use crate::classes::{Value, class_info, method_flags};
use crate::dex::Dex;
use crate::index::{HitKey, Index, TailSeg, sig_hash};
use crate::irregular::{self, NONE};
use crate::insn::Decoder;
use crate::render::{AgResolver, wtf8};

/// The element type of an array descriptor, as androguard's `lstrip('[')`.
fn strip_arrays(desc: &[u8]) -> &[u8] {
    &desc[desc.iter().take_while(|&&c| c == b'[').count()..]
}

/// `sig_hash` of the class androguard files a reference to type `idx` under,
/// or None where it skips the reference (not an object type, unreadable).
fn class_ref(dex: &Dex, type_idx: u32) -> Option<u64> {
    let desc = strip_arrays(dex.type_desc(type_idx).ok()?);
    (desc.first() == Some(&b'L')).then(|| sig_hash(desc))
}

/// Same identity as the index's method hash (`Lcls;->name(params)ret`,
/// array receivers stripped); 0 where the index skips the method.
fn method_hash(dex: &Dex, idx: u32) -> u64 {
    let Ok(cls) = dex.method_class_desc(idx) else { return 0 };
    if strip_arrays(cls).first() != Some(&b'L') {
        return 0;
    }
    let mut h = DefaultHasher::new();
    match dex.method_sig_parts(idx, &mut |p| h.write(p)) {
        Ok(()) => h.finish().max(1),
        Err(_) => 0,
    }
}

#[derive(Clone, Copy)]
enum Event {
    /// A class referenced by name hash, renderable from this DEX's type `type_idx`.
    Class { hash: u64, type_idx: u32 },
    /// An invoke target: its class's hash, its signature hash, its
    /// method_idx here; `ext` when it is known to resolve to nothing (an
    /// irregular class's `H` has no such method).
    Method { class: u64, sig: u64, midx: u32, ext: bool },
    /// The first call of EncodedMethod `e` (see `irregular`) while
    /// create_xref() visits a class_def named `name` whose winner doesn't
    /// hold it: add_method_xref_to() lists `MA*(e)`.
    Caller { name: u32, e: u32 },
    /// A call resolving to irregular slot `slot`: add_method_xref_from()
    /// lists the resolved MethodAnalysis if the class doesn't hold its
    /// EncodedMethod yet.
    Callee { slot: u32 },
    /// A class_def named `name` reusing class_data `block`, already visited
    /// under another name: the first calls of its methods list them, in
    /// order (the Callers of a first visit, without the rest).
    Run { name: u32, block: u32 },
}

/// An entry create_xref() appends to a class's get_methods().
#[derive(Clone, Copy)]
enum Tail {
    /// An ExternalMethod, renderable from (dex, method_idx).
    External(u16, u32),
    /// An irregular MethodAnalysis (`irregular::key`).
    Own(u64),
    /// The calling methods of a class_data, `Model::runs[i]`.
    Run(u32),
}

/// A `Tail::Run`: the class_data's EncodedMethods that make calls, as
/// `MA*(e)`, but those the class already held when it was met.
struct RunRec {
    block: u32,
    excluded: Vec<u32>,
}

/// One DEX's share of create_xref(): every method defined here (with or
/// without code), and the first reference to each class/method, in order.
struct DexPass {
    defined: Vec<u64>,
    events: Vec<Event>,
    fields: FieldAccess,
}

/// The fields each class_data's code reads or writes (iget*/iput*/sget*/
/// sput*, 0x52..0x6d), as field_idx in first-access order, each once per
/// class_data. Bounded by the DEX's own instructions, as every class_data
/// is scanned once however many class_defs share it.
#[derive(Default)]
struct FieldAccess {
    /// (class_data offset, start, end) into `items`, sorted by offset.
    spans: Vec<(u32, u32, u32)>,
    items: Vec<u32>,
}

impl FieldAccess {
    fn get(&self, class_data_off: u32) -> &[u32] {
        match self.spans.binary_search_by_key(&class_data_off, |s| s.0) {
            Ok(i) => &self.items[self.spans[i].1 as usize..self.spans[i].2 as usize],
            Err(_) => &[],
        }
    }
}

fn pass(idx: &Index, d: u16, dex: &Dex) -> DexPass {
    let irr = &idx.irr;
    let active = irr.active();
    let mut seen_pairs: FxHashSet<(u32, u32)> = FxHashSet::default();
    let mut defined = Vec::new();
    let mut events = Vec::new();
    let (mut seen_class, mut seen_method) = (FxHashSet::default(), FxHashSet::default());
    let mut seen_target: FxHashSet<u32> = FxHashSet::default();
    // A class_data shared by several class_defs (only in a hostile DEX)
    // yields nothing new the second time; skip it, as methods_with_code does.
    let mut seen_data = FxHashSet::default();
    let mut local: Vec<Event> = Vec::new();
    let mut fields = FieldAccess::default();
    let (mut local_fields, mut seen_field) = (Vec::new(), FxHashSet::default());
    for c in 0..dex.class_count() {
        let Ok(cd) = dex.class_def(c) else { continue };
        if !dex.has_class_data(cd.class_data_off) {
            continue;
        }
        // An irregular class_def whose winner doesn't hold this class_data:
        // its methods' first calls list them (name, first EncodedMethod).
        let mut appending = None;
        let r_def = if active { irr.def_at(d, c as u32) } else { None };
        if let Some(j) = r_def {
            let def = &irr.defs[j as usize];
            if def.block != irregular::NONE && def.block != irr.winner_block(def.name) && seen_pairs.insert((def.name, def.block)) {
                appending = Some((def.name, irr.em_range(def.block).start));
            }
        }
        if !seen_data.insert(cd.class_data_off) {
            if let (Some((name, _)), Some(j)) = (appending, r_def) {
                events.push(Event::Run { name, block: irr.defs[j as usize].block });
            }
            continue;
        }
        let Ok(data) = dex.class_data(cd.class_data_off) else { continue };
        let fields_start = fields.items.len() as u32;
        seen_field.clear();
        for (pos, m) in data.direct_methods.iter().chain(&data.virtual_methods).enumerate() {
            let mut caller = appending.map(|(name, start)| Event::Caller { name, e: start + pos as u32 });
            let h = method_hash(dex, m.idx);
            // A method the index can't identify has no xrefs there either.
            if h == 0 {
                continue;
            }
            // androguard's method table keys an irregular class's methods
            // by the class_def's name (see `irregular`), not by signature.
            if r_def.is_none() {
                defined.push(h);
            }
            if m.code_off == 0 {
                continue;
            }
            let Ok(code) = dex.code(m.code_off) else { continue };
            local.clear();
            local_fields.clear();
            let mut dec = Decoder::new(code);
            for ins in &mut dec {
                if ins.payload != 0 {
                    continue;
                }
                match ins.op {
                    0x52..=0x6d => local_fields.push(ins.idx),
                    // const-class, new-instance
                    0x1c | 0x22 => {
                        if let Some(hash) = class_ref(dex, ins.idx) {
                            local.push(Event::Class { hash, type_idx: ins.idx });
                        }
                    }
                    // The invokes androguard xrefs (not polymorphic/custom).
                    0x6e..=0x72 | 0x74..=0x78 => {
                        let Ok((cidx, _, _)) = dex.method_id(ins.idx) else { continue };
                        let (Some(class), sig) = (class_ref(dex, cidx), method_hash(dex, ins.idx)) else { continue };
                        if sig != 0 {
                            // create_xref()'s order: _resolve_method() (an
                            // ExternalMethod), add_method_xref_to() (the
                            // caller), add_method_xref_from() (the callee).
                            local.push(Event::Class { hash: class, type_idx: cidx });
                            let resolved = if active && irr.invoke_name(&idx.dexes, d, ins.idx).is_some() {
                                Some(irr.resolved(d, ins.idx).flatten())
                            } else {
                                None
                            };
                            if !matches!(resolved, Some(Some(_))) {
                                local.push(Event::Method { class, sig, midx: ins.idx, ext: resolved.is_some() });
                            }
                            if let Some(e) = caller.take() {
                                local.push(e);
                            }
                            if let Some(Some(slot)) = resolved {
                                local.push(Event::Callee { slot });
                            }
                        }
                    }
                    _ => {}
                }
            }
            // Bytecode androguard rejects contributes nothing (see Index).
            if dec.invalid {
                continue;
            }
            fields.items.extend(local_fields.iter().filter(|&&f| seen_field.insert(f)));
            for &e in &local {
                let new = match e {
                    Event::Class { hash, .. } => seen_class.insert(hash),
                    Event::Method { sig, .. } => seen_method.insert(sig),
                    Event::Caller { .. } | Event::Run { .. } => true,
                    Event::Callee { slot } => seen_target.insert(slot),
                };
                if new {
                    events.push(e);
                }
            }
        }
        if fields.items.len() as u32 > fields_start {
            fields.spans.push((cd.class_data_off, fields_start, fields.items.len() as u32));
        }
    }
    fields.spans.sort_unstable();
    DexPass { defined, events, fields }
}

/// A `ClassAnalysis.get_methods()` entry.
pub struct MethodEntry {
    /// `Lcls;->name(params)ret`, as the other queries take it.
    pub sig: String,
    pub name: String,
    /// androguard's `get_descriptor()`: "(P1 P2)R", space-separated.
    pub descriptor: String,
    /// `get_access_flags_string()`; always "" for an ExternalMethod.
    pub access_flags: String,
    /// True for an ExternalMethod (no EncodedMethod behind it).
    pub external: bool,
    /// How to name its MethodAnalysis to the other queries beyond the
    /// signature (an irregular class's; see `HitKey`).
    pub key: HitKey,
    /// `get_class_name()` (its method_id's class) of an irregular class's
    /// method, which can differ from the class listing it.
    pub method_class: Option<String>,
}

/// An xref endpoint as androguard's `get_xref_from()`/`get_xref_to()` tuple
/// spells it: (ClassAnalysis.name, method name, descriptor, offset), plus
/// the key of an overridden earlier definition's method (see MethodEntry).
pub struct XrefEntry {
    pub sig: String,
    pub class_name: String,
    pub name: String,
    pub descriptor: String,
    pub offset: u32,
    /// `HitKey::Full` for an irregular MethodAnalysis, else `HitKey::Sig`.
    pub key: HitKey,
    pub method_class: Option<String>,
}

/// `ClassAnalysis.get_methods()` of one class: its own methods (shared
/// with every class_def using the same class_data), then what create_xref()
/// appends: ExternalMethods and, for a class defined more than once, its
/// other definitions' methods, in the order it meets them.
pub struct ClassMethods {
    pub own: Arc<Vec<MethodEntry>>,
    /// (dex, class_data offset) when `own` is shared by several class_defs,
    /// so callers can cache what they build from it under this key.
    pub shared: Option<(u16, u32)>,
    /// What create_xref() appended, in order.
    pub tail: Vec<TailRows>,
}

/// A stretch of `ClassMethods::tail`.
pub enum TailRows {
    Rows(Vec<MethodEntry>),
    /// Every calling method of irregular class_data `.0`, as `MA*(e)`: the
    /// same rows in every class that lists it, built once.
    Run(u32, Arc<Vec<MethodEntry>>),
}

impl ClassMethods {
    pub fn tail_entries(&self) -> impl Iterator<Item = &MethodEntry> {
        self.tail.iter().flat_map(|t| match t {
            TailRows::Rows(r) => r.as_slice(),
            TailRows::Run(_, r) => r.as_slice(),
        })
    }
}

/// Rendered once per (dex, class_data offset) shared by several class_defs.
type SharedCells<T> = FxHashMap<(u16, u32), OnceLock<Arc<T>>>;

fn shared_cells<T>(idx: &Index) -> SharedCells<T> {
    idx.dexes
        .iter()
        .enumerate()
        .flat_map(|(d, dex)| dex.memo.shared_class_data().map(move |off| ((d as u16, off), OnceLock::new())))
        .collect()
}

/// The class_data at `off` rendered by `f`: once per shared offset (kept in
/// `cells`), else fresh.
fn rendered<T>(cells: &SharedCells<T>, d: u16, off: u32, f: impl FnOnce() -> T) -> (Arc<T>, Option<(u16, u32)>) {
    match cells.get(&(d, off)) {
        Some(cell) => (cell.get_or_init(|| Arc::new(f())).clone(), Some((d, off))),
        None => (Arc::new(f()), None),
    }
}

/// `get_class_name()` of method_idx `midx`: its method_id's class.
fn method_class(dex: &Dex, midx: u32) -> String {
    match dex.method_id(midx) {
        Ok((c, _, _)) => AgResolver { dex }.type_name(c),
        Err(_) => String::new(),
    }
}

/// A class's own methods (direct, then virtual) as get_methods() lists them.
/// For an irregular class_data (`block`), each names its EncodedMethod.
fn own_methods(dex: &Dex, off: u32, block: Option<u32>, first_em: u32) -> Vec<MethodEntry> {
    let Ok(data) = dex.class_data(off) else { return Vec::new() };
    let r = AgResolver { dex };
    data.direct_methods
        .iter()
        .chain(&data.virtual_methods)
        .enumerate()
        .map(|(pos, m)| {
            let (name, descriptor) = r.method_name_and_desc(m.idx);
            MethodEntry {
                sig: dex.method_sig(m.idx).unwrap_or_default(),
                name,
                descriptor,
                access_flags: method_flags(m.access_flags),
                external: false,
                key: if block.is_some() { HitKey::Pos(first_em + pos as u32) } else { HitKey::Sig },
                method_class: block.map(|_| method_class(dex, m.idx)),
            }
        })
        .collect()
}

/// A get_methods() entry for irregular MethodAnalysis `k`.
fn r_entry(idx: &Index, k: u64) -> MethodEntry {
    let (_, e) = irregular::unkey(k);
    let em = &idx.irr.ems[e as usize];
    let dex = &idx.dexes[em.dex as usize];
    let (name, descriptor) = AgResolver { dex }.method_name_and_desc(em.midx);
    MethodEntry {
        sig: dex.method_sig(em.midx).unwrap_or_default(),
        name,
        descriptor,
        access_flags: method_flags(em.flags),
        external: false,
        key: HitKey::Full(k),
        method_class: Some(method_class(dex, em.midx)),
    }
}

pub struct Model {
    /// Own methods of class_data shared by several class_defs, rendered on first use.
    own: SharedCells<Vec<MethodEntry>>,
    /// External classes in first-reference order: (name hash, dex, type_idx).
    ext_classes: Vec<(u64, u16, u32)>,
    ext_class_set: FxHashSet<u64>,
    /// What create_xref() appends to each class's get_methods(), by class
    /// name hash, in order.
    tails: FxHashMap<u64, Vec<Tail>>,
    /// Irregular classes (see `irregular`): the MethodAnalysis each class
    /// (name) holds for an EncodedMethod, where create_xref() put it as a
    /// single entry; the runs; and every MethodAnalysis listed that way.
    held: FxHashMap<(u32, u32), u64>,
    runs: Vec<RunRec>,
    run_of: FxHashMap<(u32, u32), u32>,
    runs_by_block: FxHashMap<u32, Vec<u32>>,
    /// Rows of each class_data appended whole, built on first use.
    run_rows: FxHashMap<u32, OnceLock<Arc<Vec<MethodEntry>>>>,
    listed: FxHashSet<u64>,
    /// Per DEX: the fields each class_data's code accesses.
    field_access: Vec<FieldAccess>,
    /// Per DEX, built on the first class_fields() that needs it: androguard's
    /// get_encoded_field_descriptor() table (see `field_defs`).
    field_defs: Vec<OnceLock<FxHashMap<u64, (u32, u32)>>>,
    /// Position in dx.get_classes() by `sig_hash` of the name as Python
    /// sees it (str.encode("utf-8", "surrogatepass")): androguard's
    /// `classes` dict, keyed by the decoded name. Built on first lookup.
    name_pos: OnceLock<FxHashMap<u64, u32>>,
}

/// A `ClassAnalysis.get_fields()` entry: an EncodedField's getters.
#[derive(Clone, Debug, PartialEq)]
pub struct FieldEntry {
    /// `get_class_name()`: the class its field_id names.
    pub class_name: String,
    pub access_flags: String,
    pub name: String,
    /// `get_descriptor()`.
    pub ty: String,
    /// `init_value.value`, or None if the field has no init_value.
    pub init: Option<Value>,
}

/// androguard's key for a field: class name + name + descriptor, as one
/// string (get_encoded_field_descriptor() concatenates them), hashed.
fn field_key(r: &AgResolver, field_idx: u32) -> u64 {
    match r.dex.field_id(field_idx) {
        Some((c, t, n)) => {
            let (c, n, t) = (r.type_name(c), r.string(n), r.type_name(t));
            let mut h = DefaultHasher::new();
            for part in [&c, &n, &t] {
                h.write(part.as_bytes());
            }
            h.finish()
        }
        None => sig_hash(b"AG:IFI:invalid_class_name;AG:IFI:invalid_name(AG:IFI:invalid_type)"),
    }
}

/// androguard's get_encoded_field_descriptor() table for one DEX: field key
/// -> (class_def index, position among its static then instance fields),
/// filled from every class_def in order, so the last writer of a key wins.
/// A class_data shared by several class_defs (only in crafted files) holds
/// the same EncodedField objects for all of them, and its last writes are
/// at its last class_def, so each class_data is entered once, there.
fn field_defs(dex: &Dex) -> FxHashMap<u64, (u32, u32)> {
    let r = AgResolver { dex };
    let mut last: FxHashMap<u32, usize> = FxHashMap::default();
    for c in 0..dex.class_count() {
        let Ok(cd) = dex.class_def(c) else { continue };
        if dex.has_class_data(cd.class_data_off) {
            last.insert(cd.class_data_off, c);
        }
    }
    let mut map = FxHashMap::default();
    for c in 0..dex.class_count() {
        let Ok(cd) = dex.class_def(c) else { continue };
        if last.get(&cd.class_data_off) != Some(&c) {
            continue;
        }
        let Ok(data) = dex.class_data(cd.class_data_off) else { continue };
        for (i, f) in data.static_fields.iter().chain(&data.instance_fields).enumerate() {
            map.insert(field_key(&r, f.idx), (c as u32, i as u32));
        }
    }
    map
}

/// The fields of class_def `ci`, as get_fields() entries (static, then instance).
fn field_entries(dex: &Dex, ci: usize) -> Result<Vec<FieldEntry>> {
    let r = AgResolver { dex };
    let info = class_info(dex, ci)?;
    let cd = dex.class_def(ci)?;
    let data = if dex.has_class_data(cd.class_data_off) { Some(dex.class_data(cd.class_data_off)?) } else { None };
    let members = data.iter().flat_map(|d| d.static_fields.iter().chain(&d.instance_fields));
    Ok(info
        .field_values()
        .zip(members)
        .map(|((flags, name, ty, init), m)| FieldEntry {
            class_name: match dex.field_id(m.idx) {
                Some((c, _, _)) => r.type_name(c),
                None => "AG:IFI:invalid_class_name;".into(),
            },
            access_flags: flags.to_owned(),
            name: name.to_owned(),
            ty: ty.to_owned(),
            init: init.cloned(),
        })
        .collect())
}

impl Model {
    pub fn build(idx: &Index) -> Model {
        crate::pool::install(|| {
            let passes: Vec<DexPass> = idx.dexes.par_iter().enumerate().map(|(d, dex)| pass(idx, d as u16, dex)).collect();
            // androguard's method table holds every definition in every DEX
            // before create_xref() runs, so "defined" is global.
            let defined: FxHashSet<u64> = passes.iter().flat_map(|p| p.defined.iter().copied()).collect();
            let mut m = Model {
                own: shared_cells(idx),
                ext_classes: Vec::new(),
                ext_class_set: FxHashSet::default(),
                tails: FxHashMap::default(),
                held: FxHashMap::default(),
                runs: Vec::new(),
                run_of: FxHashMap::default(),
                runs_by_block: FxHashMap::default(),
                run_rows: FxHashMap::default(),
                listed: FxHashSet::default(),
                field_access: Vec::new(),
                field_defs: idx.dexes.iter().map(|_| OnceLock::new()).collect(),
                name_pos: OnceLock::new(),
            };
            let mut seen_method = FxHashSet::default();
            let irr = &idx.irr;
            for (d, p) in passes.iter().enumerate() {
                for &ev in &p.events {
                    match ev {
                        Event::Class { hash, type_idx } => {
                            if idx.class_def_by_hash(hash).is_none() && m.ext_class_set.insert(hash) {
                                m.ext_classes.push((hash, d as u16, type_idx));
                            }
                        }
                        Event::Method { class, sig, midx, ext } => {
                            if (ext || !defined.contains(&sig)) && seen_method.insert(sig) {
                                m.tails.entry(class).or_default().push(Tail::External(d as u16, midx));
                            }
                        }
                        Event::Caller { name, e } => m.hold(idx, name, e, irr.ma_star(e)),
                        Event::Callee { slot } => {
                            let s = &irr.slots[slot as usize];
                            m.hold(idx, s.name, s.em, irregular::key(s.j, s.em));
                        }
                        Event::Run { name, block } => {
                            let excluded: Vec<u32> =
                                irr.em_range(block).filter(|&e| irr.ems[e as usize].calls && m.held.contains_key(&(name, e))).collect();
                            let r = m.runs.len() as u32;
                            m.runs.push(RunRec { block, excluded });
                            m.run_of.insert((name, block), r);
                            m.runs_by_block.entry(block).or_default().push(r);
                            m.tails.entry(irr.names[name as usize].hash).or_default().push(Tail::Run(r));
                        }
                    }
                }
            }
            m.field_access = passes.into_iter().map(|p| p.fields).collect();
            m.run_rows = m.runs.iter().filter(|r| r.excluded.is_empty()).map(|r| (r.block, OnceLock::new())).collect();
            m
        })
    }

    /// create_xref() lists MethodAnalysis `k` (of EncodedMethod `e`) in the
    /// class named `name` unless it already holds `e`.
    fn hold(&mut self, idx: &Index, name: u32, e: u32, k: u64) {
        if self.held_obj(idx, name, e).is_none() {
            self.held.insert((name, e), k);
            self.listed.insert(k);
            self.tails.entry(idx.irr.names[name as usize].hash).or_default().push(Tail::Own(k));
        }
    }

    /// The MethodAnalysis the class named `name` (irregular) holds for
    /// EncodedMethod `e`, if any.
    pub fn held_obj(&self, idx: &Index, name: u32, e: u32) -> Option<u64> {
        let irr = &idx.irr;
        let em = &irr.ems[e as usize];
        if irr.winner_block(name) == em.block {
            return Some(irregular::key(irr.names[name as usize].winner, e));
        }
        if let Some(&k) = self.held.get(&(name, e)) {
            return Some(k);
        }
        let r = *self.run_of.get(&(name, em.block))?;
        (em.calls && !self.runs[r as usize].excluded.contains(&e)).then(|| irr.ma_star(e))
    }

    /// True if some class lists irregular MethodAnalysis `k`.
    pub fn listed(&self, idx: &Index, k: u64) -> bool {
        let irr = &idx.irr;
        let (j, e) = irregular::unkey(k);
        let (Some(def), Some(em)) = (irr.defs.get(j as usize), irr.ems.get(e as usize)) else { return false };
        if def.block != em.block {
            return false;
        }
        if irr.names[def.name as usize].winner == j || self.listed.contains(&k) {
            return true;
        }
        em.calls
            && irr.ma_star(e) == k
            && self
                .runs_by_block
                .get(&em.block)
                .is_some_and(|rs| rs.iter().any(|&r| !self.runs[r as usize].excluded.contains(&e)))
    }

    /// callers()/callees() of a signature: the xrefs of every
    /// MethodAnalysis in dx.get_methods() with that method_id signature (a
    /// gid's, and `MA*(e)` of each irregular EncodedMethod having it).
    pub fn sig_xrefs(&self, idx: &Index, sig: &str, callers: bool) -> Vec<XrefEntry> {
        let mut out = idx.gid_of(sig).map(|g| xrefs(idx, g, callers)).unwrap_or_default();
        for &e in idx.irr.ems_with_sig(sig_hash(sig.as_bytes()).max(1)) {
            out.extend(self.r_xrefs(idx, idx.irr.ma_star(e), callers));
        }
        out
    }

    /// What create_xref() appended to an irregular class's get_methods()
    /// (ExternalMethods left out), as segments: a run with nothing excluded
    /// is its whole class_data (`TailSeg::Block`), shareable between classes.
    pub fn r_segments(&self, idx: &Index, class: u64) -> Vec<TailSeg> {
        let irr = &idx.irr;
        let mut out = Vec::new();
        let mut cur: Vec<(u32, u64)> = Vec::new();
        for t in self.tails.get(&class).map(Vec::as_slice).unwrap_or_default() {
            match *t {
                Tail::External(..) => {}
                Tail::Own(k) => cur.push((irregular::unkey(k).1, k)),
                Tail::Run(r) => {
                    let run = &self.runs[r as usize];
                    if run.excluded.is_empty() {
                        if !cur.is_empty() {
                            out.push(TailSeg::Ems(std::mem::take(&mut cur)));
                        }
                        out.push(TailSeg::Block(run.block));
                    } else {
                        cur.extend(idx.run_ems(run.block).filter(|e| !run.excluded.contains(e)).map(|e| (e, irr.ma_star(e))));
                    }
                }
            }
        }
        if !cur.is_empty() {
            out.push(TailSeg::Ems(cur));
        }
        out
    }

    /// `get_xref_to()` (`callers` false) or `get_xref_from()` of irregular
    /// MethodAnalysis `k` (see `irregular`).
    pub fn r_xrefs(&self, idx: &Index, k: u64, callers: bool) -> Vec<XrefEntry> {
        let irr = &idx.irr;
        let (j, e) = irregular::unkey(k);
        let (Some(def), Some(em)) = (irr.defs.get(j as usize), irr.ems.get(e as usize)) else { return Vec::new() };
        if def.block != em.block {
            return Vec::new();
        }
        if !callers {
            return if em.node != NONE && self.listed(idx, k) { xrefs(idx, em.node, false) } else { Vec::new() };
        }
        let mut out = Vec::new();
        for &name in &irr.blocks[em.block as usize].names {
            if let Some(s) = irr.slot(name, e)
                && self.held_obj(idx, name, e) == Some(k)
            {
                out.extend(xrefs(idx, irr.slots[s as usize].node, true));
            }
        }
        out
    }

    /// Length of dx.get_classes().
    pub fn class_count(&self, idx: &Index) -> usize {
        idx.defined_class_count() + self.ext_classes.len()
    }

    /// The `i`th entry of dx.get_classes() as (name, is_external), rendered
    /// as `classes()` does.
    pub fn class_at(&self, idx: &Index, i: usize) -> Option<(String, bool)> {
        let n = idx.defined_class_count();
        if i < n {
            let (_, dex, ci) = idx.defined_class_at(i)?;
            let name = dex.class_def(ci).map(|cd| AgResolver { dex }.type_name(cd.class_idx)).unwrap_or_default();
            return Some((name, false));
        }
        let &(_, d, ti) = self.ext_classes.get(i - n)?;
        let dex = &idx.dexes[d as usize];
        Some((AgResolver { dex }.type_name(ti).trim_start_matches('[').to_owned(), true))
    }

    /// Position in dx.get_classes() of the class androguard files under
    /// `name` (given as str.encode("utf-8", "surrogatepass") bytes), or
    /// None: dx.get_class_analysis(name). With several entries rendering
    /// to one name (only in crafted files) the last wins, as in a dict.
    pub fn class_position(&self, idx: &Index, name: &[u8]) -> Option<usize> {
        let map = self.name_pos.get_or_init(|| {
            let mut m = FxHashMap::default();
            for i in 0..self.class_count(idx) {
                if let Some((n, _)) = self.class_at(idx, i) {
                    m.insert(sig_hash(&wtf8(&n)), i as u32);
                }
            }
            m
        });
        map.get(&sig_hash(name)).map(|&i| i as usize)
    }

    /// `dx.get_class_analysis(name).get_fields()`, or None if androguard has
    /// no class by that name. An external class has none.
    ///
    /// Mirrors androguard 4.1.3: the class's own fields (static, then
    /// instance) seeded by Analysis.add(), then each field create_xref()
    /// adds because the class's code reads or writes it (0x52..0x6d), in
    /// first-access order: every definition of the class in AnalyzeAPK
    /// order (a duplicate's code too), each method in definition order. An
    /// access only counts if the DEX holding the code defines a field by
    /// that class, name and type (get_encoded_field_descriptor(), so a field
    /// inherited from another class doesn't), and each EncodedField is
    /// listed once. An error where androguard would fail to load the DEX
    /// (see class_info) is returned for the class itself; a foreign field
    /// whose class has one is skipped.
    pub fn class_fields(&self, idx: &Index, name: &str) -> Result<Option<Vec<FieldEntry>>> {
        let h = sig_hash(name.as_bytes());
        let Some((d, dex, ci)) = idx.class_def_by_hash(h) else {
            return Ok(self.ext_class_set.contains(&h).then(Vec::new));
        };
        let mut out = field_entries(dex, ci)?;
        // EncodedField identity: (dex, class_data offset, position).
        let mut seen: FxHashSet<(u16, u32, u32)> = FxHashSet::default();
        let own_off = dex.class_def(ci)?.class_data_off;
        seen.extend((0..out.len() as u32).map(|i| (d, own_off, i)));
        let mut rendered: FxHashMap<(u16, u32), Option<Vec<FieldEntry>>> = FxHashMap::default();
        let defs: Vec<(u16, u32)> = match idx.irr.name_of_hash(h) {
            Some(n) => idx.irr.names[n as usize].defs.iter().map(|&j| (idx.irr.defs[j as usize].dex, idx.irr.defs[j as usize].ci)).collect(),
            None => vec![(d, ci as u32)],
        };
        for &(dd, cci) in &defs {
            let ddex = &idx.dexes[dd as usize];
            let Ok(cd) = ddex.class_def(cci as usize) else { continue };
            if !ddex.has_class_data(cd.class_data_off) {
                continue;
            }
            let accessed = self.field_access[dd as usize].get(cd.class_data_off);
            if accessed.is_empty() {
                continue;
            }
            let map = self.field_defs[dd as usize].get_or_init(|| field_defs(ddex));
            let r = AgResolver { dex: ddex };
            for &f in accessed {
                let Some(&(tci, pos)) = map.get(&field_key(&r, f)) else { continue };
                let Ok(tcd) = ddex.class_def(tci as usize) else { continue };
                if !seen.insert((dd, tcd.class_data_off, pos)) {
                    continue;
                }
                let entries = rendered.entry((dd, tci)).or_insert_with(|| field_entries(ddex, tci as usize).ok());
                if let Some(e) = entries.as_ref().and_then(|v| v.get(pos as usize)) {
                    out.push(e.clone());
                }
            }
        }
        Ok(Some(out))
    }

    /// `dx.get_classes()` as (name, is_external), in its order.
    pub fn classes(&self, idx: &Index) -> Vec<(String, bool)> {
        let internal = idx.classes_in_order().map(|(_, dex, ci)| {
            let name = dex.class_def(ci).map(|cd| AgResolver { dex }.type_name(cd.class_idx)).unwrap_or_default();
            (name, false)
        });
        let external = self.ext_classes.iter().map(|&(_, d, ti)| {
            let dex = &idx.dexes[d as usize];
            (AgResolver { dex }.type_name(ti).trim_start_matches('[').to_owned(), true)
        });
        internal.chain(external).collect()
    }

    /// `dx.get_class_analysis(name).get_methods()`, or None if androguard
    /// has no class by that name.
    pub fn class_methods(&self, idx: &Index, name: &str) -> Option<ClassMethods> {
        let h = sig_hash(name.as_bytes());
        let (own, shared) = match idx.class_def_by_hash(h) {
            Some((d, dex, ci)) => {
                let off = dex.class_def(ci).ok()?.class_data_off;
                if dex.has_class_data(off) {
                    let block = idx.irr.block_at(d, off);
                    let first = block.map(|b| idx.irr.em_range(b).start).unwrap_or(0);
                    rendered(&self.own, d, off, || own_methods(dex, off, block, first))
                } else {
                    (Arc::default(), None)
                }
            }
            None if self.ext_class_set.contains(&h) => (Arc::default(), None),
            None => return None,
        };
        let irr = &idx.irr;
        let mut tail = Vec::new();
        let mut cur = Vec::new();
        for t in self.tails.get(&h).map(Vec::as_slice).unwrap_or_default() {
            match *t {
                Tail::External(d, midx) => {
                    let dex = &idx.dexes[d as usize];
                    let (name, descriptor) = AgResolver { dex }.method_name_and_desc(midx);
                    cur.push(MethodEntry {
                        sig: dex.method_sig(midx).unwrap_or_default(),
                        name,
                        descriptor,
                        access_flags: String::new(),
                        external: true,
                        key: HitKey::Sig,
                        method_class: None,
                    });
                }
                Tail::Own(k) => cur.push(r_entry(idx, k)),
                Tail::Run(r) => {
                    let run = &self.runs[r as usize];
                    if let Some(cell) = self.run_rows.get(&run.block).filter(|_| run.excluded.is_empty()) {
                        if !cur.is_empty() {
                            tail.push(TailRows::Rows(std::mem::take(&mut cur)));
                        }
                        let rows = cell.get_or_init(|| Arc::new(idx.run_ems(run.block).map(|e| r_entry(idx, irr.ma_star(e))).collect()));
                        tail.push(TailRows::Run(run.block, rows.clone()));
                    } else {
                        cur.extend(idx.run_ems(run.block).filter(|e| !run.excluded.contains(e)).map(|e| r_entry(idx, irr.ma_star(e))));
                    }
                }
            }
        }
        if !cur.is_empty() {
            tail.push(TailRows::Rows(cur));
        }
        Some(ClassMethods { own, shared, tail })
    }
}

/// Render xref endpoint `other` (a node: gid, irregular EncodedMethod or
/// slot) as the tuples androguard's set holds: a call from an irregular
/// EncodedMethod is one per distinct class name using its class_data.
fn push_xref(idx: &Index, other: u32, offset: u32, out: &mut Vec<XrefEntry>) {
    let (dex, midx) = idx.rep_of(other);
    let r = AgResolver { dex };
    let (name, descriptor) = r.method_name_and_desc(midx);
    let irr = &idx.irr;
    let kind = if irr.active() { irr.node_kind(other) } else { None };
    match kind {
        Some(irregular::RNode::Em(e)) => {
            let mc = method_class(dex, midx);
            for &n in &irr.blocks[irr.ems[e as usize].block as usize].names {
                out.push(XrefEntry {
                    sig: idx.sig(other),
                    class_name: r_name(idx, n),
                    name: name.clone(),
                    descriptor: descriptor.clone(),
                    offset,
                    key: HitKey::Full(irr.ma_star(e)),
                    method_class: Some(mc.clone()),
                });
            }
        }
        Some(irregular::RNode::Slot(s)) => {
            let s = &irr.slots[s as usize];
            out.push(XrefEntry {
                sig: idx.sig(other),
                class_name: r_name(idx, s.name),
                name,
                descriptor,
                offset,
                key: HitKey::Full(irregular::key(s.j, s.em)),
                method_class: Some(method_class(dex, midx)),
            });
        }
        None => {
            let class_name = match dex.method_id(midx) {
                Ok((c, _, _)) => r.type_name(c).trim_start_matches('[').to_owned(),
                Err(_) => String::new(),
            };
            out.push(XrefEntry { sig: idx.sig(other), class_name, name, descriptor, offset, key: HitKey::Sig, method_class: None });
        }
    }
}

/// The name of irregular class `name`, as dx.get_classes() spells it.
pub fn r_name(idx: &Index, name: u32) -> String {
    let def = &idx.irr.defs[idx.irr.names[name as usize].defs[0] as usize];
    let dex = &idx.dexes[def.dex as usize];
    dex.class_def(def.ci as usize).map(|cd| AgResolver { dex }.type_name(cd.class_idx)).unwrap_or_default()
}

/// Callers (`callers`) or callees of node `gid` (a gid, or an irregular
/// EncodedMethod's or slot's node), in the index's edge order. androguard
/// keeps these in a set, so its order isn't defined.
pub fn xrefs(idx: &Index, gid: u32, callers: bool) -> Vec<XrefEntry> {
    let edges = if callers { idx.callers_of(gid) } else { idx.callees_of(gid) };
    let mut out = Vec::with_capacity(edges.len());
    for &[other, offset] in edges {
        push_xref(idx, other, offset, &mut out);
    }
    out
}

/// (name, get_superclassname(), get_interfaces()) of every defined class,
/// in dx.get_classes() order. An unreadable interface list reads as empty.
pub fn hierarchy(idx: &Index) -> Vec<(String, String, Vec<String>)> {
    idx.classes_in_order().filter_map(|(_, dex, ci)| hierarchy_row(dex, ci)).collect()
}

/// One `hierarchy()` row: the `i`th class of dx.get_classes(), if defined.
pub fn class_hierarchy(idx: &Index, i: usize) -> Option<(String, String, Vec<String>)> {
    let (_, dex, ci) = idx.defined_class_at(i)?;
    hierarchy_row(dex, ci)
}

fn hierarchy_row(dex: &Dex, ci: usize) -> Option<(String, String, Vec<String>)> {
    let r = AgResolver { dex };
    let cd = dex.class_def(ci).ok()?;
    let ifaces = dex.type_list(cd.interfaces_off).unwrap_or_default();
    Some((r.type_name(cd.class_idx), r.type_name(cd.superclass_idx), ifaces.into_iter().map(|t| r.type_name(t)).collect()))
}

/// One method's const-string text: (method name, descriptor, get_output()
/// of each instruction, in order).
pub type MethodStrings = (String, String, Vec<String>);

/// For every defined class in dx.get_classes() order that has any, its
/// methods (direct, then virtual) with `const-string` instructions (and
/// `const-string/jumbo` if `jumbo`), with those instructions' get_output():
/// (class name, methods). Classes sharing a class_data share one `Arc`.
/// Methods androguard can't disassemble contribute nothing. Only the
/// matching instructions are rendered. For a class defined more than once,
/// get_methods() goes on with the methods create_xref() appends from its
/// other definitions: `extra(class hash)` gives them (see
/// `Model::r_segments`); it is only asked about such classes. Each class's
/// methods come in chunks (own, then appended), shared between classes
/// where they are the same.
pub fn const_strings(
    idx: &Index,
    jumbo: bool,
    extra: &(dyn Fn(u64) -> Vec<TailSeg> + Sync),
) -> Vec<(String, Vec<Arc<Vec<MethodStrings>>>)> {
    crate::pool::install(|| {
        let method = |dex: &Dex, midx: u32, code: &[u8]| -> Option<MethodStrings> {
            let r = AgResolver { dex };
            let mut dec = Decoder::new(code);
            let offs: Vec<u32> =
                (&mut dec).filter(|i| i.payload == 0 && (i.op == 0x1a || (jumbo && i.op == 0x1b))).map(|i| i.off).collect();
            if dec.invalid || offs.is_empty() {
                return None;
            }
            let outs: Vec<String> = offs
                .iter()
                .filter_map(|&off| dex_bytecode::decode_one_with_resolver(code, off as usize, &r).ok())
                .map(|i| i.operands)
                .collect();
            let (name, desc) = r.method_name_and_desc(midx);
            Some((name, desc, outs))
        };
        let scan = |dex: &Dex, off: u32| -> Vec<MethodStrings> {
            let Ok(data) = dex.class_data(off) else { return Vec::new() };
            data.direct_methods
                .iter()
                .chain(&data.virtual_methods)
                .filter_map(|m| method(dex, m.idx, dex.code(m.code_off).ok()?))
                .collect()
        };
        let cells: SharedCells<Vec<MethodStrings>> = shared_cells(idx);
        let classes: Vec<(u16, &Dex, usize)> = idx.classes_in_order().collect();
        let ems_rows = |ems: &mut dyn Iterator<Item = u32>| -> Vec<MethodStrings> {
            ems.filter_map(|e| {
                let (ndex, midx, code_off) = idx.em_code(e)?;
                method(ndex, midx, ndex.code(code_off).ok()?)
            })
            .collect()
        };
        // What create_xref() appended to each irregular class; a class_data
        // appended whole is rendered once for every class it is in.
        let tails: FxHashMap<u64, Vec<TailSeg>> = if idx.irr.active() {
            classes
                .iter()
                .filter_map(|&(_, dex, ci)| {
                    let h = sig_hash(dex.type_desc(dex.class_def(ci).ok()?.class_idx).ok()?);
                    idx.irr.name_of_hash(h).map(|_| (h, extra(h)))
                })
                .collect()
        } else {
            FxHashMap::default()
        };
        let runs: FxHashMap<u32, OnceLock<Arc<Vec<MethodStrings>>>> = tails
            .values()
            .flatten()
            .filter_map(|s| match s {
                TailSeg::Block(b) => Some((*b, OnceLock::new())),
                TailSeg::Ems(_) => None,
            })
            .collect();
        classes
            .par_iter()
            .filter_map(|&(d, dex, ci)| {
                let cd = dex.class_def(ci).ok()?;
                let mut chunks = Vec::new();
                if dex.has_class_data(cd.class_data_off) {
                    chunks.push(rendered(&cells, d, cd.class_data_off, || scan(dex, cd.class_data_off)).0);
                }
                let h = sig_hash(dex.type_desc(cd.class_idx).ok()?);
                for seg in tails.get(&h).map(Vec::as_slice).unwrap_or_default() {
                    chunks.push(match seg {
                        TailSeg::Ems(ems) => Arc::new(ems_rows(&mut ems.iter().map(|&(e, _)| e))),
                        TailSeg::Block(b) => runs[b].get_or_init(|| Arc::new(ems_rows(&mut idx.run_ems(*b)))).clone(),
                    });
                }
                chunks.retain(|c| !c.is_empty());
                (!chunks.is_empty()).then(|| (AgResolver { dex }.type_name(cd.class_idx), chunks))
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::Resolved;
    use crate::testdex::{Class, Spec, build};

    /// LA; reads LB;.b twice, writes its own a, and reads LC;.c, which no
    /// class here defines; LB; reads LA;.a.
    fn spec() -> Spec {
        // strings: 0 I, 1 LA;, 2 LB;, 3 LC;, 4 Ljava/lang/Object;, 5 V, 6 a, 7 b, 8 c, 9 m, 10 x
        let strings = vec!["I", "LA;", "LB;", "LC;", "Ljava/lang/Object;", "V", "a", "b", "c", "m", "x"];
        // fields: 0 A.a, 1 A.x, 2 B.b, 3 C.c
        let fields = vec![(1, 0, 6), (1, 0, 10), (2, 0, 7), (3, 0, 8)];
        let a_code = [0x60, 0, 2, 0, 0x60, 0, 3, 0, 0x67, 0, 0, 0, 0x60, 0, 2, 0, 0x0e, 0].to_vec();
        let b_code = [0x60, 0, 0, 0, 0x0e, 0].to_vec();
        Spec {
            strings,
            types: vec![0, 1, 2, 3, 4, 5],
            protos: vec![(5, 5)],
            fields,
            methods: vec![(1, 0, 9), (2, 0, 9)],
            classes: vec![
                Class {
                    type_idx: 1,
                    super_idx: 4,
                    static_fields: vec![(0, 9)],
                    instance_fields: vec![(1, 2)],
                    direct: vec![(0, 9, Some(a_code))],
                    static_values: vec![vec![0x04, 7]],
                },
                Class {
                    type_idx: 2,
                    super_idx: 4,
                    static_fields: vec![(2, 9)],
                    instance_fields: vec![],
                    direct: vec![(1, 9, Some(b_code))],
                    static_values: vec![],
                },
            ],
        }
    }

    fn names(m: &Model, idx: &Index, cls: &str) -> Option<Vec<(String, String, Option<Value>)>> {
        let f = m.class_fields(idx, cls).unwrap()?;
        Some(f.into_iter().map(|e| (e.class_name, e.name, e.init)).collect())
    }

    #[test]
    fn class_fields_own_then_accessed() {
        let idx = Index::build(vec![build(&spec())]).unwrap();
        let m = Model::build(&idx);
        let s = |c: &str, n: &str, v: Option<Value>| (c.to_owned(), n.to_owned(), v);
        assert_eq!(
            names(&m, &idx, "LA;").unwrap(),
            vec![s("LA;", "a", Some(Value::Int(7))), s("LA;", "x", None), s("LB;", "b", None)]
        );
        assert_eq!(names(&m, &idx, "LB;").unwrap(), vec![s("LB;", "b", None), s("LA;", "a", Some(Value::Int(7)))]);
        assert!(names(&m, &idx, "LC;").is_none());
        assert!(names(&m, &idx, "Ljava/lang/Object;").is_none());
    }

    #[test]
    fn duplicate_class_gets_both_definitions_accesses() {
        // Both DEX files define LB;, each reading its own b; the first also
        // reads A.a. LB; (the last definition) lists its own b, then the
        // first definition's b (a different EncodedField) and A.a, as
        // androguard does.
        let mut one = spec();
        one.classes[1].direct[0].2 = Some([0x60, 0, 2, 0, 0x60, 0, 0, 0, 0x0e, 0].to_vec());
        let mut two = spec();
        two.classes.remove(0);
        two.classes[0].direct[0].2 = Some([0x60, 0, 2, 0, 0x0e, 0].to_vec());
        let idx = Index::build(vec![build(&one), build(&two)]).unwrap();
        let m = Model::build(&idx);
        let got: Vec<String> = names(&m, &idx, "LB;").unwrap().into_iter().map(|e| format!("{}{}", e.0, e.1)).collect();
        assert_eq!(got, ["LB;b", "LB;b", "LA;a"]);
        assert_eq!(m.class_count(&idx), 2);
        assert_eq!(m.class_at(&idx, 1), Some(("LB;".to_owned(), false)));
        assert_eq!(m.class_position(&idx, b"LB;"), Some(1));
        assert_eq!(m.class_position(&idx, b"LZ;"), None);
    }

    #[test]
    fn field_access_skips_invalid_bytecode() {
        let mut s = spec();
        // An unused opcode after the reads: androguard rejects the method.
        s.classes[0].direct[0].2 = Some([0x60, 0, 2, 0, 0x3e, 0, 0x0e, 0].to_vec());
        let idx = Index::build(vec![build(&s)]).unwrap();
        let m = Model::build(&idx);
        assert_eq!(names(&m, &idx, "LA;").unwrap().len(), 2);
    }

    /// LC; in two DEX files: the first's `a` calls LX;->go and an
    /// inherited LC;->inh, its `b` calls nothing; the winner's `b` calls
    /// LX;->go. strings: 0 LC; 1 LX; 2 V 3 a 4 b 5 go 6 inh.
    fn dup_spec(first: bool) -> Spec {
        let call = |m: u8| vec![0x6e, 0, m, 0, 0, 0];
        let code = |calls: &[u8]| {
            let mut c: Vec<u8> = calls.iter().flat_map(|&m| call(m)).collect();
            c.extend([0x0e, 0]);
            c
        };
        let c = if first {
            Class { type_idx: 0, super_idx: 1, static_fields: vec![], instance_fields: vec![],
                    direct: vec![(0, 1, Some(code(&[3, 2]))), (1, 1, Some(code(&[])))], static_values: vec![] }
        } else {
            Class { type_idx: 0, super_idx: 1, static_fields: vec![], instance_fields: vec![],
                    direct: vec![(0, 1, Some(code(&[]))), (1, 1, Some(code(&[3])))], static_values: vec![] }
        };
        let mut classes = vec![c];
        if first {
            classes.push(Class { type_idx: 1, super_idx: 1, static_fields: vec![], instance_fields: vec![],
                                 direct: vec![(3, 1, Some(code(&[0, 1])))], static_values: vec![] });
        }
        Spec {
            strings: vec!["LC;", "LX;", "V", "a", "b", "go", "inh"],
            types: vec![0, 1, 2],
            protos: vec![(2, 2)],
            fields: vec![],
            methods: vec![(0, 0, 3), (0, 0, 4), (0, 0, 6), (1, 0, 5)],
            classes,
        }
    }

    #[test]
    fn duplicate_class_lists_earlier_callers_with_their_own_xrefs() {
        let idx = Index::build(vec![build(&dup_spec(true)), build(&dup_spec(false))]).unwrap();
        assert!(idx.irr.active());
        let m = Model::build(&idx);
        let cm = m.class_methods(&idx, "LC;").unwrap();
        // The winner (class_def 1 of LC;) lists its own (EncodedMethods 2, 3).
        let own: Vec<_> = cm.own.iter().map(|e| (e.sig.as_str(), e.key)).collect();
        assert_eq!(own, [("LC;->a()V", HitKey::Pos(2)), ("LC;->b()V", HitKey::Pos(3))]);
        let early = irregular::key(0, 0);
        let tail: Vec<_> = cm.tail_entries().map(|e| (e.sig.as_str(), e.external, e.key)).collect();
        assert_eq!(tail, [("LC;->a()V", false, HitKey::Full(early)), ("LC;->inh()V", true, HitKey::Sig)]);
        assert_eq!(m.r_segments(&idx, sig_hash(b"LC;")), [TailSeg::Ems(vec![(0, early)])]);
        // The earlier `a` has its own callees and no callers; the winner's none.
        let names = |es: Vec<XrefEntry>| es.into_iter().map(|e| (e.sig, e.offset, e.key)).collect::<Vec<_>>();
        assert_eq!(
            names(m.r_xrefs(&idx, early, false)),
            [("LX;->go()V".into(), 0, HitKey::Sig), ("LC;->inh()V".into(), 6, HitKey::Sig)]
        );
        assert!(m.r_xrefs(&idx, early, true).is_empty());
        let win_a = irregular::key(1, 2);
        assert!(m.r_xrefs(&idx, win_a, false).is_empty());
        assert_eq!(idx.resolve_sig("LC;->a()V"), Some(Resolved::Key(win_a)));
        assert_eq!(m.sig_xrefs(&idx, "LC;->a()V", false).len(), 2);
        // LX;->go's callers: the earlier `a` (by its key) and the winner's `b`.
        let go = idx.gid_of("LX;->go()V").unwrap();
        let mut callers = names(xrefs(&idx, go, true));
        callers.sort_by_key(|c| c.0.clone());
        assert_eq!(callers, [("LC;->a()V".into(), 0, HitKey::Full(early)), ("LC;->b()V".into(), 0, HitKey::Full(irregular::key(1, 3)))]);
        // Calls to LC;->b resolve to the winner's; the earlier `b` (no calls) never shows.
        assert_eq!(names(m.r_xrefs(&idx, irregular::key(1, 3), true)), [("LX;->go()V".into(), 6, HitKey::Sig)]);
        assert!(!m.listed(&idx, irregular::key(0, 1)));
        let extra = |h| m.r_segments(&idx, h);
        let hits = idx.search_instruction_text(&["lx;->go".into()], &extra);
        let hits: Vec<_> = hits.iter().flat_map(|c| c.1.iter().flat_map(|x| x.iter().cloned())).collect();
        assert_eq!(hits, [("LC;->b()V".into(), HitKey::Pos(3)), ("LC;->a()V".into(), HitKey::Full(early))]);
    }

    #[test]
    fn regular_classes_have_no_irregular_state() {
        let idx = Index::build(vec![build(&dup_spec(true))]).unwrap();
        assert!(!idx.irr.active());
        let m = Model::build(&idx);
        assert!(m.class_methods(&idx, "LC;").unwrap().own.iter().all(|e| e.key == HitKey::Sig));
        assert_eq!(idx.method_count(), 4);
    }
}
