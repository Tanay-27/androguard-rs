//! Python bindings: `androguard_rs.Apk(path)` builds the whole-APK index once
//! (with the GIL released) and answers whole-APK queries over it.
//! Every query returns plain Python values; text is byte-identical to
//! androguard 4.1.3.

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString, PyTuple};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use androguard_core::apk::{HeaderMode, Loaded, SkippedDex, load_bytes_mode_depth, load_mode_depth};
use androguard_core::classes::{Value, class_info};
use androguard_core::dexview;
use androguard_core::index::{Hit, HitKey, Index, Resolved, sig_hash};
use androguard_core::irregular;
use androguard_core::model::{self, MethodEntry, Model};
use androguard_core::render::{AgResolver, INVALID_INSTRUCTION_TEMPLATE};

mod apkinfo;
mod handles;
mod resources;

// Same name as androguard's exception, so `str()`/`repr()` of what bytecode()
// raises come out identical.
create_exception!(androguard_rs, InvalidInstruction, PyException);

/// A DEX string may hold lone UTF-16 surrogates, which a Rust `String`
/// can't; core carries them as private-use chars U+10F000..U+10F7FF. Turn
/// those back into real surrogates so Python sees what androguard returns.
fn py_str<'py>(py: Python<'py>, s: &str) -> PyResult<Bound<'py, PyAny>> {
    const BASE: u32 = 0x10F000;
    if !s.chars().any(|c| (BASE..BASE + 0x800).contains(&(c as u32))) {
        return Ok(PyString::new(py, s).into_any());
    }
    let mut wtf8 = Vec::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        if (BASE..BASE + 0x800).contains(&cp) {
            let sur = cp - BASE + 0xD800;
            wtf8.extend_from_slice(&[0xE0 | (sur >> 12) as u8, 0x80 | ((sur >> 6) & 0x3F) as u8, 0x80 | (sur & 0x3F) as u8]);
        } else {
            let mut buf = [0u8; 4];
            wtf8.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    PyBytes::new(py, &wtf8).call_method1("decode", ("utf-8", "surrogatepass"))
}

fn err(e: anyhow::Error) -> PyErr {
    PyValueError::new_err(format!("{e:#}"))
}

#[pyclass(frozen, module = "androguard_rs")]
struct Apk {
    idx: Index,
    /// Built on first use by classes()/class_methods().
    model: OnceLock<Model>,
    /// class_methods() rows of each class_data shared by several class_defs
    /// (only in crafted files), built once, so such a file can't make every
    /// call re-create the same rows.
    shared_rows: Mutex<HashMap<(u16, u32), Py<PyTuple>>>,
    /// Likewise the rows of a class_data's calling methods that
    /// create_xref() appends whole to several irregular classes.
    run_rows: Mutex<HashMap<u32, Py<PyTuple>>>,
    /// One str object per distinct class name, member name, descriptor and
    /// flags string the DEX-level rows (dex_class_members()) have handed
    /// out, so rows kept for the Apk's lifetime share them, as androguard's
    /// objects share the DEX's string table entries.
    strs: Mutex<rustc_hash::FxHashMap<String, Py<PyString>>>,
    /// Every get_methods() entry's name with its class's position in
    /// dx.get_classes(), sorted by name, built on first use by
    /// `_classes_with_method_prefix()`.
    method_names: OnceLock<MethodNames>,
    /// Resolved references (an instruction's get_translated_kind() text)
    /// by (DEX number, opcode, reference index), what they depend on.
    kinds: Mutex<rustc_hash::FxHashMap<(u32, u8, u32), Py<PyAny>>>,
    /// DEX files left out under `tolerant=True`.
    skipped: Vec<SkippedDex>,
    /// `get_dex_names()`: the entries read, in load order.
    names: Vec<String>,
    /// Position in `names` of each loaded DEX.
    positions: Vec<usize>,
    /// What androguard's AnalyzeAPK raises (under `header_errors=True`).
    load_error: Option<androguard_core::agload::AgErr>,
    /// What the per-query handles of `androguard_rs.dex` are answered with
    /// (see handles.rs).
    hs: handles::State,
    /// dx.get_classes() names (UTF-8, lone surrogates as WTF-8) with their
    /// positions, sorted by name, for prefix lookups; built on first use.
    class_sorted: OnceLock<Vec<(Box<[u8]>, u32)>>,
}

#[pymethods]
impl Apk {
    /// Parse every classesN.dex in the APK and build the cross-reference
    /// index. Releases the GIL while it works.
    ///
    /// With `tolerant=True`, a DEX that androguard's `DEX()` rejects with
    /// "Not a DEX file, Header too small." or "This is not a DEX file! Wrong
    /// endian tag: ..." is left out (see `skipped_dex()`), as callers that
    /// catch `DEX()`'s ValueError and skip that DEX see it;
    /// otherwise it fails the APK, as `AnalyzeAPK` does.
    ///
    /// With `header_errors=True`, every check androguard's `DEX()` header
    /// makes is made (magic, Adler-32 checksum, header size, id counts too),
    /// and a DEX failing one is left out and listed by `header_errors()`, so
    /// the caller can raise what androguard raises, in its order.
    #[new]
    #[pyo3(signature = (path, tolerant = false, header_errors = false, max_depth = androguard_core::apk::DEFAULT_MAX_DEPTH, c_budget = androguard_core::apk::DEFAULT_C_BUDGET))]
    fn new(py: Python<'_>, path: &str, tolerant: bool, header_errors: bool, max_depth: i64, c_budget: i64) -> PyResult<Self> {
        let path = path.to_owned();
        let mode = header_mode(tolerant, header_errors);
        let (idx, l) = py
            .detach(move || -> anyhow::Result<(Index, Loaded)> {
                let mut l = load_mode_depth(&path, mode, (max_depth, c_budget))?;
                Ok((Index::build(std::mem::take(&mut l.dexes))?, l))
            })
            .map_err(err)?;
        Ok(Apk::with(idx, l))
    }

    /// `Apk(path)` for an APK held in memory (`bytes` or `bytearray`).
    #[staticmethod]
    #[pyo3(signature = (data, tolerant = false, header_errors = false, max_depth = androguard_core::apk::DEFAULT_MAX_DEPTH, c_budget = androguard_core::apk::DEFAULT_C_BUDGET))]
    fn from_bytes(py: Python<'_>, data: pyo3::pybacked::PyBackedBytes, tolerant: bool, header_errors: bool, max_depth: i64, c_budget: i64) -> PyResult<Self> {
        let mode = header_mode(tolerant, header_errors);
        let (idx, l) = py
            .detach(move || -> anyhow::Result<(Index, Loaded)> {
                let mut l = load_bytes_mode_depth(&data, mode, (max_depth, c_budget))?;
                Ok((Index::build(std::mem::take(&mut l.dexes))?, l))
            })
            .map_err(err)?;
        Ok(Apk::with(idx, l))
    }

    /// The index over DEX files given as bytes, in that order (androguard's
    /// `DEX(bytes)` + `Analysis.add()` path). Each must pass androguard's
    /// header checks (the caller makes them, as `DEX()` does).
    #[staticmethod]
    fn from_dex_list(py: Python<'_>, dexes: Vec<pyo3::pybacked::PyBackedBytes>) -> PyResult<Self> {
        let (idx, l) = py
            .detach(move || -> anyhow::Result<(Index, Loaded)> {
                let parsed = dexes
                    .iter()
                    .enumerate()
                    .map(|(i, b)| androguard_core::dex::Dex::parse(b.to_vec()).map_err(|e| e.context(format!("parsing DEX #{i}"))))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                drop(dexes);
                let n = parsed.len();
                let names = (0..n).map(|i| if i == 0 { "classes.dex".to_string() } else { format!("classes{}.dex", i + 1) }).collect();
                Ok((Index::build(parsed)?, Loaded { names, dexes: Vec::new(), skipped: Vec::new(), positions: (0..n).collect(), load_error: None }))
            })
            .map_err(err)?;
        Ok(Apk::with(idx, l))
    }

    /// Position in `dex_names()` of each DEX in the index (DEX number i is
    /// the i-th).
    fn dex_positions(&self) -> Vec<usize> {
        self.positions.clone()
    }

    /// Under `header_errors=True`: (position in `dex_names()`, entry name,
    /// "ValueError" or "NotImplementedError", message) of each DEX
    /// androguard's `DEX()` rejects, in load order.
    fn header_errors(&self) -> Vec<(usize, String, &'static str, String)> {
        self.skipped
            .iter()
            .map(|s| {
                let kind = if s.not_implemented { "NotImplementedError" } else { "ValueError" };
                (s.pos, s.name.clone(), kind, s.message.clone())
            })
            .collect()
    }

    /// The method that makes androguard 4.1.3's `Analysis.add()` fail (the
    /// first one, in its order, it can't disassemble): (DEX number,
    /// class_def index, position in the class_data, the InvalidInstruction
    /// androguard raises), or None.
    fn first_invalid<'py>(&self, py: Python<'py>) -> Option<(usize, usize, usize, Bound<'py, PyAny>)> {
        let (d, ci, pos, _, e) = py.detach(|| androguard_core::strict::first_invalid(&self.idx.dexes))?;
        Some((d, ci, pos, invalid_instruction(py, &e).into_value(py).into_bound(py).into_any()))
    }

    /// Under `header_errors=True`: what androguard 4.1.3's `AnalyzeAPK`
    /// raises for this APK, as a recipe for `androguard_rs._agerr.make()`,
    /// or None.
    fn load_error<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyTuple>>> {
        self.load_error.as_ref().map(|e| ag_err_py(py, e)).transpose()
    }

    /// Number of DEX files in the index.
    fn dex_count(&self) -> usize {
        self.idx.dexes.len()
    }

    /// `get_classes_names()` of DEX number `d`: every class_def's name.
    fn dex_class_names<'py>(&self, py: Python<'py>, d: usize) -> PyResult<Bound<'py, PyList>> {
        let names = dexview::class_names(self.dex_at(d)?);
        let out = PyList::empty(py);
        for n in &names {
            out.append(py_str(py, n)?)?;
        }
        Ok(out)
    }

    /// class_def `ci` of DEX number `d`, as androguard's ClassDefItem has it:
    /// (name, access flags string, superclass, interfaces, class_data_off
    /// (0 without class_data)). Raises ValueError where androguard's DEX()
    /// would have failed on the class.
    fn dex_class_header<'py>(&self, py: Python<'py>, d: usize, ci: usize) -> PyResult<Bound<'py, PyTuple>> {
        let dex = self.dex_at(d)?;
        let c = py.detach(|| dexview::class_header(dex, ci)).map_err(err)?;
        let ifaces = PyList::empty(py);
        for i in &c.interfaces {
            ifaces.append(py_str(py, i)?)?;
        }
        PyTuple::new(
            py,
            [
                py_str(py, &c.name)?,
                py_str(py, &c.access_flags)?,
                py_str(py, &c.superclass)?,
                ifaces.into_any(),
                c.class_data_off.into_pyobject(py)?.into_any(),
            ],
        )
    }

    /// The EncodedMethods and EncodedFields of class_def `ci`'s class_data,
    /// as `(methods, fields)`: each method (get_class_name(), name,
    /// descriptor, access_flags, flags string, get_code_off(), has code,
    /// registers_size or None, method_idx), each field (get_class_name(),
    /// name, descriptor, access_flags, flags string, init, field_idx), `init`
    /// as in class_fields(). The same for every class_def sharing the
    /// class_data, as androguard's shared ClassDataItem.
    fn dex_class_members<'py>(&self, py: Python<'py>, d: usize, ci: usize) -> PyResult<Bound<'py, PyTuple>> {
        let dex = self.dex_at(d)?;
        let c = py.detach(|| dexview::class_members(dex, ci)).map_err(err)?;
        let (methods, fields) = self.member_rows(py, &c)?;
        PyTuple::new(py, [methods.into_any(), fields.into_any()])
    }

    // ── handles (androguard_rs.dex) ─────────────────────────────────────────
    //
    // A ClassDefItem handle has the slots _core (its DEX's _Core), _rs
    // (this), _d (DEX number), _ci (class_def index); an EncodedMethod
    // _core, _rs, _d, _off (class_data_off), _pos (position in the
    // class_data's methods), _idx (method_idx), _flags (access_flags),
    // _code_off (as read); an EncodedField _core, _rs, _d, _ci, _off, _pos,
    // _idx (field_idx), _flags.

    /// The cache settings in use (see handles.rs `Cfg`) and the bytes kept
    /// for instruction boundaries.
    fn _cache_info<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        let c = self.hs.cfg;
        d.set_item("atoms", c.atoms)?;
        d.set_item("spans", c.spans)?;
        d.set_item("text", c.text)?;
        d.set_item("lru", c.lru)?;
        d.set_item("atoms_kept", self.hs.atoms.lock().unwrap().len())?;
        let mut by_kind = [0usize; 8];
        for k in self.hs.atoms.lock().unwrap().keys() {
            by_kind[k.1 as usize & 7] += 1;
        }
        d.set_item("atoms_by_kind", by_kind.to_vec())?;
        d.set_item("kinds_kept", self.kinds.lock().unwrap().len())?;
        d.set_item("jtypes_kept", self.hs.jtypes.lock().unwrap().len())?;
        d.set_item("texts_kept", self.hs.texts.lock().unwrap().len())?;
        d.set_item("span_bytes", self.hs.span_bytes())?;
        Ok(d)
    }

    /// ClassDefItem handles (instances of `cls`) for every class_def of DEX
    /// number `d`, in order.
    fn _h_classes<'py>(slf: &Bound<'py, Self>, d: usize, core: &Bound<'py, PyAny>, cls: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyList>> {
        let this = slf.borrow();
        let n = this.dex_at(d)?.class_count();
        let py = slf.py();
        let slots = slot_offsets(cls, CDI_SLOTS)?;
        let dd = d.into_pyobject(py)?.into_any();
        let ints = offset_ints(py, n)?;
        let out = PyList::empty(py);
        for ci in 0..n {
            let v = [core.clone(), slf.clone().into_any(), dd.clone(), offset_int(py, &ints, ci as u32)?];
            out.append(new_handle(cls, &slots, CDI_SLOTS, v)?)?;
        }
        Ok(out)
    }

    /// Number of class_defs of DEX number `d` (`get_len_classes()`).
    fn dex_class_count(&self, d: usize) -> PyResult<usize> {
        Ok(self.dex_at(d)?.class_count())
    }

    /// The ClassDefItem handle of class_def `ci` of DEX number `d`.
    fn _h_class<'py>(slf: &Bound<'py, Self>, d: usize, ci: usize, core: &Bound<'py, PyAny>, cls: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        let py = slf.py();
        let slots = slot_offsets(cls, CDI_SLOTS)?;
        let v = [core.clone(), slf.clone().into_any(), d.into_pyobject(py)?.into_any(), ci.into_pyobject(py)?.into_any()];
        new_handle(cls, &slots, CDI_SLOTS, v)
    }

    /// EncodedMethod handles (`get_methods()`) of class_def `ci`, or, with
    /// `pos`, the one at that position. ValueError where androguard's
    /// DEX() would have failed on the class.
    #[pyo3(signature = (d, ci, core, cls, pos = None))]
    fn _h_methods<'py>(
        slf: &Bound<'py, Self>,
        d: usize,
        ci: usize,
        core: &Bound<'py, PyAny>,
        cls: &Bound<'py, PyAny>,
        pos: Option<usize>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let py = slf.py();
        let this = slf.borrow();
        let dex = this.dex_at(d)?;
        let (cd, data) = androguard_core::classes::class_data_checked(dex, ci).map_err(err)?;
        let slots = slot_offsets(cls, EM_SLOTS)?;
        let rs = slf.clone().into_any();
        let dd = d.into_pyobject(py)?.into_any();
        let off = cd.class_data_off.into_pyobject(py)?.into_any();
        let members: Vec<&androguard_core::dex::Member> = match &data {
            Some(data) => data.direct_methods.iter().chain(&data.virtual_methods).collect(),
            None => Vec::new(),
        };
        let ints = offset_ints(py, members.len())?;
        let make = |p: usize, m: &androguard_core::dex::Member| -> PyResult<Bound<'py, PyAny>> {
            let v = [
                core.clone(),
                rs.clone(),
                dd.clone(),
                off.clone(),
                offset_int(py, &ints, p as u32)?,
                m.idx.into_pyobject(py)?.into_any(),
                m.access_flags.into_pyobject(py)?.into_any(),
                m.code_off_raw.into_pyobject(py)?.into_any(),
            ];
            new_handle(cls, &slots, EM_SLOTS, v)
        };
        if let Some(p) = pos {
            let m = members.get(p).ok_or_else(|| handles::index_error("list index out of range"))?;
            return make(p, m);
        }
        let out = PyList::empty(py);
        for (p, m) in members.iter().enumerate() {
            out.append(make(p, m)?)?;
        }
        Ok(out.into_any())
    }

    /// EncodedField handles (`get_fields()`) of class_def `ci`, or the one
    /// at `pos`. ValueError as `_h_methods`.
    #[pyo3(signature = (d, ci, core, cls, pos = None))]
    fn _h_fields<'py>(
        slf: &Bound<'py, Self>,
        d: usize,
        ci: usize,
        core: &Bound<'py, PyAny>,
        cls: &Bound<'py, PyAny>,
        pos: Option<usize>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let py = slf.py();
        let this = slf.borrow();
        let dex = this.dex_at(d)?;
        let (cd, data) = androguard_core::classes::class_data_checked(dex, ci).map_err(err)?;
        let slots = slot_offsets(cls, EF_SLOTS)?;
        let rs = slf.clone().into_any();
        let dd = d.into_pyobject(py)?.into_any();
        let cci = ci.into_pyobject(py)?.into_any();
        let off = cd.class_data_off.into_pyobject(py)?.into_any();
        let members: Vec<&androguard_core::dex::Member> = match &data {
            Some(data) => data.static_fields.iter().chain(&data.instance_fields).collect(),
            None => Vec::new(),
        };
        let ints = offset_ints(py, members.len())?;
        let make = |p: usize, m: &androguard_core::dex::Member| -> PyResult<Bound<'py, PyAny>> {
            let v = [
                core.clone(),
                rs.clone(),
                dd.clone(),
                cci.clone(),
                off.clone(),
                offset_int(py, &ints, p as u32)?,
                m.idx.into_pyobject(py)?.into_any(),
                m.access_flags.into_pyobject(py)?.into_any(),
            ];
            new_handle(cls, &slots, EF_SLOTS, v)
        };
        if let Some(p) = pos {
            let m = members.get(p).ok_or_else(|| handles::index_error("list index out of range"))?;
            return make(p, m);
        }
        let out = PyList::empty(py);
        for (p, m) in members.iter().enumerate() {
            out.append(make(p, m)?)?;
        }
        Ok(out.into_any())
    }

    /// Number of get_methods() (`fields=False`) or get_fields() of
    /// class_def `ci`; ValueError as `_h_methods`.
    fn _h_count(&self, d: usize, ci: usize, fields: bool) -> PyResult<usize> {
        let dex = self.dex_at(d)?;
        let (_, data) = androguard_core::classes::class_data_checked(dex, ci).map_err(err)?;
        Ok(match data {
            Some(x) if fields => x.static_fields.len() + x.instance_fields.len(),
            Some(x) => x.direct_methods.len() + x.virtual_methods.len(),
            None => 0,
        })
    }

    /// ClassDefItem.get_name() of class_def `ci`.
    fn _c_name<'py>(&self, py: Python<'py>, d: usize, ci: usize) -> PyResult<Bound<'py, PyAny>> {
        let dex = self.dex_at(d)?;
        let t = dex.class_def(ci).map_err(err)?.class_idx;
        self.type_atom(py, d, dex, t)
    }

    /// (get_access_flags_string(), get_superclassname(), get_interfaces(),
    /// get_class_data_off()) of class_def `ci`; ValueError where androguard's
    /// DEX() would have failed on the class.
    fn _c_header<'py>(&self, py: Python<'py>, d: usize, ci: usize) -> PyResult<Bound<'py, PyTuple>> {
        let dex = self.dex_at(d)?;
        let (cd, ifaces, has_data) = androguard_core::classes::class_def_checked(dex, ci).map_err(err)?;
        if has_data {
            dex.class_data(cd.class_data_off).map_err(err)?;
        }
        let flags = self.hs.atom(py, (d as u32, handles::A_CFLAGS, cd.access_flags as u64), || {
            handles::s(py, &androguard_core::classes::class_flags(cd.access_flags))
        })?;
        let l = PyList::empty(py);
        for t in ifaces {
            l.append(self.type_atom(py, d, dex, t)?)?;
        }
        let off = if has_data { cd.class_data_off } else { 0 };
        PyTuple::new(py, [flags, self.type_atom(py, d, dex, cd.superclass_idx)?, l.into_any(), off.into_pyobject(py)?.into_any()])
    }

    /// DEX.get_class(name): the first class_def of DEX `d` named `name`.
    fn _dex_first_class(&self, py: Python<'_>, d: usize, name: &Bound<'_, PyString>) -> PyResult<Option<usize>> {
        let dex = self.dex_at(d)?;
        let key = handles::pystr_bytes(name)?;
        let map = self.hs.first_class[d].get_or_init(|| {
            let r = AgResolver { dex };
            let mut m: rustc_hash::FxHashMap<u64, Vec<u32>> = rustc_hash::FxHashMap::default();
            for ci in 0..dex.class_count() {
                let n = dex.class_def(ci).map(|cd| r.type_name(cd.class_idx)).unwrap_or_default();
                m.entry(sig_hash(&androguard_core::render::wtf8(&n))).or_default().push(ci as u32);
            }
            m
        });
        let _ = py;
        let Some(cands) = map.get(&sig_hash(&key)) else { return Ok(None) };
        let r = AgResolver { dex };
        for &ci in cands {
            let n = dex.class_def(ci as usize).map(|cd| r.type_name(cd.class_idx)).unwrap_or_default();
            if androguard_core::render::wtf8(&n).as_ref() == key.as_slice() {
                return Ok(Some(ci as usize));
            }
        }
        Ok(None)
    }

    /// EncodedMethod.get_name() of method_id `midx`.
    fn _m_name<'py>(&self, py: Python<'py>, d: usize, midx: u32) -> PyResult<Bound<'py, PyAny>> {
        let dex = self.dex_at(d)?;
        match dex.method_id(midx) {
            Ok((_, _, n)) => self.str_atom(py, d, dex, n),
            Err(_) => handles::s(py, "AG:IMI:invalid_name"),
        }
    }

    /// EncodedMethod.get_descriptor() ("(P1 P2)R") of method_id `midx`.
    fn _m_desc<'py>(&self, py: Python<'py>, d: usize, midx: u32) -> PyResult<Bound<'py, PyAny>> {
        let dex = self.dex_at(d)?;
        match dex.method_id(midx) {
            Ok((_, p, _)) => self.desc_atom(py, d, dex, p),
            Err(_) => handles::s(py, "()AG:IMI:invalid_proto"),
        }
    }

    /// EncodedMethod.get_class_name() of method_id `midx`.
    fn _m_class<'py>(&self, py: Python<'py>, d: usize, midx: u32) -> PyResult<Bound<'py, PyAny>> {
        let dex = self.dex_at(d)?;
        match dex.method_id(midx) {
            Ok((c, _, _)) => self.type_atom(py, d, dex, c),
            Err(_) => handles::s(py, "AG:IMI:invalid_class_name;"),
        }
    }

    /// get_access_flags_string() of a method (`kind` 0), field (1) or
    /// class (2) with access flags `value`.
    fn _flags_str<'py>(&self, py: Python<'py>, kind: u8, value: u64) -> PyResult<Bound<'py, PyAny>> {
        use androguard_core::classes::{class_flags, field_flags, method_flags};
        let (k, f): (u8, fn(u64) -> String) = match kind {
            0 => (handles::A_MFLAGS, method_flags),
            1 => (handles::A_FFLAGS, field_flags),
            _ => (handles::A_CFLAGS, |v| class_flags(v as u32)),
        };
        self.hs.atom(py, (u32::MAX, k, value), || handles::s(py, &f(value)))
    }

    /// registers_size of the code_item at `code_off` (as read: up to 36
    /// bits), or None without one (`get_code()` is None).
    fn _code_regs(&self, d: usize, code_off: u64) -> PyResult<Option<u16>> {
        let dex = self.dex_at(d)?;
        Ok(u32::try_from(code_off).ok().and_then(|o| dex.registers_size(o)))
    }

    /// EncodedMethod.get_information() of method_id `midx` whose code is at
    /// `code_off`: a new dict each call, as androguard's.
    fn _m_info<'py>(&self, py: Python<'py>, d: usize, midx: u32, code_off: u64) -> PyResult<Bound<'py, PyDict>> {
        let dex = self.dex_at(d)?;
        let Some(nb) = u32::try_from(code_off).ok().and_then(|o| dex.registers_size(o)) else {
            return Ok(PyDict::new(py));
        };
        let (proto_key, desc) = match dex.method_id(midx) {
            Ok((_, p, _)) => (p as u64, None),
            Err(_) => (u64::MAX, Some("()AG:IMI:invalid_proto".to_string())),
        };
        let parts = self.hs.atom(py, (d as u32, handles::A_INFO, proto_key), || {
            let desc = match &desc {
                Some(x) => x.clone(),
                None => AgResolver { dex }.descriptor(proto_key as u32),
            };
            let (ret, params) = handles::information_types(&desc).map_err(handles::index_error)?;
            let jt = if self.hs.cfg.atoms {
                params.iter().map(|t| self.hs.jtype(py, t)).collect::<PyResult<Vec<_>>>()?
            } else {
                params.iter().map(|t| py_str(py, t)).collect::<PyResult<Vec<_>>>()?
            };
            let ret = if self.hs.cfg.atoms { self.hs.jtype(py, &ret)? } else { py_str(py, &ret)? };
            Ok(PyTuple::new(py, [ret, PyTuple::new(py, jt)?.into_any()])?.into_any())
        })?;
        handles::information_dict(py, &parts, nb as i64)
    }

    /// EncodedField.get_name() of field_id `fidx`.
    fn _f_name<'py>(&self, py: Python<'py>, d: usize, fidx: u32) -> PyResult<Bound<'py, PyAny>> {
        let dex = self.dex_at(d)?;
        match dex.field_id(fidx) {
            Some((_, _, n)) => self.str_atom(py, d, dex, n),
            None => handles::s(py, "AG:IFI:invalid_name"),
        }
    }

    /// EncodedField.get_descriptor() of field_id `fidx`.
    fn _f_type<'py>(&self, py: Python<'py>, d: usize, fidx: u32) -> PyResult<Bound<'py, PyAny>> {
        let dex = self.dex_at(d)?;
        match dex.field_id(fidx) {
            Some((_, t, _)) => self.type_atom(py, d, dex, t),
            None => handles::s(py, "(AG:IFI:invalid_type)"),
        }
    }

    /// EncodedField.get_class_name() of field_id `fidx`.
    fn _f_class<'py>(&self, py: Python<'py>, d: usize, fidx: u32) -> PyResult<Bound<'py, PyAny>> {
        let dex = self.dex_at(d)?;
        match dex.field_id(fidx) {
            Some((c, _, _)) => self.type_atom(py, d, dex, c),
            None => handles::s(py, "AG:IFI:invalid_class_name;"),
        }
    }

    /// EncodedField.get_init_value() of field `pos` of class_def `ci`: a new
    /// `value_cls` (androguard's EncodedValue, slot `value`) holding the
    /// value typed as in class_fields() (an array or annotation wrapped in
    /// `obj_cls`, slot `_obj`), or None without one.
    fn _f_init<'py>(
        &self,
        py: Python<'py>,
        d: usize,
        ci: usize,
        pos: usize,
        value_cls: &Bound<'py, PyAny>,
        obj_cls: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let dex = self.dex_at(d)?;
        let inits = self.hs.inits(d as u32, ci as u32, dex).map_err(err)?;
        let Some(v) = inits.get(pos) else { return Ok(py.None().into_bound(py)) };
        let mut value = value_to_py(py, v)?;
        if matches!(v, Value::Opaque(_)) {
            value = new_handle(obj_cls, &slot_offsets(obj_cls, &["_obj"])?, &["_obj"], [value])?;
        }
        let o = new_handle(value_cls, &slot_offsets(value_cls, &["value"])?, &["value"], [value])?;
        // It may hold a list: back in the cycle collector's view.
        // SAFETY: a live GC object made untracked by new_handle().
        unsafe { pyo3::ffi::PyObject_GC_Track(o.as_ptr().cast()) };
        Ok(o)
    }

    /// The instruction handles of the code_item at `code_off` in DEX number
    /// `d`, as a tuple (see `insn_objects`), or None without a code_item
    /// there; InvalidInstruction for bytecode androguard rejects.
    fn _insn_handles<'py>(
        slf: &Bound<'py, Self>,
        d: usize,
        code_off: u64,
        holder: &Bound<'py, PyAny>,
        classes: &Bound<'py, PyDict>,
    ) -> PyResult<Option<Bound<'py, PyTuple>>> {
        let this = slf.borrow();
        let dex = this.dex_at(d)?;
        let Ok(off) = u32::try_from(code_off) else { return Ok(None) };
        if !dex.has_code_item(off) {
            return Ok(None);
        }
        let code = dex.code(off).map_err(err)?;
        let spans = this.hs.spans(d as u32, off, code).map_err(|e| invalid_instruction(slf.py(), &e))?;
        insn_objects(slf, d, off, code, &spans, None, holder, classes).map(Some)
    }

    /// `_insn_handles(...)[idx]` with list indexing (negative counts from
    /// the end; IndexError "list index out of range"), making only that
    /// handle. None without a code_item.
    fn _insn_at<'py>(
        slf: &Bound<'py, Self>,
        d: usize,
        code_off: u64,
        idx: isize,
        holder: &Bound<'py, PyAny>,
        classes: &Bound<'py, PyDict>,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        let this = slf.borrow();
        let dex = this.dex_at(d)?;
        let Ok(off) = u32::try_from(code_off) else { return Ok(None) };
        if !dex.has_code_item(off) {
            return Ok(None);
        }
        let code = dex.code(off).map_err(err)?;
        let spans = this.hs.spans(d as u32, off, code).map_err(|e| invalid_instruction(slf.py(), &e))?;
        let n = spans.len() as isize;
        let i = if idx < 0 { idx + n } else { idx };
        if i < 0 || i >= n {
            return Err(handles::index_error("list index out of range"));
        }
        let t = insn_objects(slf, d, off, code, &spans, Some(i as usize), holder, classes)?;
        Ok(Some(t.get_item(0)?))
    }

    /// The insns of the code_item at `code_off` in DEX number `d`.
    fn _code_bytes<'py>(&self, py: Python<'py>, d: usize, code_off: u32) -> PyResult<Bound<'py, PyBytes>> {
        let dex = self.dex_at(d)?;
        Ok(PyBytes::new(py, dex.code(code_off).map_err(err)?))
    }

    /// (number of instructions, position of the one at byte offset `off`
    /// or -1) of the code_item at `code_off`; None without one.
    #[pyo3(signature = (d, code_off, off = None))]
    fn _insn_pos(slf: &Bound<'_, Self>, d: usize, code_off: u64, off: Option<i64>) -> PyResult<Option<(usize, isize)>> {
        let this = slf.borrow();
        let dex = this.dex_at(d)?;
        let Ok(co) = u32::try_from(code_off) else { return Ok(None) };
        if !dex.has_code_item(co) {
            return Ok(None);
        }
        let code = dex.code(co).map_err(err)?;
        let spans = this.hs.spans(d as u32, co, code).map_err(|e| invalid_instruction(slf.py(), &e))?;
        let pos = match off {
            Some(o) if o >= 0 && o <= u32::MAX as i64 => spans.offs.binary_search(&(o as u32)).map(|p| p as isize).unwrap_or(-1),
            _ => -1,
        };
        Ok(Some((spans.len(), pos)))
    }

    /// See `androguard_rs.dex.DEX.find_methods_referencing`: `(class_def
    /// index, position in its get_methods())` of the matching methods of
    /// DEX number `d`, in get_encoded_methods() order. `rules`: (opcode
    /// values or None, True for a suffix / False for a substring, text).
    /// Scans classes in parallel, without the GIL.
    fn _dex_methods_referencing(
        &self,
        py: Python<'_>,
        d: usize,
        names: Vec<String>,
        rules: Vec<(Option<Vec<u16>>, bool, String)>,
        include_unreadable: bool,
    ) -> PyResult<Vec<(u32, u32)>> {
        let dex = self.dex_at(d)?;
        let names: rustc_hash::FxHashSet<String> = names.into_iter().collect();
        let rules: Vec<dexview::OutputRule> =
            rules.into_iter().map(|(ops, suffix, text)| dexview::OutputRule { ops, suffix, text }).collect();
        py.detach(|| dexview::methods_referencing(dex, &names, &rules, include_unreadable)).map_err(err)
    }

    /// Positions in dx.get_classes(), ascending, of the classes one of
    /// whose get_methods() entries (`class_methods()` rows, ExternalMethods
    /// included) has a name starting with `prefix`: the only classes whose
    /// methods a `re.match(methodname, name)` with that literal prefix can
    /// match. The name table is built once, natively, on first use.
    fn _classes_with_method_prefix<'py>(&self, py: Python<'py>, prefix: &str) -> PyResult<Vec<u32>> {
        Ok(py.detach(|| {
            let t = self.method_names.get_or_init(|| MethodNames::build(&self.idx, self.model()));
            t.classes_with_prefix(prefix)
        }))
    }

    /// `(DEX number, code_off)` of a method's code_item by its native key
    /// (a signature or row key, as `instructions()` takes), or None.
    fn _code_location(&self, key: &Bound<'_, PyAny>) -> PyResult<Option<(usize, u32)>> {
        let Some((dex, _, code_off)) = self.code(key)? else {
            return Ok(None);
        };
        Ok(self.idx.dexes.iter().position(|x| std::ptr::eq(x, dex)).map(|d| (d, code_off)))
    }

    /// The resolved reference (get_translated_kind() text, or None) of the
    /// instruction at byte offset `off` of the code_item at `code_off` in
    /// DEX number `d`, as `_insn_text()` gives it: kept per (DEX, opcode,
    /// reference index), so asking again (for any instruction with the same
    /// reference) returns the same str without decoding.
    fn _insn_kind<'py>(&self, py: Python<'py>, d: usize, code_off: u32, off: usize) -> PyResult<Bound<'py, PyAny>> {
        let dex = self.dex_at(d)?;
        let code = dex.code(code_off).map_err(err)?;
        let Some((op, idx)) = androguard_core::insn_rows::kind_key(code, off) else {
            return Ok(py.None().into_bound(py));
        };
        let key = (d as u32, op, idx);
        if self.hs.cfg.atoms
            && let Some(v) = self.kinds.lock().unwrap().get(&key)
        {
            return Ok(v.bind(py).clone());
        }
        let r = androguard_core::insn_rows::insn_row_at(dex, code, off).map_err(|e| invalid_instruction(py, &e))?;
        let v = match &r.kind {
            Some(s) => py_str(py, s)?,
            None => py.None().into_bound(py),
        };
        if self.hs.cfg.atoms {
            self.kinds.lock().unwrap().insert(key, v.clone().unbind());
        }
        Ok(v)
    }

    /// `(get_output(), resolved reference)` of the instruction at byte
    /// offset `off` of the code_item at `code_off` in DEX number `d` (the
    /// text the handles leave out; same as its `instructions()` row's),
    /// kept with the `text` cache setting.
    fn _insn_text<'py>(&self, py: Python<'py>, d: usize, code_off: u32, off: usize) -> PyResult<Bound<'py, PyTuple>> {
        let dex = self.dex_at(d)?;
        let key = (d as u32, code_off, off as u32);
        if self.hs.cfg.text
            && let Some(t) = self.hs.texts.lock().unwrap().get(&key)
        {
            return Ok(t.bind(py).clone());
        }
        let t = insn_text(py, dex, code_off, off)?;
        if self.hs.cfg.text {
            self.hs.texts.lock().unwrap().insert(key, t.clone().unbind());
        }
        Ok(t)
    }

    /// The instructions of the code_item at `code_off` in DEX number `d`,
    /// as `instructions()` gives them; None without a code_item there.
    fn code_instructions<'py>(&self, py: Python<'py>, d: usize, code_off: u64) -> PyResult<Option<Bound<'py, PyTuple>>> {
        let dex = self.dex_at(d)?;
        let Ok(off) = u32::try_from(code_off) else { return Ok(None) };
        if !dex.has_code_item(off) {
            return Ok(None);
        }
        let code = dex.code(off).map_err(err)?;
        rows_to_py(py, dex, code).map(Some)
    }

    /// Where a MethodAnalysis's EncodedMethod is: (DEX number, a class_def
    /// index using its class_data, class_data_off, position in the
    /// class_data), for the method `key` (a signature or row key) that
    /// class `cls` lists; None for an external method.
    fn method_location(&self, cls: &Bound<'_, PyString>, key: &Bound<'_, PyAny>) -> PyResult<Option<(usize, usize, u32, usize)>> {
        match self.target(key)? {
            Some(Resolved::Key(k)) => {
                let (j, e) = irregular::unkey(k);
                let irr = &self.idx.irr;
                let em = &irr.ems[e as usize];
                let block = &irr.blocks[em.block as usize];
                let def = &irr.defs[j as usize];
                Ok(Some((em.dex as usize, def.ci as usize, block.off, (e - block.em_start) as usize)))
            }
            Some(Resolved::Node(_)) | None => {
                let Ok(sig) = key.cast::<PyString>() else { return Ok(None) };
                let sig = sig.to_cow()?;
                let raw = cls.call_method1("encode", ("utf-8", "surrogatepass"))?;
                let Some((d, dex, ci)) = self.idx.class_def_by_hash(sig_hash(raw.cast::<PyBytes>()?.as_bytes())) else {
                    return Ok(None);
                };
                let cd = dex.class_def(ci).map_err(err)?;
                if !dex.has_class_data(cd.class_data_off) {
                    return Ok(None);
                }
                let data = dex.class_data(cd.class_data_off).map_err(err)?;
                let pos = data
                    .direct_methods
                    .iter()
                    .chain(&data.virtual_methods)
                    .position(|m| dex.method_sig(m.idx).is_ok_and(|s| s == *sig));
                Ok(pos.map(|p| (d as usize, ci, cd.class_data_off, p)))
            }
        }
    }

    /// (DEX number, class_def index) of the class_def androguard's
    /// `ClassAnalysis.get_vm_class()` holds for class `name` (the last
    /// definition loaded), or None if the APK doesn't define it.
    fn class_def_position(&self, name: &Bound<'_, PyString>) -> PyResult<Option<(usize, usize)>> {
        let raw = name.call_method1("encode", ("utf-8", "surrogatepass"))?;
        Ok(self.idx.class_def_by_hash(sig_hash(raw.cast::<PyBytes>()?.as_bytes())).map(|(d, _, ci)| (d as usize, ci)))
    }

    /// DEX number `d`'s `get_encoded_method_descriptor()` (`fields=False`)
    /// or `get_encoded_field_descriptor()` (`fields=True`) lookup: the
    /// member whose get_class_name() + get_name() + get_descriptor() equals
    /// `key`, the last one in class_def order (androguard's cache dict is
    /// written in that order), as (class_def index, position); None if none.
    fn dex_find_member(&self, py: Python<'_>, d: usize, key: &Bound<'_, PyString>, fields: bool) -> PyResult<Option<(usize, usize)>> {
        let dex = self.dex_at(d)?;
        let key = key.call_method1("encode", ("utf-8", "surrogatepass"))?;
        let key = key.cast::<PyBytes>()?.as_bytes().to_vec();
        Ok(py.detach(|| dexview::find_member(dex, &key, fields)))
    }

    /// (class_def index, position, get_name()) of every EncodedField of DEX
    /// number `d`, in `get_encoded_fields()` order.
    fn dex_field_names<'py>(&self, py: Python<'py>, d: usize) -> PyResult<Bound<'py, PyList>> {
        let dex = self.dex_at(d)?;
        let rows = py.detach(|| dexview::field_names(dex));
        let out = PyList::empty(py);
        for (ci, pos, name) in &rows {
            out.append((*ci, *pos, py_str(py, name)?))?;
        }
        Ok(out)
    }

    /// androguard's `APK.get_dex_names()`, i.e. the order AnalyzeAPK (and
    /// `get_all_dex()`) load DEX files in: central directory order, names matching
    /// `^classes(\d*).dex$`. Skipped ones included.
    fn dex_names(&self) -> Vec<String> {
        self.names.clone()
    }

    /// (entry name, androguard's error message) of each DEX left out under
    /// `tolerant=True`, in load order.
    fn skipped_dex(&self) -> Vec<(String, String)> {
        self.skipped.iter().map(|s| (s.name.clone(), s.message.clone())).collect()
    }

    /// Counts from the index build (methods, instructions, edges, ...).
    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let s = self.idx.stats;
        let d = PyDict::new(py);
        d.set_item("dex_files", self.idx.dexes.len())?;
        d.set_item("classes", s.classes)?;
        d.set_item("methods_with_code", s.methods_with_code)?;
        d.set_item("instructions", s.instructions)?;
        d.set_item("invoke_edges", s.invoke_edges)?;
        d.set_item("const_string_refs", s.string_refs)?;
        d.set_item("invalid_methods", s.invalid_methods)?;
        d.set_item("methods", self.idx.method_count())?;
        d.set_item("internal_methods", self.idx.internal_count())?;
        d.set_item("index_bytes", self.idx.index_bytes())?;
        d.set_item("dex_bytes", self.idx.dex_bytes())?;
        Ok(d)
    }

    /// Methods calling `sig` ("Lcls;->name(Params)Ret"), as
    /// [(caller_sig, byte_offset)] — androguard's MethodAnalysis.get_xref_from().
    fn callers<'py>(&self, py: Python<'py>, sig: &str) -> PyResult<Bound<'py, PyList>> {
        self.neighbours(py, sig, true)
    }

    /// Methods `sig` calls, as [(callee_sig, byte_offset)] — get_xref_to().
    fn callees<'py>(&self, py: Python<'py>, sig: &str) -> PyResult<Bound<'py, PyList>> {
        self.neighbours(py, sig, false)
    }

    /// True if the method is defined in the APK with code (not
    /// external/abstract). Takes a signature or a row key (see class_methods()).
    fn has_code(&self, key: &Bound<'_, PyAny>) -> PyResult<bool> {
        Ok(self.code(key)?.is_some())
    }

    /// The method's instructions as [(byte_offset, get_name(), get_output())],
    /// exactly what androguard's get_instructions_idx() yields (get_output()
    /// can be None). None if the method has no code here. If androguard
    /// would reject the bytecode, raises InvalidInstruction with the same
    /// args as androguard's, so str(exc) is identical. Takes a signature
    /// ("Lcls;->name(Params)Ret": the method calls to it resolve to, i.e.
    /// its last definition) or a row key (see class_methods()).
    fn bytecode<'py>(&self, py: Python<'py>, key: &Bound<'py, PyAny>) -> PyResult<Option<Bound<'py, PyList>>> {
        let Some((dex, _, code_off)) = self.code(key)? else {
            return Ok(None);
        };
        let code = dex.code(code_off).map_err(err)?;
        decode_to_py(py, dex, code).map(Some)
    }

    /// The method's instructions as androguard 4.1.3's
    /// `get_code().get_bc().get_instructions()` yields them, for the
    /// `androguard_rs.dex` Instruction objects: `(insns, rows, offsets)`, where
    /// `insns` is the method's instruction bytes and each row is
    /// `(offset, get_op_value(), get_length(), len(get_raw()), get_output(),
    /// kind)`: `get_raw()` is `insns[offset:offset + raw_len]`, and `kind` is
    /// the resolved reference (`get_translated_kind()`) or None; `offsets`
    /// is each row's offset. None if the
    /// method has no code here; InvalidInstruction exactly as `bytecode()`.
    /// Takes a signature or a row key, as `bytecode()`. Decoded on every
    /// call; nothing is kept.
    fn instructions<'py>(&self, py: Python<'py>, key: &Bound<'py, PyAny>) -> PyResult<Option<Bound<'py, PyTuple>>> {
        let Some((dex, _, code_off)) = self.code(key)? else {
            return Ok(None);
        };
        let code = dex.code(code_off).map_err(err)?;
        rows_to_py(py, dex, code).map(Some)
    }

    /// Test hook: `instructions()` for raw `code` bytes against DEX number
    /// `dex_no`'s tables.
    fn _instructions_of_code<'py>(&self, py: Python<'py>, dex_no: usize, code: &[u8]) -> PyResult<Bound<'py, PyTuple>> {
        let dex = self.idx.dexes.get(dex_no).ok_or_else(|| PyValueError::new_err("no such dex"))?;
        rows_to_py(py, dex, code)
    }

    /// Methods whose instruction text (lower-cased get_output() of any one
    /// instruction) contains any of `needles`, as signatures, in the order
    /// androguard's dx.get_classes() then get_methods() order. Needles are used as given. Releases the
    /// GIL while it scans. With `keys=True`, each is (signature, key, class),
    /// key as in class_methods() rows (None for a regular class's method)
    /// and class the one whose get_methods() lists it.
    #[pyo3(signature = (needles, keys = false))]
    fn search_instruction_text<'py>(&self, py: Python<'py>, needles: Vec<String>, keys: bool) -> PyResult<Bound<'py, PyList>> {
        let chunks = py.detach(|| {
            let model = self.idx.irr.active().then(|| self.model());
            let extra = |h| model.map(|m| m.r_segments(&self.idx, h)).unwrap_or_default();
            self.idx.search_instruction_text(&needles, &extra)
        });
        // Classes sharing a class_data share a chunk: build its strings once.
        let mut built: HashMap<*const Vec<Hit>, Vec<Bound<'py, PyAny>>> = HashMap::new();
        let out = PyList::empty(py);
        for ((d, ci), class_chunks) in &chunks {
            let cls = if keys {
                let dex = &self.idx.dexes[*d as usize];
                Some(py_str(py, &dex.class_def(*ci as usize).map(|cd| AgResolver { dex }.type_name(cd.class_idx)).unwrap_or_default())?)
            } else {
                None
            };
            for chunk in class_chunks {
            let key = std::sync::Arc::as_ptr(chunk);
            if let std::collections::hash_map::Entry::Vacant(e) = built.entry(key) {
                let items = chunk
                    .iter()
                    .map(|(s, k)| {
                        let s = py_str(py, s)?;
                        if keys { Ok((s, key_to_py(py, *k)?).into_pyobject(py)?.into_any()) } else { Ok(s) }
                    })
                    .collect::<PyResult<_>>()?;
                e.insert(items);
            }
            for s in &built[&key] {
                match &cls {
                    // (signature, key, class listing it)
                    Some(c) => {
                        let (sig, k): (Bound<'py, PyAny>, Bound<'py, PyAny>) = s.extract()?;
                        out.append((sig, k, c))?;
                    }
                    None => out.append(s)?,
                }
            }
            }
        }
        Ok(out)
    }

    /// androguard's dx.get_classes(): [(name, is_external)], in its order —
    /// defined classes, then the external ones its xref pass references
    /// (by first reference). The first call replays that pass (GIL released).
    fn classes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let names = py.detach(|| self.model().classes(&self.idx));
        let out = PyList::empty(py);
        for (name, external) in names {
            out.append((py_str(py, &name)?, external))?;
        }
        Ok(out)
    }

    /// dx.get_class_analysis(name).get_methods(), as [(sig, name,
    /// descriptor, access_flags, is_external)]: the class's own methods
    /// (direct, then virtual), then what androguard's create_xref() adds, in
    /// the order it meets them: ExternalMethods for calls into the class it
    /// can't resolve (e.g. inherited methods) and, for an irregular class
    /// (defined more than once, sharing its class_data with another class,
    /// listing another class's method_id or one method twice; see
    /// core/src/irregular.rs), the other MethodAnalysis objects that make a
    /// call or that a call resolves to. Descriptors are get_descriptor()'s
    /// "(P1 P2)R"; flags are "" for an ExternalMethod. An irregular class's
    /// rows (but its ExternalMethods) have two more elements: the key to
    /// pass to bytecode()/has_code()/xref_from()/xref_to()/method_row()
    /// instead of the signature, (e,) for the class's own method (pass
    /// (class name, e)) or an int, and get_class_name() (the method_id's
    /// class). None if androguard has no class by that name
    /// (get_class_analysis() returns None).
    ///
    /// With `prefix`, only the rows whose name starts with it.
    #[pyo3(signature = (name, prefix = None))]
    fn class_methods<'py>(&self, py: Python<'py>, name: &str, prefix: Option<&Bound<'py, PyString>>) -> PyResult<Option<Bound<'py, PyList>>> {
        let Some(methods) = py.detach(|| self.model().class_methods(&self.idx, name)) else {
            return Ok(None);
        };
        if let Some(p) = prefix {
            let p = handles::pystr_bytes(p)?;
            let out = PyList::empty(py);
            for m in methods.own.iter().chain(methods.tail_entries()) {
                if androguard_core::render::wtf8(&m.name).starts_with(&p) {
                    out.append(method_row(py, m)?)?;
                }
            }
            return Ok(Some(out));
        }
        let own = match methods.shared {
            Some(key) => {
                let cached = self.shared_rows.lock().unwrap().get(&key).map(|t| t.clone_ref(py));
                match cached {
                    Some(t) => t.into_bound(py),
                    None => {
                        let t = method_rows(py, &methods.own)?;
                        self.shared_rows.lock().unwrap().entry(key).or_insert_with(|| t.clone().unbind());
                        t
                    }
                }
            }
            None => method_rows(py, &methods.own)?,
        };
        let out = PyList::new(py, own.iter())?;
        for t in &methods.tail {
            match t {
                model::TailRows::Rows(rows) => {
                    for m in rows {
                        out.append(method_row(py, m)?)?;
                    }
                }
                model::TailRows::Run(block, rows) => {
                    let cached = self.run_rows.lock().unwrap().get(block).map(|t| t.clone_ref(py));
                    let t = match cached {
                        Some(t) => t.into_bound(py),
                        None => {
                            let t = method_rows(py, rows)?;
                            self.run_rows.lock().unwrap().entry(*block).or_insert_with(|| t.clone().unbind());
                            t
                        }
                    };
                    for r in t.iter() {
                        out.append(r)?;
                    }
                }
            }
        }
        Ok(Some(out))
    }

    /// The class_methods(cls) row whose key is `key` (a signature, an int
    /// key, or (cls, e) / (e,) for the class's own method of an irregular
    /// class), the last one if several; None if none (or no such class).
    fn _class_method_row<'py>(&self, py: Python<'py>, cls: &str, key: &Bound<'py, PyAny>) -> PyResult<Option<Bound<'py, PyAny>>> {
        enum K {
            Sig(String),
            Pos(u32),
            Full(u64),
        }
        let k = if let Ok(s) = key.cast::<PyString>() {
            K::Sig(s.to_cow()?.into_owned())
        } else if let Ok(t) = key.cast::<PyTuple>() {
            match t.len() {
                1 => K::Pos(t.get_item(0)?.extract()?),
                2 => {
                    if t.get_item(0)?.extract::<String>()? != cls {
                        return Ok(None);
                    }
                    K::Pos(t.get_item(1)?.extract()?)
                }
                _ => return Ok(None),
            }
        } else {
            K::Full(key.extract()?)
        };
        let Some(methods) = py.detach(|| self.model().class_methods(&self.idx, cls)) else {
            return Ok(None);
        };
        let found = methods.own.iter().chain(methods.tail_entries()).filter(|m| match (&k, m.key) {
            (K::Sig(s), HitKey::Sig) => m.sig == *s,
            (K::Pos(e), HitKey::Pos(x)) => *e == x,
            (K::Full(f), HitKey::Full(x)) => *f == x,
            _ => false,
        }).last();
        found.map(|m| method_row(py, m)).transpose()
    }

    /// [(position, name, is_external)] of the dx.get_classes() entries
    /// whose name starts with `prefix`, by position.
    fn _classes_prefix<'py>(&self, py: Python<'py>, prefix: &Bound<'py, PyString>) -> PyResult<Bound<'py, PyList>> {
        let p = handles::pystr_bytes(prefix)?;
        let model = py.detach(|| self.model());
        let positions: Vec<u32> = if p.is_empty() {
            (0..model.class_count(&self.idx) as u32).collect()
        } else {
            let sorted = py.detach(|| {
                self.class_sorted.get_or_init(|| {
                    let mut v: Vec<(Box<[u8]>, u32)> = (0..model.class_count(&self.idx))
                        .filter_map(|i| model.class_at(&self.idx, i).map(|(n, _)| (androguard_core::render::wtf8(&n).into_owned().into_boxed_slice(), i as u32)))
                        .collect();
                    v.sort_unstable();
                    v
                })
            });
            let lo = sorted.partition_point(|(n, _)| **n < *p.as_slice());
            let mut out: Vec<u32> = sorted[lo..].iter().take_while(|(n, _)| n.starts_with(&p)).map(|&(_, i)| i).collect();
            out.sort_unstable();
            out
        };
        self.classes_at(py, &positions)
    }

    /// [(position, name, is_external)] of the dx.get_classes() entries at
    /// `positions`.
    fn _classes_at<'py>(&self, py: Python<'py>, positions: Vec<u32>) -> PyResult<Bound<'py, PyList>> {
        self.classes_at(py, &positions)
    }

    /// The full row of a method key (see class_methods()): (sig, name,
    /// descriptor, access_flags, is_external[, key, get_class_name()]), or
    /// None. For an xref endpoint, whose class may not list it.
    fn method_row<'py>(&self, py: Python<'py>, key: &Bound<'py, PyAny>) -> PyResult<Option<Bound<'py, PyAny>>> {
        match self.target(key)? {
            Some(Resolved::Key(k)) => {
                let e = irregular::unkey(k).1;
                let em = &self.idx.irr.ems[e as usize];
                let dex = &self.idx.dexes[em.dex as usize];
                let r = AgResolver { dex };
                let (name, desc) = r.method_name_and_desc(em.midx);
                let mc = match dex.method_id(em.midx) {
                    Ok((c, _, _)) => r.type_name(c),
                    Err(_) => String::new(),
                };
                let m = MethodEntry {
                    sig: dex.method_sig(em.midx).unwrap_or_default(),
                    name,
                    descriptor: desc,
                    access_flags: androguard_core::classes::method_flags(em.flags),
                    external: false,
                    key: HitKey::Full(k),
                    method_class: Some(mc),
                };
                method_row(py, &m).map(Some)
            }
            _ => Ok(None),
        }
    }

    /// len(dx.get_classes()).
    fn class_count(&self, py: Python<'_>) -> usize {
        py.detach(|| self.model().class_count(&self.idx))
    }

    /// dx.get_classes()[start:stop] as [(name, is_external)]: classes()
    /// a slice at a time, so a caller can walk it without holding it all.
    fn classes_slice<'py>(&self, py: Python<'py>, start: usize, stop: usize) -> PyResult<Bound<'py, PyList>> {
        let model = py.detach(|| self.model());
        let out = PyList::empty(py);
        for i in start..stop.min(model.class_count(&self.idx)) {
            if let Some((name, external)) = model.class_at(&self.idx, i) {
                out.append((py_str(py, &name)?, external))?;
            }
        }
        Ok(out)
    }

    /// The entry dx.get_class_analysis(name) finds, as (name,
    /// is_external), or None if there is none. Same lookup as
    /// `{n: e for n, e in classes()}`, without building it in Python.
    fn class_entry<'py>(&self, py: Python<'py>, name: &Bound<'py, PyString>) -> PyResult<Option<Bound<'py, PyAny>>> {
        let pos = self.position(py, name)?;
        let Some((n, external)) = pos.and_then(|i| self.model().class_at(&self.idx, i)) else { return Ok(None) };
        Ok(Some((py_str(py, &n)?, external).into_pyobject(py)?.into_any()))
    }

    /// One hierarchy() row, (superclass, interfaces), for a defined class
    /// by name; None for an external or unknown one.
    fn class_hierarchy<'py>(&self, py: Python<'py>, name: &Bound<'py, PyString>) -> PyResult<Option<Bound<'py, PyAny>>> {
        let Some(i) = self.position(py, name)? else { return Ok(None) };
        let Some((_, sup, ifaces)) = model::class_hierarchy(&self.idx, i) else { return Ok(None) };
        let l = PyList::empty(py);
        for x in &ifaces {
            l.append(py_str(py, x)?)?;
        }
        Ok(Some((py_str(py, &sup)?, l).into_pyobject(py)?.into_any()))
    }

    /// MethodAnalysis.get_xref_from() of a method (a signature, or a row key
    /// from class_methods()), as [(caller_sig, class_name, method_name,
    /// descriptor, offset)] — each tuple's ClassAnalysis.name and
    /// get_method().get_name()/get_descriptor(); a caller that is an
    /// overridden earlier definition's method has its key as a sixth
    /// element. androguard returns a set, so its order isn't defined; this
    /// one is stable.
    fn xref_from<'py>(&self, py: Python<'py>, key: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyList>> {
        self.xref_entries(py, key, true)
    }

    /// MethodAnalysis.get_xref_to() of a method, shaped like xref_from().
    fn xref_to<'py>(&self, py: Python<'py>, key: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyList>> {
        self.xref_entries(py, key, false)
    }

    /// [(name, superclass, interfaces)] for every class defined in the APK,
    /// in dx.get_classes() order: ClassDefItem's get_superclassname() and
    /// get_interfaces(), without the cost of class_info() per class.
    fn hierarchy<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let rows = py.detach(|| model::hierarchy(&self.idx));
        let out = PyList::empty(py);
        for (name, sup, ifaces) in rows {
            let l = PyList::empty(py);
            for i in &ifaces {
                l.append(py_str(py, i)?)?;
            }
            out.append((py_str(py, &name)?, py_str(py, &sup)?, l))?;
        }
        Ok(out)
    }

    /// The const-string text of every class defined in the APK, as
    /// [(class_name, ((method_name, descriptor, (get_output(), ...)), ...))]
    /// in dx.get_classes() then get_methods() order: each `const-string`
    /// instruction (plus `const-string/jumbo` if include_jumbo). Methods and
    /// classes with none are left out. Classes sharing a class_data (only
    /// in crafted files) share one methods tuple.
    #[pyo3(signature = (include_jumbo=false))]
    fn const_strings<'py>(&self, py: Python<'py>, include_jumbo: bool) -> PyResult<Bound<'py, PyList>> {
        let rows = py.detach(|| {
            let model = self.idx.irr.active().then(|| self.model());
            let extra = |h| model.map(|m| m.r_segments(&self.idx, h)).unwrap_or_default();
            model::const_strings(&self.idx, include_jumbo, &extra)
        });
        let mut built: HashMap<*const Vec<model::MethodStrings>, Bound<'py, PyTuple>> = HashMap::new();
        let out = PyList::empty(py);
        for (cls, chunks) in &rows {
            let mut parts = Vec::with_capacity(chunks.len());
            for methods in chunks {
                let key = std::sync::Arc::as_ptr(methods);
                let t = match built.get(&key) {
                    Some(t) => t.clone(),
                    None => {
                        let mut items = Vec::with_capacity(methods.len());
                        for (name, desc, outs) in methods.iter() {
                            let outs = PyTuple::new(py, outs.iter().map(|o| py_str(py, o)).collect::<PyResult<Vec<_>>>()?)?;
                            items.push((py_str(py, name)?, py_str(py, desc)?, outs).into_pyobject(py)?.into_any());
                        }
                        let t = PyTuple::new(py, items)?;
                        built.insert(key, t.clone());
                        t
                    }
                };
                parts.push(t);
            }
            // One chunk (every regular class) is passed on as built, shared.
            let t = if parts.len() == 1 {
                parts.pop().unwrap()
            } else {
                PyTuple::new(py, parts.iter().flat_map(|p| p.iter()).collect::<Vec<_>>())?
            };
            out.append((py_str(py, cls)?, t))?;
        }
        Ok(out)
    }

    /// Test hook: disassemble raw `code` bytes against DEX number `dex_no`'s
    /// tables, exactly as bytecode() does.
    fn _decode_code<'py>(&self, py: Python<'py>, dex_no: usize, code: &[u8]) -> PyResult<Bound<'py, PyList>> {
        let dex = self.idx.dexes.get(dex_no).ok_or_else(|| PyValueError::new_err("no such dex"))?;
        decode_to_py(py, dex, code)
    }

    /// Signatures of methods with a const-string containing `needle` (any
    /// definition of a signature counts for it): `needle in s.get_value()`
    /// over `dx.get_strings()`' xrefs, on the text
    /// androguard has for each string (lone surrogates included).
    fn methods_using_string<'py>(&self, py: Python<'py>, needle: &Bound<'py, PyString>) -> PyResult<Bound<'py, PyList>> {
        let needle = needle.call_method1("encode", ("utf-8", "surrogatepass"))?;
        let needle: Vec<u8> = needle.cast::<PyBytes>()?.as_bytes().to_vec();
        let (_, nodes) = py.detach(|| self.idx.methods_using_string(&needle));
        let out = PyList::empty(py);
        let mut seen = std::collections::HashSet::new();
        for g in nodes {
            let s = self.idx.sig(g);
            if seen.insert(s.clone()) {
                out.append(py_str(py, &s)?)?;
            }
        }
        Ok(out)
    }

    /// A class defined in the APK, by descriptor ("Lcom/foo/Bar;"), as
    /// androguard presents it: access_flags, superclass, interfaces,
    /// methods [(name, descriptor, flags)], fields [(flags, name, type,
    /// repr(init) or "<no encoded init value>")]. None if not defined here.
    fn class_info<'py>(&self, py: Python<'py>, name: &str) -> PyResult<Option<Bound<'py, PyDict>>> {
        let Some((dex, i)) = self.idx.class_def_of(name) else {
            return Ok(None);
        };
        let c = class_info(dex, i).map_err(err)?;
        let d = PyDict::new(py);
        d.set_item("name", py_str(py, &c.name)?)?;
        d.set_item("access_flags", &c.access_flags)?;
        d.set_item("superclass", py_str(py, &c.superclass)?)?;
        let ifaces = PyList::empty(py);
        for i in &c.interfaces {
            ifaces.append(py_str(py, i)?)?;
        }
        d.set_item("interfaces", ifaces)?;
        let methods = PyList::empty(py);
        for (n, desc, flags) in c.methods.iter() {
            methods.append((py_str(py, n)?, py_str(py, desc)?, flags))?;
        }
        d.set_item("methods", methods)?;
        let fields = PyList::empty(py);
        for (flags, n, ty, init) in c.field_rows() {
            fields.append((flags, py_str(py, n)?, py_str(py, ty)?, py_str(py, &init)?))?;
        }
        d.set_item("fields", fields)?;
        Ok(Some(d))
    }

    /// dx.get_class_analysis(name).get_fields(), as [(class_name,
    /// access_flags, name, descriptor, init)]: the class's own fields
    /// (static, then instance), then the fields of other classes its code
    /// reads or writes, as androguard's create_xref() adds them (see
    /// Model::class_fields). `init` is None for a field without an initial
    /// value, else (repr(value), value) with `value` typed as androguard's
    /// EncodedValue.value: int, str, bool, None, nested lists for field
    /// and method references, or an EncodedObject for an array or
    /// annotation. [] for an external class, None if androguard has no
    /// class by that name.
    fn class_fields<'py>(&self, py: Python<'py>, name: &str) -> PyResult<Option<Bound<'py, PyList>>> {
        let Some(fields) = py.detach(|| self.model().class_fields(&self.idx, name)).map_err(err)? else {
            return Ok(None);
        };
        let out = PyList::empty(py);
        for f in &fields {
            let init = match &f.init {
                Some(v) => (py_str(py, &v.repr())?, value_to_py(py, v)?).into_pyobject(py)?.into_any(),
                None => py.None().into_bound(py),
            };
            out.append((py_str(py, &f.class_name)?, &f.access_flags, py_str(py, &f.name)?, py_str(py, &f.ty)?, init))?;
        }
        Ok(Some(out))
    }
}

/// A static value androguard keeps as an object (EncodedArray or
/// EncodedAnnotation); only its `repr()` is reproduced.
#[pyclass(frozen, module = "androguard_rs")]
struct EncodedObject {
    #[pyo3(get)]
    kind: &'static str,
    text: &'static str,
}

#[pymethods]
impl EncodedObject {
    fn __repr__(&self) -> &'static str {
        self.text
    }
}

fn value_to_py<'py>(py: Python<'py>, v: &Value) -> PyResult<Bound<'py, PyAny>> {
    Ok(match v {
        Value::Int(i) => i.into_pyobject(py)?.into_any(),
        Value::Str(s) => py_str(py, s)?,
        Value::List(items) => PyList::new(py, items.iter().map(|i| value_to_py(py, i)).collect::<PyResult<Vec<_>>>()?)?.into_any(),
        Value::Bool(b) => b.into_pyobject(py)?.to_owned().into_any(),
        Value::Null => py.None().into_bound(py),
        Value::Opaque(text) => {
            let kind = if *text == androguard_core::classes::ENCODED_ARRAY_REPR { "EncodedArray" } else { "EncodedAnnotation" };
            Bound::new(py, EncodedObject { kind, text })?.into_any()
        }
    })
}

/// A method key as Python sees it: None (the signature names it), (e,) (an
/// irregular class's own method, by its EncodedMethod; the class listing
/// it completes it) or an int (an irregular MethodAnalysis).
fn key_to_py<'py>(py: Python<'py>, k: HitKey) -> PyResult<Bound<'py, PyAny>> {
    Ok(match k {
        HitKey::Sig => py.None().into_bound(py),
        HitKey::Pos(e) => (e,).into_pyobject(py)?.into_any(),
        HitKey::Full(k) => k.into_pyobject(py)?.into_any(),
    })
}

fn method_row<'py>(py: Python<'py>, m: &MethodEntry) -> PyResult<Bound<'py, PyAny>> {
    let (sig, name, desc) = (py_str(py, &m.sig)?, py_str(py, &m.name)?, py_str(py, &m.descriptor)?);
    Ok(match m.key {
        HitKey::Sig => (sig, name, desc, &m.access_flags, m.external).into_pyobject(py)?.into_any(),
        k => {
            let mc = py_str(py, m.method_class.as_deref().unwrap_or_default())?;
            (sig, name, desc, &m.access_flags, m.external, key_to_py(py, k)?, mc).into_pyobject(py)?.into_any()
        }
    })
}

fn method_rows<'py>(py: Python<'py>, ms: &[MethodEntry]) -> PyResult<Bound<'py, PyTuple>> {
    PyTuple::new(py, ms.iter().map(|m| method_row(py, m)).collect::<PyResult<Vec<_>>>()?)
}

fn decode_to_py<'py>(py: Python<'py>, dex: &androguard_core::dex::Dex, code: &[u8]) -> PyResult<Bound<'py, PyList>> {
    let resolver = AgResolver { dex };
    let ins = dex_bytecode::decode_all_with_resolver(code, 0, &resolver).map_err(|e| invalid_instruction(py, &e))?;
    let out = PyList::empty(py);
    for i in ins {
        let output = if i.output_is_none { py.None().into_bound(py) } else { py_str(py, &i.operands)? };
        out.append((i.offset, i.mnemonic, output))?;
    }
    Ok(out)
}

fn invalid_instruction(py: Python<'_>, e: &dex_bytecode::DexError) -> PyErr {
    let inner = InvalidInstruction::new_err(e.message().to_owned()).into_value(py);
    InvalidInstruction::new_err((INVALID_INSTRUCTION_TEMPLATE, e.offset.unwrap_or(0), inner))
}

fn rows_to_py<'py>(py: Python<'py>, dex: &androguard_core::dex::Dex, code: &[u8]) -> PyResult<Bound<'py, PyTuple>> {
    let rows = androguard_core::insn_rows::insn_rows(dex, code).map_err(|e| invalid_instruction(py, &e))?;
    let none = py.None().into_bound(py);
    let out = PyList::empty(py);
    let offs = PyList::empty(py);
    for r in rows {
        offs.append(r.off)?;
        let output = match &r.output {
            Some(s) => py_str(py, s)?,
            None => none.clone(),
        };
        let kind = match &r.kind {
            Some(s) => py_str(py, s)?,
            None => none.clone(),
        };
        let row = (r.off, r.op_value, r.len, r.raw_len, output, kind).into_pyobject(py)?;
        untrack(&row);
        out.append(row)?;
    }
    PyTuple::new(py, [PyBytes::new(py, code).into_any(), out.into_any(), offs.into_any()])
}

/// `object.__new__(cls)` for a class whose instances have only slots
/// (no `__init__`, no `__new__` of its own): the type's tp_alloc, which is
/// all object.__new__ does for one.
fn alloc<'py>(cls: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    let py = cls.py();
    let ty = cls.cast::<pyo3::types::PyType>()?;
    // SAFETY: `ty` is a live type object; PyType_GetSlot(Py_tp_alloc) gives
    // its allocator (every type has one), called with the type and 0 items
    // as object.__new__ calls it; it returns a new reference or NULL with
    // an exception set.
    unsafe {
        let f = pyo3::ffi::PyType_GetSlot(ty.as_type_ptr(), pyo3::ffi::Py_tp_alloc);
        if f.is_null() {
            return Err(PyValueError::new_err("type without tp_alloc"));
        }
        let f: pyo3::ffi::allocfunc = std::mem::transmute(f);
        let o = f(ty.as_type_ptr(), 0);
        Bound::from_owned_ptr_or_err(py, o)
    }
}

/// Byte offsets of the slots `names` in instances of `cls`, found once per
/// class: an instance gets a marker object in each through setattr(), the
/// words of its fixed part (`__basicsize__`) are searched for them, and the
/// offsets are only used if each marker is found exactly once and an
/// instance written through them reads back the same objects through
/// getattr(). None (setattr() is used) otherwise.
fn slot_offsets(cls: &Bound<'_, PyAny>, names: &[&str]) -> PyResult<Option<Vec<usize>>> {
    // By (class, slot names); the classes are kept alive by the cache.
    type Cache = Option<HashMap<(usize, Vec<String>), (Py<PyAny>, Option<Vec<usize>>)>>;
    static CACHE: Mutex<Cache> = Mutex::new(None);
    let py = cls.py();
    let key = (cls.as_ptr() as usize, names.iter().map(|n| n.to_string()).collect::<Vec<_>>());
    if let Some((_, o)) = CACHE.lock().unwrap().as_ref().and_then(|m| m.get(&key)) {
        return Ok(o.clone());
    }
    let found = (|| -> PyResult<Option<Vec<usize>>> {
        let size: usize = cls.getattr("__basicsize__")?.extract()?;
        let word = std::mem::size_of::<*mut pyo3::ffi::PyObject>();
        let o = alloc(cls)?;
        let markers: Vec<Bound<'_, PyList>> = names.iter().map(|_| PyList::empty(py)).collect();
        for (n, m) in names.iter().zip(&markers) {
            if o.setattr(*n, m).is_err() {
                return Ok(None);
            }
        }
        let base = o.as_ptr().cast::<u8>();
        let mut offs = Vec::new();
        for m in &markers {
            let hits: Vec<usize> = (std::mem::size_of::<pyo3::ffi::PyObject>()..size)
                .step_by(word)
                // SAFETY: `o` is a live instance of `cls`, whose fixed part
                // is `size` bytes; every offset read is word-aligned and in
                // it.
                .filter(|&at| unsafe { base.add(at).cast::<*mut pyo3::ffi::PyObject>().read() } == m.as_ptr())
                .collect();
            if hits.len() != 1 {
                return Ok(None);
            }
            offs.push(hits[0]);
        }
        // Check: write through the offsets, read back through getattr().
        let t = alloc(cls)?;
        let check: Vec<Bound<'_, PyList>> = names.iter().map(|_| PyList::empty(py)).collect();
        for (off, v) in offs.iter().zip(&check) {
            // SAFETY: a fresh instance (slots NULL); offsets of its slots.
            unsafe { put_slot(&t, *off, v.clone().into_any()) };
        }
        for (n, v) in names.iter().zip(&check) {
            if !t.getattr(*n)?.is(v) {
                return Ok(None);
            }
        }
        Ok(Some(offs))
    })()?;
    CACHE.lock().unwrap().get_or_insert_with(HashMap::new).insert(key, (cls.clone().unbind(), found.clone()));
    Ok(found)
}

/// Store `v` (its reference moves in) in the object slot at byte `off` of
/// `o`.
///
/// # Safety
/// `off` must be the offset of an object slot of `o`'s type (see
/// slot_offsets()) that is still empty (NULL, as tp_alloc leaves it).
unsafe fn put_slot(o: &Bound<'_, PyAny>, off: usize, v: Bound<'_, PyAny>) {
    unsafe { o.as_ptr().cast::<u8>().add(off).cast::<*mut pyo3::ffi::PyObject>().write(v.into_ptr()) }
}

/// Instruction handles for one code_item: `object.__new__(classes[op])`
/// with `_code` a `holder` (one per call, slots `_rs`, `_d`, `_co` naming
/// the code, `_plen` `{offset: len(get_raw())}` of its payloads if it has
/// any, `_raw` and `_fd` None) and `_row` the byte offset (and an
/// instruction's `_name` and `_op`); all of them, or (`only`) the one at
/// that position, as a tuple.
#[allow(clippy::too_many_arguments)]
fn insn_objects<'py>(
    slf: &Bound<'py, Apk>,
    d: usize,
    code_off: u32,
    code: &[u8],
    spans: &handles::Spans,
    only: Option<usize>,
    holder: &Bound<'py, PyAny>,
    classes: &Bound<'py, PyDict>,
) -> PyResult<Bound<'py, PyTuple>> {
    let py = slf.py();
    // The holder: slots _rs, _d, _co, _raw (None), _plen (set below), _fd
    // (None); it refers only to the Apk, ints and dicts of atoms, so it is
    // no part of a cycle and is kept out of the cycle collector, as the
    // instructions are.
    let none = py.None().into_bound(py);
    let hslots = slot_offsets(holder, HOLDER_SLOTS)?;
    let raw = alloc(holder)?;
    let hv = [slf.clone().into_any(), d.into_pyobject(py)?.into_any(), code_off.into_pyobject(py)?.into_any(), none.clone(), none.clone(), none.clone()];
    match &hslots {
        // SAFETY: offsets slot_offsets() found and checked for this class;
        // `raw` is fresh from tp_alloc (slots NULL).
        Some(at) => unsafe {
            for (off, v) in at.iter().zip(hv) {
                put_slot(&raw, *off, v);
            }
        },
        None => {
            for (n, v) in HOLDER_SLOTS.iter().zip(hv) {
                raw.setattr(*n, v)?;
            }
        }
    }
    untrack(&raw);
    let k_code = pyo3::intern!(py, "_code");
    let k_row = pyo3::intern!(py, "_row");
    let mut plen: Option<Bound<'py, PyDict>> = None;
    // one class lookup per opcode value
    let table = insn_classes(classes)?;
    let ints = offset_ints(py, code.len())?;
    let range = match only {
        Some(i) => i..i + 1,
        None => 0..spans.len(),
    };
    // SAFETY: a new tuple of range.len() NULL items, each set exactly once
    // below (PyTuple_SetItem steals the reference) before it is used; on an
    // error the partly filled tuple is dropped (NULL items are allowed).
    let out = unsafe { Bound::from_owned_ptr_or_err(py, pyo3::ffi::PyTuple_New(range.len() as pyo3::ffi::Py_ssize_t))? };
    for (k, i) in range.enumerate() {
        let (op, at) = (spans.ops[i], spans.offs[i]);
        let Some((cls, name, slots)) = table.get(op as usize).and_then(|e| e.as_ref()) else {
            return Err(PyValueError::new_err(format!("no instruction class for {op:#x}")));
        };
        let cls = cls.bind(py);
        let o = alloc(cls)?;
        let off = offset_int(py, &ints, at)?;
        if op >= 0x100 {
            plen.get_or_insert_with(|| PyDict::new(py)).set_item(&off, spans.raw_len(code, i))?;
        }
        match slots {
            // SAFETY: offsets slot_offsets() found and checked for this
            // class (four for an instruction with a name, two for a
            // payload); `o` is fresh from tp_alloc (slots NULL).
            Some(sl) => unsafe {
                put_slot(&o, sl[0], raw.clone());
                put_slot(&o, sl[1], off);
                if let Some(n) = name {
                    put_slot(&o, sl[2], n.bind(py).clone());
                    put_slot(&o, sl[3], offset_int(py, &ints, op as u32)?);
                }
            },
            None => {
                o.setattr(k_code, &raw)?;
                o.setattr(k_row, &off)?;
                if let Some(n) = name {
                    o.setattr(pyo3::intern!(py, "_name"), n.bind(py))?;
                    o.setattr(pyo3::intern!(py, "_op"), offset_int(py, &ints, op as u32)?)?;
                }
            }
        }
        if op < 0x100 {
            untrack(&o);
        }
        // SAFETY: `out` is a tuple of this length; k < len; steals `o`.
        unsafe { pyo3::ffi::PyTuple_SetItem(out.as_ptr(), k as pyo3::ffi::Py_ssize_t, o.into_ptr()) };
    }
    if let Some(p) = plen {
        raw.setattr(pyo3::intern!(py, "_plen"), p)?;
    }
    let out = out.cast_into::<PyTuple>()?;
    // Only instructions (untracked) and payloads (whose notes list is the
    // only thing they can refer to besides atoms) are in it.
    untrack(out.as_any());
    Ok(out)
}


/// One instruction's (get_output(), resolved reference), decoded.
fn insn_text<'py>(py: Python<'py>, dex: &androguard_core::dex::Dex, code_off: u32, off: usize) -> PyResult<Bound<'py, PyTuple>> {
    let code = dex.code(code_off).map_err(err)?;
    let r = androguard_core::insn_rows::insn_row_at(dex, code, off).map_err(|e| invalid_instruction(py, &e))?;
    let output = match &r.output {
        Some(s) => py_str(py, s)?,
        None => py.None().into_bound(py),
    };
    let kind = match &r.kind {
        Some(s) => py_str(py, s)?,
        None => py.None().into_bound(py),
    };
    PyTuple::new(py, [output, kind])
}

const CDI_SLOTS: &[&str] = &["_core", "_rs", "_d", "_ci"];
const HOLDER_SLOTS: &[&str] = &["_rs", "_d", "_co", "_raw", "_plen", "_fd"];
const EM_SLOTS: &[&str] = &["_core", "_rs", "_d", "_off", "_pos", "_idx", "_flags", "_code_off"];
const EF_SLOTS: &[&str] = &["_core", "_rs", "_d", "_ci", "_off", "_pos", "_idx", "_flags"];

/// A handle: `object.__new__(cls)` with the slots `names` set to `values`
/// (through `slots`, their offsets, when known), untracked by the cycle
/// collector (a handle refers to its DEX's _Core, the Apk and ints, none of
/// which refers back to it).
fn new_handle<'py, const N: usize>(
    cls: &Bound<'py, PyAny>,
    slots: &Option<Vec<usize>>,
    names: &[&str],
    values: [Bound<'py, PyAny>; N],
) -> PyResult<Bound<'py, PyAny>> {
    let o = alloc(cls)?;
    match slots {
        // SAFETY: offsets slot_offsets() found and checked for this class;
        // `o` is fresh from tp_alloc (slots NULL).
        Some(at) => unsafe {
            for (off, v) in at.iter().zip(values) {
                put_slot(&o, *off, v);
            }
        },
        None => {
            for (n, v) in names.iter().zip(values) {
                o.setattr(*n, v)?;
            }
        }
    }
    untrack(&o);
    Ok(o)
}

/// Every class's get_methods() entry names (see
/// `Apk._classes_with_method_prefix`).
struct MethodNames {
    /// Distinct names, sorted (by code point, as Python compares str).
    names: Vec<Box<str>>,
    /// (index in `names`, class position), sorted.
    entries: Vec<(u32, u32)>,
}

impl MethodNames {
    fn build(idx: &Index, model: &Model) -> MethodNames {
        let mut pairs: Vec<(String, u32)> = Vec::new();
        for i in 0..model.class_count(idx) {
            let Some((name, _)) = model.class_at(idx, i) else { continue };
            let Some(cm) = model.class_methods(idx, &name) else { continue };
            for m in cm.own.iter().chain(cm.tail_entries()) {
                pairs.push((m.name.clone(), i as u32));
            }
        }
        // Rust's str order is byte order, which for UTF-8 is code point
        // order (as Python's); core's private-use stand-ins for lone
        // surrogates sort after them, but only prefix ranges are used and
        // a prefix's range is the same either way.
        pairs.sort_unstable();
        let mut names: Vec<Box<str>> = Vec::new();
        let mut entries = Vec::with_capacity(pairs.len());
        for (n, pos) in pairs {
            if names.last().map(|l| **l != *n).unwrap_or(true) {
                names.push(n.into_boxed_str());
            }
            entries.push(((names.len() - 1) as u32, pos));
        }
        MethodNames { names, entries }
    }

    fn classes_with_prefix(&self, prefix: &str) -> Vec<u32> {
        let lo = self.names.partition_point(|n| **n < *prefix);
        let mut hi = lo;
        while hi < self.names.len() && self.names[hi].starts_with(prefix) {
            hi += 1;
        }
        let (a, b) = (
            self.entries.partition_point(|&(n, _)| (n as usize) < lo),
            self.entries.partition_point(|&(n, _)| (n as usize) < hi),
        );
        let mut out: Vec<u32> = self.entries[a..b].iter().map(|&(_, p)| p).collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// An opcode's instruction class, its name (a payload has none) and the
/// offsets of its `_code`, `_row` (and `_name`, `_op`) slots.
type InsnClass = (Py<PyAny>, Option<Py<PyAny>>, Option<Vec<usize>>);

/// The instruction class and name of each opcode value (payloads are
/// 0x100..=0x300) in `classes` ({op: (class, name or None)}), with its
/// slot offsets: worked out once per `classes` dict.
fn insn_classes(classes: &Bound<'_, PyDict>) -> PyResult<std::sync::Arc<Vec<Option<InsnClass>>>> {
    static TABLE: Mutex<Option<(Py<PyDict>, std::sync::Arc<Vec<Option<InsnClass>>>)>> = Mutex::new(None);
    if let Some((d, t)) = TABLE.lock().unwrap().as_ref() {
        if d.is(classes) {
            return Ok(t.clone());
        }
    }
    let mut t: Vec<Option<InsnClass>> = (0..=0x300).map(|_| None).collect();
    for (k, v) in classes.iter() {
        let op: usize = k.extract()?;
        let (cls, name): (Bound<'_, PyAny>, Bound<'_, PyAny>) = v.extract()?;
        if op < t.len() {
            let (name, slots) = if name.is_none() {
                (None, slot_offsets(&cls, &["_code", "_row"])?)
            } else {
                (Some(name.unbind()), slot_offsets(&cls, &["_code", "_row", "_name", "_op"])?)
            };
            t[op] = Some((cls.unbind(), name, slots));
        }
    }
    let t = std::sync::Arc::new(t);
    *TABLE.lock().unwrap() = Some((classes.clone().unbind(), t.clone()));
    Ok(t)
}

/// Ints for instruction offsets: one shared object per value below 2**17
/// (instruction lists kept for an APK's lifetime would otherwise hold one
/// int per instruction), a new one above.
static OFFSET_INTS: Mutex<Vec<Py<PyAny>>> = Mutex::new(Vec::new());
const SHARED_INTS: usize = 1 << 17;

/// The shared ints, covering `0..=max` (or all of them).
fn offset_ints(py: Python<'_>, max: usize) -> PyResult<std::sync::MutexGuard<'static, Vec<Py<PyAny>>>> {
    let mut ints = OFFSET_INTS.lock().unwrap();
    let want = (max + 1).min(SHARED_INTS);
    while ints.len() < want {
        let n = ints.len() as u32;
        ints.push(n.into_pyobject(py)?.into_any().unbind());
    }
    Ok(ints)
}

fn offset_int<'py>(py: Python<'py>, ints: &[Py<PyAny>], off: u32) -> PyResult<Bound<'py, PyAny>> {
    match ints.get(off as usize) {
        Some(i) => Ok(i.bind(py).clone()),
        None => Ok(off.into_pyobject(py)?.into_any()),
    }
}

/// Append a row tuple of atoms (and, for a field's init value, its typed
/// value) to `list`, untracked by the cycle collector: rows are kept for an
/// APK's lifetime and refer to nothing that refers back.
fn append_untracked<'py, T: IntoPyObject<'py, Target = PyTuple, Output = Bound<'py, PyTuple>>>(
    list: &Bound<'py, PyList>,
    row: T,
) -> PyResult<()> {
    let row = row.into_pyobject(list.py()).map_err(Into::into)?.into_any();
    untrack(&row);
    list.append(row)
}

/// Stop the cycle collector tracking `obj`: for objects that only refer to
/// atomic values (ints, strings, bytes, None, tuples of those), which can't
/// be part of a reference cycle. Instruction rows and objects are made by
/// the million and dropped soon after; untracked, the collections their
/// allocations trigger have nothing of theirs to traverse.
fn untrack(obj: &Bound<'_, PyAny>) {
    // SAFETY: `obj` is a live object (we hold a reference); the call is a
    // no-op for an object that isn't tracked, and the object's own
    // deallocator untracks only if it is still tracked.
    unsafe { pyo3::ffi::PyObject_GC_UnTrack(obj.as_ptr().cast()) }
}

fn header_mode(tolerant: bool, header_errors: bool) -> HeaderMode {
    if header_errors {
        HeaderMode::Record
    } else if tolerant {
        HeaderMode::Tolerant
    } else {
        HeaderMode::Strict
    }
}

impl Apk {
    /// dex_class_members() rows (untracked tuples; strings shared through
    /// `strs`).
    fn member_rows<'py>(&self, py: Python<'py>, c: &dexview::Members) -> PyResult<(Bound<'py, PyList>, Bound<'py, PyList>)> {
        let mut strs = self.strs.lock().unwrap();
        let mut s = |x: &str| -> PyResult<Bound<'py, PyAny>> {
            if let Some(v) = strs.get(x) {
                return Ok(v.bind(py).clone().into_any());
            }
            let v = py_str(py, x)?;
            if let Ok(ps) = v.cast::<PyString>() {
                strs.insert(x.to_owned(), ps.clone().unbind());
            }
            Ok(v)
        };
        let methods = PyList::empty(py);
        for m in &c.methods {
            append_untracked(&methods, (
                s(&m.class_name)?,
                s(&m.name)?,
                s(&m.descriptor)?,
                m.access_flags,
                s(&m.flags_string)?,
                m.code_off,
                m.has_code,
                m.registers,
                m.method_idx,
            ))?;
        }
        let fields = PyList::empty(py);
        for f in &c.fields {
            let init = match &f.init {
                Some(v) => (py_str(py, &v.repr())?, value_to_py(py, v)?).into_pyobject(py)?.into_any(),
                None => py.None().into_bound(py),
            };
            append_untracked(&fields, (
                s(&f.class_name)?,
                s(&f.name)?,
                s(&f.ty)?,
                f.access_flags,
                s(&f.flags_string)?,
                init,
                f.field_idx,
            ))?;
        }
        Ok((methods, fields))
    }

    /// DEX `d`'s string `idx` as androguard decodes it, kept as an atom.
    fn str_atom<'py>(&self, py: Python<'py>, d: usize, dex: &androguard_core::dex::Dex, idx: u32) -> PyResult<Bound<'py, PyAny>> {
        self.hs.atom(py, (d as u32, handles::A_STR, idx as u64), || py_str(py, &AgResolver { dex }.string(idx)))
    }

    /// DEX `d`'s type name `idx`, kept as an atom.
    fn type_atom<'py>(&self, py: Python<'py>, d: usize, dex: &androguard_core::dex::Dex, idx: u32) -> PyResult<Bound<'py, PyAny>> {
        self.hs.atom(py, (d as u32, handles::A_TYPE, idx as u64), || py_str(py, &AgResolver { dex }.type_name(idx)))
    }

    /// DEX `d`'s proto `idx` as a descriptor "(P1 P2)R", kept as an atom.
    fn desc_atom<'py>(&self, py: Python<'py>, d: usize, dex: &androguard_core::dex::Dex, idx: u32) -> PyResult<Bound<'py, PyAny>> {
        self.hs.atom(py, (d as u32, handles::A_DESC, idx as u64), || py_str(py, &AgResolver { dex }.descriptor(idx)))
    }

    fn classes_at<'py>(&self, py: Python<'py>, positions: &[u32]) -> PyResult<Bound<'py, PyList>> {
        let model = self.model();
        let out = PyList::empty(py);
        for &i in positions {
            if let Some((n, ext)) = model.class_at(&self.idx, i as usize) {
                out.append((i, py_str(py, &n)?, ext))?;
            }
        }
        Ok(out)
    }

    fn dex_at(&self, d: usize) -> PyResult<&androguard_core::dex::Dex> {
        self.idx.dexes.get(d).ok_or_else(|| PyValueError::new_err("no such dex"))
    }

    fn with(idx: Index, l: Loaded) -> Apk {
        Apk {
            model: OnceLock::new(),
            shared_rows: Mutex::default(),
            run_rows: Mutex::default(),
            strs: Mutex::default(),
            method_names: OnceLock::new(),
            kinds: Mutex::default(),
            skipped: l.skipped,
            names: l.names,
            positions: l.positions,
            load_error: l.load_error,
            hs: handles::State::new(idx.dexes.len()),
            class_sorted: OnceLock::new(),
            idx,
        }
    }

    fn position(&self, py: Python<'_>, name: &Bound<'_, PyString>) -> PyResult<Option<usize>> {
        let raw = name.call_method1("encode", ("utf-8", "surrogatepass"))?;
        let raw = raw.cast::<PyBytes>()?.as_bytes().to_vec();
        Ok(py.detach(|| self.model().class_position(&self.idx, &raw)))
    }

    /// Built once; waited for with the GIL released, so a second thread
    /// asking meanwhile can't deadlock against the builder.
    fn model(&self) -> &Model {
        self.model.get_or_init(|| Model::build(&self.idx))
    }

    /// What a method key names (see `key_to_py`): a signature resolves as a
    /// call to it does (for an irregular class, through androguard's
    /// (class, name, descriptor) table); an int is an irregular
    /// MethodAnalysis; (class name, e) the one that class holds as its own.
    fn target(&self, key: &Bound<'_, PyAny>) -> PyResult<Option<Resolved>> {
        if let Ok(sig) = key.cast::<PyString>() {
            return Ok(self.idx.resolve_sig(&sig.to_cow()?));
        }
        if let Ok(t) = key.cast::<PyTuple>() {
            let (cls, e): (Bound<'_, PyString>, u32) = t.extract()?;
            let raw = cls.call_method1("encode", ("utf-8", "surrogatepass"))?;
            let irr = &self.idx.irr;
            let Some(n) = irr.name_of_hash(sig_hash(raw.cast::<PyBytes>()?.as_bytes())) else { return Ok(None) };
            let w = irr.names[n as usize].winner;
            let b = irr.defs[w as usize].block;
            return Ok((b != irregular::NONE && irr.em_range(b).contains(&e)).then(|| Resolved::Key(irregular::key(w, e))));
        }
        let k: u64 = key.extract()?;
        let (j, e) = irregular::unkey(k);
        let irr = &self.idx.irr;
        let ok = irr.defs.get(j as usize).zip(irr.ems.get(e as usize)).is_some_and(|(d, m)| d.block == m.block);
        Ok(ok.then_some(Resolved::Key(k)))
    }

    fn code(&self, key: &Bound<'_, PyAny>) -> PyResult<Option<(&androguard_core::dex::Dex, u32, u32)>> {
        Ok(match self.target(key)? {
            Some(Resolved::Node(g)) => self.idx.code_of(g),
            Some(Resolved::Key(k)) => self.idx.em_code(irregular::unkey(k).1),
            None => None,
        })
    }

    fn xref_entries<'py>(&self, py: Python<'py>, key: &Bound<'py, PyAny>, callers: bool) -> PyResult<Bound<'py, PyList>> {
        let out = PyList::empty(py);
        let entries = match self.target(key)? {
            Some(Resolved::Node(g)) => model::xrefs(&self.idx, g, callers),
            Some(Resolved::Key(k)) => py.detach(|| self.model().r_xrefs(&self.idx, k, callers)),
            None => return Ok(out),
        };
        for e in entries {
            let (sig, cls, name, desc) = (py_str(py, &e.sig)?, py_str(py, &e.class_name)?, py_str(py, &e.name)?, py_str(py, &e.descriptor)?);
            match e.key {
                HitKey::Sig => out.append((sig, cls, name, desc, e.offset))?,
                k => {
                    let mc = py_str(py, e.method_class.as_deref().unwrap_or_default())?;
                    out.append((sig, cls, name, desc, e.offset, key_to_py(py, k)?, mc))?
                }
            }
        }
        Ok(out)
    }

    /// callers()/callees(): every definition of the signature counts.
    fn neighbours<'py>(&self, py: Python<'py>, sig: &str, callers: bool) -> PyResult<Bound<'py, PyList>> {
        let out = PyList::empty(py);
        if self.idx.irr.active() {
            for e in py.detach(|| self.model().sig_xrefs(&self.idx, sig, callers)) {
                out.append((py_str(py, &e.sig)?, e.offset))?;
            }
            return Ok(out);
        }
        let Some(g) = self.idx.gid_of(sig) else {
            return Ok(out);
        };
        let edges = if callers { self.idx.callers_of(g) } else { self.idx.callees_of(g) };
        for &[other, off] in edges {
            out.append((py_str(py, &self.idx.sig(other))?, off))?;
        }
        Ok(out)
    }
}

/// Test hook: decode raw DEX string bytes the way androguard does
/// (StringDataItem.get()), for differential testing against `mutf8`.
#[pyfunction]
fn _decode_dex_string<'py>(py: Python<'py>, raw: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    match androguard_core::render::mutf8_decode(raw) {
        Some(s) => py_str(py, &s),
        None => Ok(py.None().into_bound(py)),
    }
}

/// Test hook: the lower-casing search_instruction_text uses (Python's
/// str.lower()).
#[pyfunction]
fn _py_lower(s: &str) -> String {
    androguard_core::render::py_lower(s)
}

/// androguard 4.1.3's error for a DEX as a recipe tuple, which
/// `androguard_rs._agerr.make()` turns into the exception.
fn ag_err_py<'py>(py: Python<'py>, e: &androguard_core::agload::AgErr) -> PyResult<Bound<'py, PyTuple>> {
    use androguard_core::agload::AgErr::*;
    let t = |items: Vec<Bound<'py, PyAny>>| PyTuple::new(py, items);
    let s = |v: &str| -> Bound<'py, PyAny> { PyString::new(py, v).into_any() };
    let i = |v: u64| -> Bound<'py, PyAny> { v.into_pyobject(py).unwrap().into_any() };
    match e {
        Header { not_implemented, message } => {
            t(vec![s("Header"), pyo3::types::PyBool::new(py, *not_implemented).to_owned().into_any(), s(message)])
        }
        Struct(n) => t(vec![s("Struct"), i(*n as u64)]),
        KeyMap(ty) => t(vec![s("KeyMap"), i(*ty as u64)]),
        KeyInt(v) => t(vec![s("KeyInt"), i(*v)]),
        Enum { which, value } => t(vec![s("Enum"), s(which), i(*value)]),
        IndexList => t(vec![s("IndexList")]),
        IndexStr => t(vec![s("IndexStr")]),
        Attr { obj, name } => t(vec![s("Attr"), s(obj), s(name)]),
        Recursion => t(vec![s("Recursion")]),
        NoTerminate => t(vec![s("NoTerminate")]),
        Invalid(x) => t(vec![s("Invalid"), invalid_instruction(py, x).into_value(py).into_bound(py).into_any()]),
    }
}

/// What androguard 4.1.3 raises for the DEX `data` in `DEX(data)`, then in
/// `Analysis.add()`, then in `create_xref()`: three recipes or None (only
/// the first that raises is given). `max_depth`: Python frames androguard
/// may go deeper than `DEX.__init__`; `c_budget`: C recursion units left
/// there. Raises ValueError if androguard loads
/// the DEX but the native reader can't.
#[pyfunction]
#[pyo3(signature = (data, max_depth, c_budget = androguard_core::apk::DEFAULT_C_BUDGET))]
fn _dex_check<'py>(py: Python<'py>, data: pyo3::pybacked::PyBackedBytes, max_depth: i64, c_budget: i64) -> PyResult<(Option<Bound<'py, PyTuple>>, Option<Bound<'py, PyTuple>>, Option<Bound<'py, PyTuple>>)> {
    use androguard_core::agload;
    let r = py
        .detach(move || -> anyhow::Result<(Option<agload::AgErr>, Option<agload::AgErr>, Option<agload::AgErr>)> {
            let st = match agload::load(&data, max_depth, c_budget) {
                Ok(st) => st,
                Err(e) => return Ok((Some(e), None, None)),
            };
            if st.no_map {
                return Ok((None, Some(agload::add_error_no_map()), None));
            }
            let dex = androguard_core::dex::Dex::parse(data.to_vec())?;
            if let Some(e) = agload::add_error(&st, &dex) {
                return Ok((None, Some(e), None));
            }
            Ok((None, None, agload::xref_error(&st, &dex)))
        })
        .map_err(err)?;
    Ok((
        r.0.as_ref().map(|e| ag_err_py(py, e)).transpose()?,
        r.1.as_ref().map(|e| ag_err_py(py, e)).transpose()?,
        r.2.as_ref().map(|e| ag_err_py(py, e)).transpose()?,
    ))
}

/// androguard 4.1.3's `DEX()` header checks on `data`: None, or
/// ("ValueError" | "NotImplementedError", message) for the first that fails.
#[pyfunction]
fn _dex_header_error(data: &[u8]) -> Option<(&'static str, String)> {
    androguard_core::apk::androguard_header_check(data, true)
        .map(|e| (if e.not_implemented { "NotImplementedError" } else { "ValueError" }, e.message))
}

/// Parse `data` as a DEX (nothing kept); ValueError if the index can't.
#[pyfunction]
fn _dex_parse_check(py: Python<'_>, data: pyo3::pybacked::PyBackedBytes) -> PyResult<()> {
    py.detach(move || androguard_core::dex::Dex::parse(data.to_vec()).map(|_| ())).map_err(err)
}

/// The InvalidInstruction androguard's `Analysis.add()` raises for the DEX
/// `data` (its first method that can't be disassembled), or None. Nothing
/// is kept.
#[pyfunction]
fn _dex_first_invalid(py: Python<'_>, data: pyo3::pybacked::PyBackedBytes) -> PyResult<Option<Bound<'_, PyAny>>> {
    let found = py
        .detach(move || -> anyhow::Result<_> {
            let dex = androguard_core::dex::Dex::parse(data.to_vec())?;
            Ok(androguard_core::strict::first_invalid(std::slice::from_ref(&dex)).map(|f| f.4))
        })
        .map_err(err)?;
    Ok(found.map(|e| invalid_instruction(py, &e).into_value(py).into_bound(py).into_any()))
}

#[pymodule]
fn androguard_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Apk>()?;
    m.add_class::<EncodedObject>()?;
    m.add("InvalidInstruction", m.py().get_type::<InvalidInstruction>())?;
    m.add_function(wrap_pyfunction!(_decode_dex_string, m)?)?;
    m.add_function(wrap_pyfunction!(_dex_header_error, m)?)?;
    m.add_function(wrap_pyfunction!(_dex_check, m)?)?;
    m.add_function(wrap_pyfunction!(_dex_parse_check, m)?)?;
    m.add_function(wrap_pyfunction!(_dex_first_invalid, m)?)?;
    m.add_function(wrap_pyfunction!(_py_lower, m)?)?;
    m.add_class::<resources::Resources>()?;
    m.add("ResourcesError", m.py().get_type::<resources::ResourcesError>())?;
    m.add_function(wrap_pyfunction!(resources::_decode_pool_string, m)?)?;
    m.add_function(wrap_pyfunction!(resources::_format_value, m)?)?;
    apkinfo::register(m)?;
    Ok(())
}
