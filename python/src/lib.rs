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

use androguard_core::apk::{HeaderMode, Loaded, SkippedDex, load_bytes_mode, load_mode};
use androguard_core::classes::{Value, class_info};
use androguard_core::dexview;
use androguard_core::index::{Hit, HitKey, Index, Resolved, sig_hash};
use androguard_core::irregular;
use androguard_core::model::{self, MethodEntry, Model};
use androguard_core::render::{AgResolver, INVALID_INSTRUCTION_TEMPLATE};

mod apkinfo;
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
    /// DEX files left out under `tolerant=True`.
    skipped: Vec<SkippedDex>,
    /// `get_dex_names()`: the entries read, in load order.
    names: Vec<String>,
    /// Position in `names` of each loaded DEX.
    positions: Vec<usize>,
}

#[pymethods]
impl Apk {
    /// Parse every classesN.dex in the APK and build the cross-reference
    /// index. Releases the GIL while it works.
    ///
    /// With `tolerant=True`, a DEX that androguard's `DEX()` rejects with
    /// "Not a DEX file, Header too small." or "This is not a DEX file! Wrong
    /// endian tag: ..." is left out (see `skipped_dex()`);
    /// otherwise it fails the APK, as `AnalyzeAPK` does.
    ///
    /// With `header_errors=True`, every check androguard's `DEX()` header
    /// makes is made (magic, Adler-32 checksum, header size, id counts too),
    /// and a DEX failing one is left out and listed by `header_errors()`, so
    /// the caller can raise what androguard raises, in its order.
    #[new]
    #[pyo3(signature = (path, tolerant = false, header_errors = false))]
    fn new(py: Python<'_>, path: &str, tolerant: bool, header_errors: bool) -> PyResult<Self> {
        let path = path.to_owned();
        let mode = header_mode(tolerant, header_errors);
        let (idx, l) = py
            .detach(move || -> anyhow::Result<(Index, Loaded)> {
                let mut l = load_mode(&path, mode)?;
                Ok((Index::build(std::mem::take(&mut l.dexes))?, l))
            })
            .map_err(err)?;
        Ok(Apk::with(idx, l))
    }

    /// `Apk(path)` for an APK held in memory (`bytes` or `bytearray`).
    #[staticmethod]
    #[pyo3(signature = (data, tolerant = false, header_errors = false))]
    fn from_bytes(py: Python<'_>, data: pyo3::pybacked::PyBackedBytes, tolerant: bool, header_errors: bool) -> PyResult<Self> {
        let mode = header_mode(tolerant, header_errors);
        let (idx, l) = py
            .detach(move || -> anyhow::Result<(Index, Loaded)> {
                let mut l = load_bytes_mode(&data, mode)?;
                Ok((Index::build(std::mem::take(&mut l.dexes))?, l))
            })
            .map_err(err)?;
        Ok(Apk::with(idx, l))
    }

    /// The index over DEX files given as bytes, in that order (the
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
                Ok((Index::build(parsed)?, Loaded { names, dexes: Vec::new(), skipped: Vec::new(), positions: (0..n).collect() }))
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
        let methods = PyList::empty(py);
        for m in &c.methods {
            methods.append((
                py_str(py, &m.class_name)?,
                py_str(py, &m.name)?,
                py_str(py, &m.descriptor)?,
                m.access_flags,
                py_str(py, &m.flags_string)?,
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
            fields.append((
                py_str(py, &f.class_name)?,
                py_str(py, &f.name)?,
                py_str(py, &f.ty)?,
                f.access_flags,
                py_str(py, &f.flags_string)?,
                init,
                f.field_idx,
            ))?;
        }
        PyTuple::new(py, [methods.into_any(), fields.into_any()])
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

    /// TLS-related method pre-filter (not androguard): (class_def index,
    /// position) of each EncodedMethod of DEX number `d`'s
    /// `get_encoded_methods()` that it selects, in that order (see
    /// `androguard_rs.dex.DEX.get_ssl_candidate_methods`).
    fn ssl_candidates(&self, py: Python<'_>, d: usize) -> PyResult<Vec<(u32, u32)>> {
        let dex = self.dex_at(d)?;
        Ok(py.detach(|| dexview::ssl_candidates(dex)))
    }

    /// androguard's `APK.get_dex_names()`, i.e. the order AnalyzeAPK (and a
    /// manual `DEX()` + `Analysis.add()` load) reads DEX files in: central directory order, names matching
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
    /// `androguard_rs.dex` Instruction objects: `(insns, rows)`, where
    /// `insns` is the method's instruction bytes and each row is
    /// `(offset, get_op_value(), get_length(), len(get_raw()), get_output(),
    /// kind)`: `get_raw()` is `insns[offset:offset + raw_len]`, and `kind` is
    /// the resolved reference (`get_translated_kind()`) or None. None if the
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
    fn class_methods<'py>(&self, py: Python<'py>, name: &str) -> PyResult<Option<Bound<'py, PyList>>> {
        let Some(methods) = py.detach(|| self.model().class_methods(&self.idx, name)) else {
            return Ok(None);
        };
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
    for r in rows {
        let output = match &r.output {
            Some(s) => py_str(py, s)?,
            None => none.clone(),
        };
        let kind = match &r.kind {
            Some(s) => py_str(py, s)?,
            None => none.clone(),
        };
        out.append((r.off, r.op_value, r.len, r.raw_len, output, kind))?;
    }
    PyTuple::new(py, [PyBytes::new(py, code).into_any(), out.into_any()])
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
    fn dex_at(&self, d: usize) -> PyResult<&androguard_core::dex::Dex> {
        self.idx.dexes.get(d).ok_or_else(|| PyValueError::new_err("no such dex"))
    }

    fn with(idx: Index, l: Loaded) -> Apk {
        Apk {
            idx,
            model: OnceLock::new(),
            shared_rows: Mutex::default(),
            run_rows: Mutex::default(),
            skipped: l.skipped,
            names: l.names,
            positions: l.positions,
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
