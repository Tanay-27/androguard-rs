//! What the per-query handles of `androguard_rs.dex` (ClassDefItem,
//! EncodedMethod, EncodedField, DalvikCode, DCode, Instruction*) are made
//! from and answered with. A handle is a Python object holding the native
//! `Apk` and integer keys only; everything it answers is computed here from
//! the DEX bytes when asked. Nothing per handle is kept.
//!
//! What may be kept natively (see `Cfg`): Python str objects for DEX
//! strings, type names, descriptors and flag words ("atoms", one per
//! distinct value, as androguard's objects share the DEX's string table),
//! the instruction boundaries of the last few methods asked for (so
//! `get_instruction(idx)` stepping through a method doesn't decode it again
//! each time), and, optionally, every method's instruction boundaries
//! and rendered instruction text.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use pyo3::exceptions::PyIndexError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString, PyTuple};
use rustc_hash::FxHashMap;

use androguard_core::dex::Dex;
use androguard_core::insn_rows::{insn_spans, payload_lengths};

/// What is kept natively, from `ANDROGUARD_RS_CACHE` (comma-separated
/// words) when the index is built:
/// - `noatoms`: make a new str for every DEX string, type name, descriptor,
///   flags string and resolved reference asked for, instead of one per
///   distinct value;
/// - `spans`: keep every method's instruction boundaries once decoded
///   (6 bytes per instruction), instead of the last `lru` methods' only;
/// - `text`: keep every instruction's rendered text once asked for;
/// - `lru=N`: how many methods' boundaries the default keeps (32).
#[derive(Clone, Copy, Debug)]
pub struct Cfg {
    pub atoms: bool,
    pub spans: bool,
    pub text: bool,
    pub lru: usize,
}

impl Cfg {
    pub fn from_env() -> Cfg {
        let mut c = Cfg { atoms: true, spans: false, text: false, lru: 32 };
        if let Ok(v) = std::env::var("ANDROGUARD_RS_CACHE") {
            for w in v.split(',').map(str::trim) {
                match w {
                    "noatoms" => c.atoms = false,
                    "atoms" => c.atoms = true,
                    "spans" => c.spans = true,
                    "text" => c.text = true,
                    "none" | "" => {}
                    _ => {
                        if let Some(n) = w.strip_prefix("lru=").and_then(|n| n.parse().ok()) {
                            c.lru = n;
                        }
                    }
                }
            }
        }
        c
    }
}

/// One method's instructions: byte offset and `get_op_value()` of each.
pub struct Spans {
    pub offs: Vec<u32>,
    pub ops: Vec<u16>,
}

impl Spans {
    pub fn of(code: &[u8]) -> Result<Spans, dex_bytecode::DexError> {
        let s = insn_spans(code)?;
        Ok(Spans { offs: s.iter().map(|x| x.off).collect(), ops: s.iter().map(|x| x.op_value).collect() })
    }

    pub fn len(&self) -> usize {
        self.offs.len()
    }

    /// `len(get_raw())` of the instruction at position `i` (payloads only
    /// differ from their format length).
    pub fn raw_len(&self, code: &[u8], i: usize) -> u32 {
        let off = self.offs[i] as usize;
        payload_lengths(self.ops[i], &code[off..]).1 as u32
    }

    pub fn bytes(&self) -> usize {
        self.offs.capacity() * 4 + self.ops.capacity() * 2
    }
}

pub type AtomKey = (u32, u8, u64);
pub const A_STR: u8 = 0;
pub const A_TYPE: u8 = 1;
pub const A_DESC: u8 = 2;
pub const A_MFLAGS: u8 = 3;
pub const A_FFLAGS: u8 = 4;
pub const A_CFLAGS: u8 = 5;
pub const A_INFO: u8 = 6;

/// The native state behind the handles.
pub struct State {
    pub cfg: Cfg,
    pub atoms: Mutex<FxHashMap<AtomKey, Py<PyAny>>>,
    /// get_type() results by text, shared by the get_information() parts.
    pub jtypes: Mutex<FxHashMap<String, Py<PyString>>>,
    /// The last `cfg.lru` methods' instruction boundaries, by (DEX, code_off).
    lru: Mutex<VecDeque<((u32, u32), Arc<Spans>)>>,
    /// Every method's (with `cfg.spans`).
    all_spans: Mutex<FxHashMap<(u32, u32), Arc<Spans>>>,
    /// (get_output(), resolved reference) by (DEX, code_off, offset), with
    /// `cfg.text`.
    pub texts: Mutex<FxHashMap<(u32, u32, u32), Py<PyTuple>>>,
    /// Static values of the last few classes asked for, by (DEX, class_def).
    inits: Mutex<VecDeque<((u32, u32), Arc<Vec<androguard_core::classes::Value>>)>>,
    /// Per DEX: the first class_def of each name (hash of its UTF-8/WTF-8
    /// bytes -> class_def indices with that hash), built on first use.
    pub first_class: Vec<std::sync::OnceLock<FxHashMap<u64, Vec<u32>>>>,
}

impl State {
    pub fn new(dex_count: usize) -> State {
        State {
            cfg: Cfg::from_env(),
            atoms: Mutex::default(),
            jtypes: Mutex::default(),
            lru: Mutex::default(),
            all_spans: Mutex::default(),
            texts: Mutex::default(),
            inits: Mutex::default(),
            first_class: (0..dex_count).map(|_| std::sync::OnceLock::new()).collect(),
        }
    }

    /// A kept str (or other atom) for `key`, made by `make` the first time;
    /// a new one each time without atoms.
    pub fn atom<'py>(
        &self,
        py: Python<'py>,
        key: AtomKey,
        make: impl FnOnce() -> PyResult<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if !self.cfg.atoms {
            return make();
        }
        if let Some(v) = self.atoms.lock().unwrap().get(&key) {
            return Ok(v.bind(py).clone());
        }
        let v = make()?;
        self.atoms.lock().unwrap().entry(key).or_insert_with(|| v.clone().unbind());
        Ok(v)
    }

    /// The instruction boundaries of the code_item at `code_off` (its insns
    /// `code`), decoded or kept.
    pub fn spans(&self, d: u32, code_off: u32, code: &[u8]) -> Result<Arc<Spans>, dex_bytecode::DexError> {
        let key = (d, code_off);
        if self.cfg.spans {
            if let Some(s) = self.all_spans.lock().unwrap().get(&key) {
                return Ok(s.clone());
            }
            let s = Arc::new(Spans::of(code)?);
            self.all_spans.lock().unwrap().insert(key, s.clone());
            return Ok(s);
        }
        if self.cfg.lru > 0 {
            let mut lru = self.lru.lock().unwrap();
            if let Some(i) = lru.iter().position(|(k, _)| *k == key) {
                let e = lru.remove(i).unwrap();
                let s = e.1.clone();
                lru.push_front(e);
                return Ok(s);
            }
        }
        let s = Arc::new(Spans::of(code)?);
        if self.cfg.lru > 0 {
            let mut lru = self.lru.lock().unwrap();
            lru.push_front((key, s.clone()));
            lru.truncate(self.cfg.lru);
        }
        Ok(s)
    }

    /// Static field values of class_def `ci` (androguard's, see
    /// `class_info`), kept for the last few classes.
    pub fn inits(&self, d: u32, ci: u32, dex: &Dex) -> anyhow::Result<Arc<Vec<androguard_core::classes::Value>>> {
        let key = (d, ci);
        {
            let lru = self.inits.lock().unwrap();
            if let Some((_, v)) = lru.iter().find(|(k, _)| *k == key) {
                return Ok(v.clone());
            }
        }
        let v = androguard_core::classes::class_inits(dex, ci as usize)?;
        let mut lru = self.inits.lock().unwrap();
        lru.push_front((key, v.clone()));
        lru.truncate(8);
        Ok(v)
    }

    /// Bytes kept natively for instruction boundaries (for stats()).
    pub fn span_bytes(&self) -> usize {
        self.all_spans.lock().unwrap().values().map(|s| s.bytes() + 48).sum::<usize>()
            + self.lru.lock().unwrap().iter().map(|(_, s)| s.bytes() + 48).sum::<usize>()
    }
}

impl State {
    /// A get_type() result as a str, one per distinct text.
    pub fn jtype<'py>(&self, py: Python<'py>, t: &str) -> PyResult<Bound<'py, PyAny>> {
        if let Some(v) = self.jtypes.lock().unwrap().get(t) {
            return Ok(v.bind(py).clone().into_any());
        }
        let v = s(py, t)?;
        if let Ok(ps) = v.cast::<PyString>() {
            self.jtypes.lock().unwrap().insert(t.to_owned(), ps.clone().unbind());
        }
        Ok(v)
    }
}

/// Python's `str.isspace()` for one code point (what `str.split()` splits
/// on).
pub fn is_py_space(c: char) -> bool {
    matches!(c,
        '\u{9}'..='\u{d}' | '\u{1c}'..='\u{20}' | '\u{85}' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}'
        | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}')
}

/// androguard 4.1.3's `get_type(atype)` (size None); Err(message) for its
/// IndexError on an empty name.
pub fn py_get_type(atype: &str) -> Result<String, &'static str> {
    let mut atype = atype.to_owned();
    let mut suffix = String::new();
    loop {
        if atype.starts_with("java.lang") {
            atype = atype.replace("java.lang.", "");
        }
        let stripped = atype.trim_start_matches(|c| "java.lng".contains(c));
        let base = match stripped {
            "V" => Some("void"),
            "Z" => Some("boolean"),
            "B" => Some("byte"),
            "S" => Some("short"),
            "C" => Some("char"),
            "I" => Some("int"),
            "J" => Some("long"),
            "F" => Some("float"),
            "D" => Some("double"),
            _ => None,
        };
        if let Some(b) = base {
            return Ok(b.to_owned() + &suffix);
        }
        let mut chars = atype.chars();
        match chars.next() {
            None => return Err("string index out of range"),
            Some('L') => {
                let inner: Vec<char> = chars.collect();
                let end = inner.len().saturating_sub(1);
                let s: String = inner[..end].iter().collect();
                return Ok(s.replace('/', ".") + &suffix);
            }
            Some('[') => {
                atype = chars.collect();
                suffix.push_str("[]");
            }
            Some(_) => return Ok(atype + &suffix),
        }
    }
}

/// `get_information()`'s register-independent parts for descriptor
/// `proto`: (return type, parameter types), as androguard 4.1.3 computes
/// them; Err for its IndexError.
pub fn information_types(proto: &str) -> Result<(String, Vec<String>), &'static str> {
    let mut pieces = proto.split(')');
    let first = pieces.next().unwrap_or("");
    let Some(ret) = pieces.next() else { return Err("list index out of range") };
    let mut fc = first.chars();
    fc.next();
    let ret_type = py_get_type(ret)?;
    let params = fc.as_str().split(is_py_space).filter(|p| !p.is_empty()).map(py_get_type).collect::<Result<Vec<_>, _>>()?;
    Ok((ret_type, params))
}

/// A new `get_information()` dict for a method with `nb` registers from
/// its descriptor's kept parts (a tuple (return type, parameter types)).
pub fn information_dict<'py>(py: Python<'py>, parts: &Bound<'py, PyAny>, nb: i64) -> PyResult<Bound<'py, PyDict>> {
    let t = parts.cast::<PyTuple>()?;
    let d = PyDict::new(py);
    d.set_item(pyo3::intern!(py, "return"), t.get_item(0)?)?;
    let ptypes = t.get_item(1)?;
    let ptypes = ptypes.cast::<PyTuple>()?;
    let n = ptypes.len() as i64;
    if n == 0 {
        d.set_item(pyo3::intern!(py, "registers"), (0, nb - 1))?;
        return Ok(d);
    }
    d.set_item(pyo3::intern!(py, "registers"), (0, nb - n - 1))?;
    let params = PyList::empty(py);
    for (j, ty) in ptypes.iter().enumerate() {
        params.append((nb - n + j as i64, ty))?;
    }
    d.set_item(pyo3::intern!(py, "params"), params)?;
    Ok(d)
}

pub fn index_error(msg: &'static str) -> PyErr {
    PyIndexError::new_err(msg)
}

/// A Python str for a Rust one (see `py_str` in lib.rs).
pub fn s<'py>(py: Python<'py>, v: &str) -> PyResult<Bound<'py, PyAny>> {
    crate::py_str(py, v)
}

pub fn pystr_bytes(name: &Bound<'_, PyString>) -> PyResult<Vec<u8>> {
    let raw = name.call_method1("encode", ("utf-8", "surrogatepass"))?;
    Ok(raw.cast::<pyo3::types::PyBytes>()?.as_bytes().to_vec())
}
