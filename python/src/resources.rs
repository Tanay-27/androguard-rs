//! `androguard_rs.Resources`: androguard's `ARSCParser` query methods,
//! byte-identical to androguard 4.1.3, on a table parsed once in Rust.

use std::collections::HashMap;
use std::sync::Mutex;

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString, PyTuple};

use androguard_core::arsc::{Arsc, Item, Resolved, Val, format_value, py_decode};

// Raised wherever androguard's ARSCParser raises (ResParserError,
// struct.error, AttributeError, ...).
create_exception!(androguard_rs, ResourcesError, PyException);

fn err(e: anyhow::Error) -> PyErr {
    ResourcesError::new_err(format!("{e:#}"))
}

#[pyclass(frozen, module = "androguard_rs")]
pub struct Resources {
    arsc: Arsc,
    /// androguard's `_analyse()` raises from the first query that runs it;
    /// later queries see what it collected before failing.
    pending: Mutex<Option<String>>,
}

impl Resources {
    fn wrap(arsc: Arsc) -> Self {
        let pending = Mutex::new(arsc.analysis_error().map(str::to_owned));
        Resources { arsc, pending }
    }

    fn analysed(&self) -> PyResult<()> {
        match self.pending.lock().unwrap().take() {
            Some(e) => Err(ResourcesError::new_err(e)),
            None => Ok(()),
        }
    }
}

#[pymethods]
impl Resources {
    /// Parse `resources.arsc` bytes, e.g. `APK.get_file("resources.arsc")`
    /// (what `APK.get_android_resources()` parses). Raises ResourcesError
    /// where `ARSCParser(raw)` raises. Releases the GIL while it works.
    #[new]
    fn new(py: Python<'_>, data: &[u8]) -> PyResult<Self> {
        let data = data.to_vec();
        py.detach(move || Arsc::parse(data)).map(Resources::wrap).map_err(err)
    }

    /// The APK's `resources.arsc`, or None if it has none (as
    /// `get_android_resources()`).
    #[staticmethod]
    fn from_apk(py: Python<'_>, path: &str) -> PyResult<Option<Self>> {
        let path = path.to_owned();
        py.detach(move || Arsc::from_apk(&path)).map(|a| a.map(Resources::wrap)).map_err(err)
    }

    /// `get_packages_names()`.
    fn get_packages_names(&self) -> Vec<String> {
        self.arsc.package_names().into_iter().map(str::to_owned).collect()
    }

    /// `get_public_resources(package_name, locale)`: the XML as bytes.
    #[pyo3(signature = (package_name, locale = "\x00\x00"))]
    fn get_public_resources<'py>(&self, py: Python<'py>, package_name: &str, locale: &str) -> PyResult<Bound<'py, PyBytes>> {
        self.analysed()?;
        let xml = py.detach(|| self.arsc.public_resources(package_name, locale)).map_err(err)?;
        Ok(PyBytes::new(py, &xml))
    }

    /// `get_resolved_strings()`: {package: {locale or "DEFAULT": {rid: str or None}}}.
    fn get_resolved_strings<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        self.analysed()?;
        let r = py.detach(|| self.arsc.resolved_strings()).map_err(err)?;
        let strings: Vec<Bound<'py, PyString>> = r.strings.iter().map(|s| PyString::new(py, s)).collect();
        let out = PyDict::new(py);
        for (pkg, locales) in &r.packages {
            let pd = PyDict::new(py);
            for (locale, items) in locales {
                let ld = PyDict::new(py);
                for &(rid, v) in items {
                    match v {
                        Some(i) => ld.set_item(rid, &strings[i as usize])?,
                        None => ld.set_item(rid, py.None())?,
                    }
                }
                pd.set_item(locale, ld)?;
            }
            out.set_item(pkg, pd)?;
        }
        Ok(out)
    }

    /// `get_resolved_res_configs(rid)`: [(config, value)], value a str, or a
    /// list for a complex entry. The config is `ARSCResTableConfig._get_tuple()`,
    /// or, with `factory`, `factory(start, raw)` for the bytes androguard's
    /// `ARSCResTableConfig(buff)` read at `start` (one call per config
    /// object; the same object is reused).
    #[pyo3(signature = (rid, factory = None))]
    fn get_resolved_res_configs<'py>(&self, py: Python<'py>, rid: i64, factory: Option<Bound<'py, PyAny>>) -> PyResult<Bound<'py, PyList>> {
        self.analysed()?;
        if rid == 0 {
            return Err(PyValueError::new_err("'rid' should be set"));
        }
        if rid < 0 || rid > u32::MAX as i64 {
            return Ok(PyList::empty(py));
        }
        let r = py.detach(|| self.arsc.resolved_res_configs(rid as u32)).map_err(err)?;
        let mut cv = Conv { py, r: &r, strings: vec![None; r.strings.len()], configs: HashMap::new(), factory };
        let out = PyList::empty(py);
        for it in &r.items {
            out.append(cv.item(it)?)?;
        }
        Ok(out)
    }

    /// `get_resource_xml_name(r_id, package)`.
    #[pyo3(signature = (r_id, package = None))]
    fn get_resource_xml_name(&self, r_id: i64, package: Option<&str>) -> PyResult<Option<String>> {
        if package.is_some_and(|p| !p.is_empty()) || !self.arsc.package_names().is_empty() {
            self.analysed()?;
        }
        self.arsc.resource_xml_name(r_id, package).map_err(err)
    }

    /// `get_string(package_name, name, locale)`: `[name, value]` (a list,
    /// as androguard's) of the first string resource with that name, or None.
    #[pyo3(signature = (package_name, name, locale = "\x00\x00"))]
    fn get_string(&self, package_name: &str, name: &str, locale: &str) -> PyResult<Option<Vec<String>>> {
        self.analysed()?;
        Ok(self.arsc.get_string(package_name, name, locale).map_err(err)?.map(|(k, v)| vec![k, v]))
    }

    /// `get_string_resources(package_name, locale)`: the `<string>` XML bytes.
    #[pyo3(signature = (package_name, locale = "\x00\x00"))]
    fn get_string_resources<'py>(&self, py: Python<'py>, package_name: &str, locale: &str) -> PyResult<Bound<'py, PyBytes>> {
        self.analysed()?;
        let b = self.arsc.string_resources(package_name, locale).map_err(err)?;
        Ok(PyBytes::new(py, &b))
    }

    /// Every rid that has an entry (androguard's `resource_values` keys), sorted.
    fn rids(&self) -> Vec<u32> {
        self.arsc.rids()
    }

    /// Bytes held by the parsed table.
    fn heap_bytes(&self) -> usize {
        self.arsc.heap_bytes()
    }
}

/// Builds Python values for a resolved tree, one object per distinct string
/// and config.
struct Conv<'py, 'a> {
    py: Python<'py>,
    r: &'a Resolved<'a>,
    strings: Vec<Option<Bound<'py, PyString>>>,
    configs: HashMap<u32, Bound<'py, PyAny>>,
    /// Builds a config object from (start, bytes); None: `_get_tuple()`s.
    factory: Option<Bound<'py, PyAny>>,
}

impl<'py> Conv<'py, '_> {
    fn string(&mut self, i: u32) -> Bound<'py, PyString> {
        self.strings[i as usize].get_or_insert_with(|| PyString::new(self.py, &self.r.strings[i as usize])).clone()
    }

    fn config(&mut self, c: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(o) = self.configs.get(&c) {
            return Ok(o.clone());
        }
        let o = match &self.factory {
            Some(f) => {
                let (start, raw) = self.r.config_bytes(c);
                f.call1((start, PyBytes::new(self.py, raw)))?
            }
            None => PyTuple::new(self.py, self.r.config_key(c))?.into_any(),
        };
        self.configs.insert(c, o.clone());
        Ok(o)
    }

    fn item(&mut self, it: &Item) -> PyResult<Bound<'py, PyAny>> {
        Ok(match it {
            Item::Str(s) => self.string(*s).into_any(),
            Item::Pair(c, v) => {
                let c = self.config(*c)?.into_any();
                let v = match v {
                    Val::Str(s) => self.string(*s).into_any(),
                    Val::List(items) => {
                        let l = PyList::empty(self.py);
                        for x in items {
                            l.append(self.item(x)?)?;
                        }
                        l.into_any()
                    }
                };
                PyTuple::new(self.py, [c, v])?.into_any()
            }
        })
    }
}

/// Test hook: decode string-pool bytes as androguard does
/// (`bytes.decode("utf-8" or "utf-16", "replace")`).
#[pyfunction]
pub fn _decode_pool_string(data: &[u8], utf8: bool) -> String {
    py_decode(data, utf8)
}

/// Test hook: androguard's `format_value(type, data)` for a non-string type.
#[pyfunction]
pub fn _format_value(ty: u8, data: u32) -> PyResult<String> {
    format_value(ty, data).map_err(err)
}
