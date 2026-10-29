//! The APK-side pieces of androguard 4.1.3 that `androguard_rs.apk` builds
//! its `APK` and `AXMLPrinter` on: `AxmlParser` (androguard's `AXMLParser`)
//! and `ApkFile` (the zip as apkInspector reads it, plus the v2/v3 signing
//! block). Kept apart from the DEX bindings in lib.rs.

#![allow(non_snake_case)] // androguard's method names

use std::sync::Mutex;

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyKeyError};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::{PyBytes, PyList, PyString, PyTuple};

use androguard_core::axml::AxmlParser as CoreParser;
use androguard_core::zipapk::{self, ApkZip, MemSource, ReadError, SigningBlock};

// Raised wherever androguard's AXMLParser/AXMLPrinter raises something other
// than what it catches (struct.error, ResParserError from a string, ...).
create_exception!(androguard_rs, AxmlError, PyException);
// Raised where androguard's APK/apkInspector raise on a broken zip or
// signing block (ValueError, struct.error, zlib.error, BrokenAPKError, ...).
create_exception!(androguard_rs, ApkError, PyException);

fn axml_err(e: anyhow::Error) -> PyErr {
    AxmlError::new_err(format!("{e:#}"))
}

fn apk_err(e: anyhow::Error) -> PyErr {
    ApkError::new_err(format!("{e:#}"))
}

/// androguard's `AXMLParser`, method for method (only what `AXMLPrinter`
/// uses). Strings come back as `str`; errors as `AxmlError`.
#[pyclass(module = "androguard_rs")]
pub struct AxmlParser {
    p: CoreParser,
}

#[pymethods]
impl AxmlParser {
    #[new]
    fn new(py: Python<'_>, data: &[u8]) -> PyResult<Self> {
        let data = data.to_vec();
        py.detach(move || CoreParser::new(data)).map(|p| AxmlParser { p }).map_err(axml_err)
    }

    fn is_valid(&self) -> bool {
        self.p.is_valid()
    }

    /// `next(parser)`: the next event (`m_event`).
    fn next(&mut self) -> PyResult<i32> {
        self.p.next_event().map_err(axml_err)
    }

    #[getter]
    fn m_event(&self) -> i32 {
        self.p.event()
    }

    #[getter]
    fn m_lineNumber(&self) -> i64 {
        self.p.line_number()
    }

    #[getter]
    fn packerwarning(&self) -> bool {
        self.p.packerwarning
    }

    #[getter]
    fn axml_tampered(&self) -> bool {
        self.p.axml_tampered
    }

    #[getter]
    fn name(&mut self) -> PyResult<String> {
        self.p.name().map(|s| s.to_string()).map_err(axml_err)
    }

    #[getter]
    fn namespace(&mut self) -> PyResult<String> {
        self.p.namespace().map(|s| s.to_string()).map_err(axml_err)
    }

    #[getter]
    fn comment(&mut self) -> PyResult<Option<String>> {
        self.p.comment().map(|s| s.map(|s| s.to_string())).map_err(axml_err)
    }

    #[getter]
    fn text(&mut self) -> PyResult<String> {
        self.p.text().map(|s| s.to_string()).map_err(axml_err)
    }

    /// `parser.namespaces`: open (prefix, uri) string indices, in order.
    #[getter]
    fn namespaces<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let items: Vec<Bound<'py, PyTuple>> =
            self.p.namespaces().iter().map(|&(a, b)| PyTuple::new(py, [a, b])).collect::<PyResult<_>>()?;
        PyList::new(py, items)
    }

    /// Changes whenever `namespaces` does (for caching `nsmap`).
    fn namespaces_version(&self) -> u64 {
        self.p.namespaces_version()
    }

    /// `parser.sb[idx]`.
    fn string<'py>(&mut self, py: Python<'py>, idx: u32) -> PyResult<Bound<'py, PyString>> {
        let s = self.p.string(idx).map_err(axml_err)?;
        Ok(PyString::new(py, &s))
    }

    fn getAttributeCount(&self) -> i64 {
        self.p.attribute_count()
    }

    fn getAttributeNamespace(&mut self, index: usize) -> PyResult<String> {
        self.p.attribute_namespace(index).map(|s| s.to_string()).map_err(axml_err)
    }

    fn getAttributeName(&mut self, index: usize) -> PyResult<String> {
        self.p.attribute_name(index).map_err(axml_err)
    }

    fn getAttributeValueType(&self, index: usize) -> PyResult<u32> {
        self.p.attribute_value_type(index).map_err(axml_err)
    }

    fn getAttributeValueData(&self, index: usize) -> PyResult<u32> {
        self.p.attribute_value_data(index).map_err(axml_err)
    }

    fn getAttributeValue(&mut self, index: usize) -> PyResult<String> {
        self.p.attribute_value(index).map(|s| s.to_string()).map_err(axml_err)
    }
}

/// An APK's zip and signing block, read as androguard 4.1.3 reads them.
/// Opened from a path (read through seeks, never loaded whole) or from a
/// `bytes` object (used in place, not copied).
#[pyclass(frozen, module = "androguard_rs")]
pub struct ApkFile {
    zip: ApkZip<'static>,
    path: Option<String>,
    raw: Option<Py<PyAny>>,
    signing: Mutex<Option<SigningBlock>>,
}

#[pymethods]
impl ApkFile {
    /// `ZipEntry.parse(path)`: raises ApkError where it raises.
    #[new]
    fn new(py: Python<'_>, path: &str) -> PyResult<Self> {
        let p = path.to_owned();
        let zip = py.detach(move || ApkZip::open_path(&p)).map_err(apk_err)?;
        Ok(ApkFile { zip, path: Some(path.to_owned()), raw: None, signing: Mutex::new(None) })
    }

    /// The same for an APK held in memory (`bytes` is kept, not copied;
    /// a `bytearray` is copied once).
    #[staticmethod]
    fn from_bytes(py: Python<'_>, data: Bound<'_, PyAny>) -> PyResult<Self> {
        let backed: PyBackedBytes = data.extract()?;
        let raw = data.unbind();
        let zip = py.detach(move || ApkZip::open(Box::new(MemSource(backed)))).map_err(apk_err)?;
        Ok(ApkFile { zip, path: None, raw: Some(raw), signing: Mutex::new(None) })
    }

    /// `namelist()`, a new list each call.
    fn namelist(&self) -> Vec<String> {
        self.zip.names().to_vec()
    }

    /// `ZipEntry.read(name)`: KeyError when there is no such entry (or its
    /// local header is missing), ApkError when it can't be extracted.
    fn read<'py>(&self, py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyBytes>> {
        let n = name.to_owned();
        match py.detach(|| self.zip.read(&n)) {
            Ok(b) => Ok(PyBytes::new(py, &b)),
            Err(ReadError::NotPresent) => Err(PyKeyError::new_err(format!(
                "Key: {name} was not found within the local headers list!"
            ))),
            Err(ReadError::Failed(e)) => Err(apk_err(e)),
        }
    }

    /// Size of the APK in bytes.
    fn size(&self) -> u64 {
        self.zip.source().size()
    }

    /// The whole APK: the original `bytes` object, or the file read now.
    fn raw<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        if let Some(r) = &self.raw {
            return Ok(r.bind(py).clone());
        }
        let path = self.path.clone().unwrap_or_default();
        let b = py.detach(move || std::fs::read(&path)).map_err(|e| apk_err(e.into()))?;
        Ok(PyBytes::new(py, &b).into_any())
    }

    /// `parse_v2_v3_signature()` as (flags_set, v2, v3, error or None),
    /// computed once.
    fn signing_block(&self) -> (bool, bool, bool, Option<String>) {
        let sb = self.block();
        (sb.flags_set, sb.v2, sb.v3, sb.error)
    }

    /// `get_certificates_der_v2()` / `_v3()` from a fresh parse of the
    /// signer block: (certificates as DER bytes, error or None). Empty if
    /// that scheme's block isn't there.
    fn signer_certificates<'py>(&self, py: Python<'py>, v3: bool) -> PyResult<(Vec<Bound<'py, PyBytes>>, Option<String>)> {
        let sb = self.block();
        let at = if v3 { sb.v3_value } else { sb.v2_value };
        let Some(at) = at.filter(|_| if v3 { sb.v3 } else { sb.v2 }) else { return Ok((Vec::new(), None)) };
        let src = self.zip.source();
        let (certs, e) = py.detach(|| -> anyhow::Result<_> {
            let block = zipapk::read_block_value(src, at)?;
            Ok(zipapk::signer_certificates(&block, v3))
        })
        .map_err(apk_err)?;
        Ok((certs.iter().map(|c| PyBytes::new(py, c)).collect(), e))
    }
}

impl ApkFile {
    fn block(&self) -> SigningBlock {
        let mut g = self.signing.lock().unwrap_or_else(|e| e.into_inner());
        g.get_or_insert_with(|| zipapk::signing_block(self.zip.source())).clone()
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<AxmlParser>()?;
    m.add_class::<ApkFile>()?;
    m.add("AxmlError", m.py().get_type::<AxmlError>())?;
    m.add("ApkError", m.py().get_type::<ApkError>())?;
    Ok(())
}
