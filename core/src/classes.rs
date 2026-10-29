//! Class metadata rendered exactly as androguard 4.1.3 presents it:
//! access-flag strings, superclass/interfaces, method
//! and field descriptors, and `repr()` of static field initial values.

use std::sync::{Arc, OnceLock};

use anyhow::{Result, anyhow, bail};
use rustc_hash::FxHashMap;

use crate::dex::{ClassData, ClassDef, Dex};
use crate::maplist::{ag_uleb128, skip_encoded_value};
use crate::py_printable::PRINTABLE;
use crate::render::AgResolver;

/// androguard's ACCESS_FLAGS, in its dict order (0x20000 repeats "synchronized").
const ACCESS_FLAGS: [(u64, &str); 17] = [
    (0x1, "public"),
    (0x2, "private"),
    (0x4, "protected"),
    (0x8, "static"),
    (0x10, "final"),
    (0x20, "synchronized"),
    (0x40, "bridge"),
    (0x80, "varargs"),
    (0x100, "native"),
    (0x200, "interface"),
    (0x400, "abstract"),
    (0x800, "strictfp"),
    (0x1000, "synthetic"),
    (0x4000, "enum"),
    (0x8000, "unused"),
    (0x10000, "constructor"),
    (0x20000, "synchronized"),
];

fn flags_words(value: u64) -> String {
    ACCESS_FLAGS
        .iter()
        .filter(|(k, _)| k & value == *k)
        .map(|(_, v)| *v)
        .collect::<Vec<_>>()
        .join(" ")
}

/// EncodedMethod.get_access_flags_string(): words, else `0x%x` if nonzero.
pub fn method_flags(value: u64) -> String {
    let s = flags_words(value);
    if s.is_empty() && value != 0 { format!("0x{value:x}") } else { s }
}

/// EncodedField.get_access_flags_string(): "" for 0, words, else `0x{:06x}`.
pub fn field_flags(value: u64) -> String {
    if value == 0 {
        return String::new();
    }
    let s = flags_words(value);
    if s.is_empty() { format!("0x{value:06x}") } else { s }
}

/// ClassDefItem.get_access_flags_string(): words, else `0x%x` (even for 0).
pub fn class_flags(value: u32) -> String {
    let s = flags_words(value as u64);
    if s.is_empty() { format!("0x{value:x}") } else { s }
}

fn py_printable(c: char) -> bool {
    let cp = c as u32;
    PRINTABLE
        .binary_search_by(|&(a, b)| {
            if b < cp {
                std::cmp::Ordering::Less
            } else if a > cp {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Python's `repr(str)`. Carried lone surrogates (see render.rs) are
/// non-printable, so they come out as `\udXXX` like in Python.
pub fn py_str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for ch in s.chars() {
        let cp = ch as u32;
        match ch {
            c if c == quote || c == '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ if cp < 0x20 || cp == 0x7f => out.push_str(&format!("\\x{cp:02x}")),
            c if cp < 0x7f => out.push(c),
            _ if (0x10F000..0x10F800).contains(&cp) => {
                out.push_str(&format!("\\u{:04x}", cp - 0x10F000 + 0xD800));
            }
            c if py_printable(c) => out.push(c),
            _ if cp <= 0xff => out.push_str(&format!("\\x{cp:02x}")),
            _ if cp <= 0xffff => out.push_str(&format!("\\u{cp:04x}")),
            _ => out.push_str(&format!("\\U{cp:08x}")),
        }
    }
    out.push(quote);
    out
}

fn py_list_repr(items: &[String]) -> String {
    format!("[{}]", items.join(", "))
}

/// An androguard 4.1.3 `EncodedValue.value`, typed as androguard types it.
/// `repr()` renders it exactly as Python's `repr(value)` does.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// VALUE_BYTE and every numeric type: an unsigned int (no sign
    /// extension, floats/doubles left as their raw bits).
    Int(u64),
    /// A string, a type name, or the "" of an unknown value type.
    Str(String),
    /// A field (enum) or method reference: androguard's nested lists.
    List(Vec<Value>),
    Bool(bool),
    /// VALUE_NULL: Python's None.
    Null,
    /// An EncodedArray or EncodedAnnotation object, as its `repr()` (with
    /// the memory address blanked to 0x0).
    Opaque(&'static str),
}

impl Value {
    /// Python's `repr(value)`.
    pub fn repr(&self) -> String {
        match self {
            Value::Int(v) => v.to_string(),
            Value::Str(s) => py_str_repr(s),
            Value::List(items) => py_list_repr(&items.iter().map(Value::repr).collect::<Vec<_>>()),
            Value::Bool(b) => if *b { "True" } else { "False" }.into(),
            Value::Null => "None".into(),
            Value::Opaque(text) => (*text).into(),
        }
    }
}

pub const ENCODED_ARRAY_REPR: &str = "<androguard.core.dex.EncodedArray object at 0x0>";
pub const ENCODED_ANNOTATION_REPR: &str = "<androguard.core.dex.EncodedAnnotation object at 0x0>";
/// What `field_rows` shows for a field without an initial value.
pub const NO_INIT: &str = "<no encoded init value>";

/// An androguard EncodedValue's `.value`.
/// Parsing mirrors androguard 4.1.3 exactly, including its quirks: numeric
/// types (0x02..0x16) are read as unsigned little-endian integers with no
/// sign extension or float decoding, from however many of the `arg + 1`
/// bytes the file still has; VALUE_BYTE always reads one byte; unknown
/// types read nothing. Sizing is maplist.rs's `skip_encoded_value`.
fn read_value(r: &AgResolver, pos: &mut usize) -> Result<Value> {
    let b = &r.dex.data;
    let start = *pos;
    let header = *b.get(*pos).ok_or_else(|| anyhow!("encoded_value out of bounds"))?;
    let arg = (header >> 5) as u32;
    let ty = header & 0x1f;
    skip_encoded_value(b, pos, 0)?;
    // Scalars span at most 8 bytes after the header.
    let raw = if ty <= 0x1b { b.get(start + 1..*pos).unwrap_or_default() } else { &[] };
    let uint = raw.iter().enumerate().fold(0u64, |acc, (i, &x)| acc | (x as u64) << (8 * i));
    // An index past u32 is out of every table, as it is for androguard.
    let idx = u32::try_from(uint).unwrap_or(u32::MAX);
    Ok(match ty {
        0x02..=0x16 | 0x00 => Value::Int(uint),
        0x17 => Value::Str(r.string(idx)),
        0x18 => Value::Str(r.type_name(idx)),
        0x19 | 0x1b => field_list(r, idx),
        0x1a => method_list(r, idx),
        0x1c => Value::Opaque(ENCODED_ARRAY_REPR),
        0x1d => Value::Opaque(ENCODED_ANNOTATION_REPR),
        0x1e => Value::Null,
        0x1f => Value::Bool(arg != 0),
        _ => Value::Str(String::new()),
    })
}

fn str_list<const N: usize>(parts: [String; N]) -> Value {
    Value::List(parts.into_iter().map(Value::Str).collect())
}

/// cm.get_field(idx): ['Lcls;', 'type', 'name'].
fn field_list(r: &AgResolver, idx: u32) -> Value {
    match r.dex.field_id(idx) {
        Some((c, t, n)) => str_list([r.type_name(c), r.type_name(t), r.string(n)]),
        None => str_list([
            "AG:IFI:invalid_class_name;".into(),
            "(AG:IFI:invalid_type)".into(),
            "AG:IFI:invalid_name".into(),
        ]),
    }
}

/// cm.get_method(idx): ['Lcls;', 'name', ['(P1 P2)', 'R']].
fn method_list(r: &AgResolver, idx: u32) -> Value {
    let Ok((c, p, n)) = r.dex.method_id(idx) else {
        return str_list([
            "AG:IMI:invalid_class_name;".into(),
            "AG:IMI:invalid_name".into(),
            "()AG:IMI:invalid_proto".into(),
        ]);
    };
    let proto = match r.dex.proto(p) {
        Some((ret, params)) => {
            let params: Vec<String> = params.into_iter().map(|t| r.type_name(t)).collect();
            str_list([format!("({})", params.join(" ")), r.type_name(ret)])
        }
        None => Value::Str("AG:IPI:invalid_params;".into()),
    };
    Value::List(vec![Value::Str(r.type_name(c)), Value::Str(r.string(n)), proto])
}

type Methods = Arc<Vec<(String, String, String)>>;
type Fields = Arc<Vec<(String, String, String)>>;

/// A class as androguard 4.1.3 presents it.
///
/// Class_defs that share a class_data_item (or static values) share these
/// `Arc`s, so a crafted DEX pointing thousands of classes at one large
/// class_data costs one parse, not one per class.
pub struct ClassInfo {
    pub name: String,
    pub access_flags: String,
    pub superclass: String,
    pub interfaces: Vec<String>,
    /// (name, descriptor "(P1 P2)R", access flags), direct then virtual.
    pub methods: Methods,
    /// (access flags, name, type), static then instance.
    pub fields: Fields,
    /// Initial values of the leading static fields; later fields have
    /// none. See `field_rows`.
    pub inits: Arc<Vec<Value>>,
}

impl ClassInfo {
    /// Each field as (access flags, name, type, initial value if any).
    pub fn field_values(&self) -> impl Iterator<Item = (&str, &str, &str, Option<&Value>)> {
        self.fields.iter().enumerate().map(|(i, (flags, name, ty))| {
            (flags.as_str(), name.as_str(), ty.as_str(), self.inits.get(i))
        })
    }

    /// Each field as (access flags, name, type, repr(init value) or
    /// "<no encoded init value>").
    pub fn field_rows(&self) -> impl Iterator<Item = (&str, &str, &str, String)> {
        self.field_values().map(|(f, n, t, v)| (f, n, t, v.map_or_else(|| NO_INIT.to_owned(), Value::repr)))
    }
}

/// What class_info renders from one class_data_item.
struct Body {
    methods: Methods,
    fields: Fields,
    inits: Arc<Vec<Value>>,
}

type Cell<T> = OnceLock<Result<Arc<T>, String>>;

/// For each class_data offset that more than one class_def points at (only
/// crafted files do that): the static_values_off of each of those classes
/// in class_def order, and the rendered result, computed on first use.
/// Static values shared the same way are memoized too. Offsets used once
/// aren't kept, so a normal DEX stores nothing here.
#[derive(Default)]
pub struct Memo {
    bodies: FxHashMap<u32, (Vec<u32>, Cell<Body>)>,
    statics: FxHashMap<u32, Cell<Vec<Value>>>,
}

impl Memo {
    pub(crate) fn build(dex: &Dex) -> Memo {
        // (class_data_off, class_def index, static_values_off)
        let mut data = Vec::new();
        for i in 0..dex.class_count() {
            let Ok(cd) = dex.class_def(i) else { continue };
            if dex.has_class_data(cd.class_data_off) {
                data.push((cd.class_data_off, i, cd.static_values_off));
            }
        }
        data.sort_unstable();
        let mut memo = Memo::default();
        for group in data.chunk_by(|a, b| a.0 == b.0).filter(|g| g.len() > 1) {
            let statics = group.iter().map(|g| g.2).filter(|&o| o != 0).collect();
            memo.bodies.insert(group[0].0, (statics, OnceLock::new()));
        }
        let mut statics: Vec<u32> = data.iter().map(|d| d.2).filter(|&o| o != 0).collect();
        statics.sort_unstable();
        memo.statics = statics.windows(2).filter(|w| w[0] == w[1]).map(|w| (w[0], OnceLock::new())).collect();
        memo
    }

    /// class_data offsets shared by more than one class_def.
    pub(crate) fn shared_class_data(&self) -> impl Iterator<Item = u32> + '_ {
        self.bodies.keys().copied()
    }
}

fn memoized<T>(cell: Option<&Cell<T>>, f: impl FnOnce() -> Result<T>) -> Result<Arc<T>> {
    let compute = || f().map(Arc::new).map_err(|e| format!("{e:#}"));
    match cell {
        Some(c) => c.get_or_init(compute).clone().map_err(|e| anyhow!(e)),
        None => compute().map_err(|e| anyhow!(e)),
    }
}

/// Render the class_data_item at `off`, used by class_defs whose
/// static_values_off are `statics` (in class_def order).
///
/// androguard gives every class_def the same ClassDataItem object for one
/// offset, and each class_def's reload() writes its static values into that
/// object's leading fields (when there are no more values than static
/// fields). So every class sharing the data shows the same values: for each
/// field, the one written by the last class_def that wrote that field.
fn body(dex: &Dex, r: &AgResolver, off: u32, statics: &[u32]) -> Result<Body> {
    let data = dex.class_data(off)?;
    let methods = data
        .direct_methods
        .iter()
        .chain(&data.virtual_methods)
        .map(|m| {
            let (name, desc) = r.method_name_and_desc(m.idx);
            (name, desc, method_flags(m.access_flags))
        })
        .collect();
    let fields = data
        .static_fields
        .iter()
        .chain(&data.instance_fields)
        .map(|f| {
            let (fname, ftype) = match dex.field_id(f.idx) {
                Some((_, t, n)) => (r.string(n), r.type_name(t)),
                None => ("AG:IFI:invalid_name".into(), "(AG:IFI:invalid_type)".into()),
            };
            (field_flags(f.access_flags), fname, ftype)
        })
        .collect();
    let inits = static_inits(dex, r, &data, statics);
    Ok(Body { methods: Arc::new(methods), fields: Arc::new(fields), inits })
}

/// The initial values of a class_data's leading static fields, written by
/// the class_defs whose static_values_off are `statics` (see `body`).
fn static_inits(dex: &Dex, r: &AgResolver, data: &ClassData, statics: &[u32]) -> Arc<Vec<Value>> {
    // Last writer wins per field: walk the writers backwards, and let each
    // fill only the fields no later writer reached, so every field is
    // written once whatever the number of classes.
    let mut inits: Option<Arc<Vec<Value>>> = None;
    let mut buf: Vec<Value> = Vec::new();
    for &sv in statics.iter().rev() {
        // An undeclared offset here makes androguard raise; class_info
        // reports that per class, and it writes nothing.
        if dex.encoded_array_declared(sv) != Some(true) {
            continue;
        }
        let Ok(values) = memoized(dex.memo.statics.get(&sv), || static_values(r, sv)) else { continue };
        let done = inits.as_ref().map_or(buf.len(), |v| v.len());
        if values.len() > data.static_fields.len() || values.len() <= done {
            continue;
        }
        if done == 0 && inits.is_none() {
            inits = Some(values);
        } else {
            if let Some(v) = inits.take() {
                buf = v.to_vec();
            }
            buf.extend(values[done..].iter().cloned());
        }
    }
    inits.unwrap_or_else(|| Arc::new(buf))
}

/// `class_info(dex, i).inits` (and its errors), without rendering the
/// class's members.
pub fn class_inits(dex: &Dex, i: usize) -> Result<Arc<Vec<Value>>> {
    let (cd, _, has_data) = class_def_checked(dex, i)?;
    if !has_data {
        return Ok(Default::default());
    }
    if dex.memo.bodies.contains_key(&cd.class_data_off) {
        return Ok(class_info(dex, i)?.inits);
    }
    let data = dex.class_data(cd.class_data_off)?;
    let sv = cd.static_values_off;
    let statics: &[u32] = if sv != 0 { &[sv] } else { &[] };
    Ok(static_inits(dex, &AgResolver { dex }, &data, statics))
}

fn static_values(r: &AgResolver, off: u32) -> Result<Vec<Value>> {
    let mut pos = off as usize;
    let n = ag_uleb128(&r.dex.data, &mut pos)?;
    // Each value takes at least one byte, so a bad count runs out of input.
    let mut values = Vec::new();
    for _ in 0..n {
        values.push(read_value(r, &mut pos)?);
    }
    Ok(values)
}

/// The checks `class_info` makes on class_def `i` itself (its errors,
/// in its order): the class_def, its interfaces' type indices and whether
/// it has a class_data.
pub fn class_def_checked(dex: &Dex, i: usize) -> Result<(ClassDef, Vec<u32>, bool)> {
    let cd = dex.class_def(i)?;
    let interfaces = dex.type_list(cd.interfaces_off)?;
    if cd.annotations_off != 0 && !dex.declared.has_annotations_dir {
        bail!("annotations_off {:#x} set but the map list has no annotations directory", cd.annotations_off);
    }
    let has_data = dex.has_class_data(cd.class_data_off);
    let sv = cd.static_values_off;
    if sv != 0 {
        match dex.encoded_array_declared(sv) {
            None => bail!("static_values_off {sv:#x} set but the map list has no encoded_array section"),
            Some(false) if has_data => bail!("static_values_off {sv:#x} is not declared in the map list"),
            _ => {}
        }
    }
    Ok((cd, interfaces, has_data))
}

/// class_def `i` and its parsed class_data (None without one), failing
/// exactly where `class_info` does, without rendering any text.
pub fn class_data_checked(dex: &Dex, i: usize) -> Result<(ClassDef, Option<ClassData>)> {
    let (cd, _, has_data) = class_def_checked(dex, i)?;
    if !has_data {
        return Ok((cd, None));
    }
    let data = dex.class_data(cd.class_data_off)?;
    Ok((cd, Some(data)))
}

/// class_info for class_def `i`, following androguard's
/// `ClassDefItem.reload()`. Where that raises (and androguard then fails
/// to load the whole DEX), this returns an error for the class:
/// - interfaces_off is not a declared type_list (KeyError);
/// - annotations_off is set but the map has no annotations_directory
///   section (KeyError);
/// - static_values_off is set and the map has no encoded_array section
///   (KeyError), or the class has class_data and static_values_off isn't
///   a declared encoded_array_item (AttributeError on None).
///
/// An undeclared class_data_off leaves the class without methods or fields,
/// as in androguard.
pub fn class_info(dex: &Dex, i: usize) -> Result<ClassInfo> {
    let r = AgResolver { dex };
    let (cd, ifaces, has_data) = class_def_checked(dex, i)?;
    let interfaces = ifaces.into_iter().map(|t| r.type_name(t)).collect();
    let sv = cd.static_values_off;
    let body = if !has_data {
        Arc::new(Body { methods: Default::default(), fields: Default::default(), inits: Default::default() })
    } else if let Some((statics, cell)) = dex.memo.bodies.get(&cd.class_data_off) {
        memoized(Some(cell), || body(dex, &r, cd.class_data_off, statics))?
    } else {
        let statics: &[u32] = if sv != 0 { &[sv] } else { &[] };
        Arc::new(body(dex, &r, cd.class_data_off, statics)?)
    };
    Ok(ClassInfo {
        name: r.type_name(cd.class_idx),
        access_flags: class_flags(cd.access_flags),
        superclass: r.type_name(cd.superclass_idx),
        interfaces,
        methods: body.methods.clone(),
        fields: body.fields.clone(),
        inits: body.inits.clone(),
    })
}

/// One DEX's class metadata as dump lines (see `spike classes`).
pub fn dump(dex: &Dex, out: &mut dyn FnMut(String) -> Result<()>) -> Result<()> {
    for i in 0..dex.class_count() {
        let c = class_info(dex, i)?;
        out(format!("C\t{}\t{}\t{}\t{}", c.name, c.access_flags, c.superclass, c.interfaces.join(",")))?;
        for (name, desc, flags) in c.methods.iter() {
            out(format!("M\t{}\t{name}\t{desc}\t{flags}", c.name))?;
        }
        for (flags, name, ty, init) in c.field_rows() {
            out(format!("F\t{}\t{flags}\t{name}\t{ty}\t{init}", c.name))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdex::{Class, Spec, build};

    #[test]
    fn typed_init_values_and_their_repr() {
        let dex = build(&Spec {
            // 0 I, 1 LA;, 2 Ljava/lang/Object;, 3 V, 4 it's, 5 m, 6..=11 field names
            strings: vec!["I", "LA;", "Ljava/lang/Object;", "V", "it's", "m", "f0", "f1", "f2", "f3", "f4", "f5"],
            types: vec![0, 1, 2, 3],
            protos: vec![(3, 3)],
            fields: (6..12).map(|n| (1, 0, n)).collect(),
            methods: vec![(1, 0, 5)],
            classes: vec![Class {
                type_idx: 1,
                super_idx: 2,
                static_fields: (0..6).map(|i| (i, 9)).collect(),
                instance_fields: vec![],
                direct: vec![(0, 9, None)],
                static_values: vec![
                    vec![0x64, 0x01, 0x00, 0x0b, 0x7f], // int 0x7f0b0001
                    vec![0x00, 0xfe],                   // byte: unsigned
                    vec![0x17, 4],                      // string
                    vec![0x3f],                         // true
                    vec![0x1e],                         // null
                    vec![0x1a, 0],                      // method
                ],
            }],
        });
        let c = class_info(&dex, 0).unwrap();
        let method = Value::List(vec![
            Value::Str("LA;".into()),
            Value::Str("m".into()),
            Value::List(vec![Value::Str("()".into()), Value::Str("V".into())]),
        ]);
        assert_eq!(
            *c.inits,
            vec![Value::Int(0x7f0b0001), Value::Int(254), Value::Str("it's".into()), Value::Bool(true), Value::Null, method]
        );
        let reprs: Vec<String> = c.field_rows().map(|r| r.3).collect();
        assert_eq!(reprs, ["2131427329", "254", "\"it's\"", "True", "None", "['LA;', 'm', ['()', 'V']]"]);
    }

    #[test]
    fn value_repr_matches_python() {
        assert_eq!(Value::Str(String::new()).repr(), "''");
        assert_eq!(Value::Opaque(ENCODED_ARRAY_REPR).repr(), ENCODED_ARRAY_REPR);
        assert_eq!(Value::Bool(false).repr(), "False");
        assert_eq!(Value::List(vec![]).repr(), "[]");
        assert_eq!(Value::Int(u64::MAX).repr(), "18446744073709551615");
    }
}
