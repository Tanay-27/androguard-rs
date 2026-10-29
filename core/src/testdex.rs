//! A minimal DEX writer for unit tests (python/tests/dexbuild.py is the
//! full one): sorted id tables given by the test, protos without
//! parameters, code items, class_data and static values, and a map list
//! declaring them, so `Dex::parse` sees what androguard would.

use crate::dex::Dex;

pub fn uleb(mut v: u32, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// Indices are into the test's own tables. Methods: (method_idx, flags,
/// insns or None). Fields: (field_idx, flags).
pub struct Class {
    pub type_idx: u32,
    pub super_idx: u32,
    pub static_fields: Vec<(u32, u32)>,
    pub instance_fields: Vec<(u32, u32)>,
    pub direct: Vec<(u32, u32, Option<Vec<u8>>)>,
    /// Encoded values of the leading static fields, already encoded.
    pub static_values: Vec<Vec<u8>>,
}

pub struct Spec {
    pub strings: Vec<&'static str>,
    /// String index of each type.
    pub types: Vec<u32>,
    /// (shorty string, return type) per proto.
    pub protos: Vec<(u32, u32)>,
    /// (class type, field type, name string).
    pub fields: Vec<(u32, u32, u32)>,
    /// (class type, proto, name string).
    pub methods: Vec<(u32, u32, u32)>,
    pub classes: Vec<Class>,
}

fn align4(b: &mut Vec<u8>) {
    while !b.len().is_multiple_of(4) {
        b.push(0);
    }
}

fn put(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

pub fn build(spec: &Spec) -> Dex {
    let mut b = vec![0u8; 0x70];
    let ids = b.len();
    let (n_s, n_t, n_p, n_f, n_m, n_c) =
        (spec.strings.len(), spec.types.len(), spec.protos.len(), spec.fields.len(), spec.methods.len(), spec.classes.len());
    let (s_off, t_off) = (ids, ids + 4 * n_s);
    let p_off = t_off + 4 * n_t;
    let f_off = p_off + 12 * n_p;
    let m_off = f_off + 8 * n_f;
    let c_off = m_off + 8 * n_m;
    b.resize(c_off + 32 * n_c, 0);
    for (i, &t) in spec.types.iter().enumerate() {
        put(&mut b, t_off + 4 * i, t);
    }
    for (i, &(shorty, ret)) in spec.protos.iter().enumerate() {
        put(&mut b, p_off + 12 * i, shorty);
        put(&mut b, p_off + 12 * i + 4, ret);
    }
    for (i, &(c, t, n)) in spec.fields.iter().enumerate() {
        b[f_off + 8 * i..f_off + 8 * i + 4].copy_from_slice(&[(c as u16).to_le_bytes(), (t as u16).to_le_bytes()].concat());
        put(&mut b, f_off + 8 * i + 4, n);
    }
    for (i, &(c, p, n)) in spec.methods.iter().enumerate() {
        b[m_off + 8 * i..m_off + 8 * i + 4].copy_from_slice(&[(c as u16).to_le_bytes(), (p as u16).to_le_bytes()].concat());
        put(&mut b, m_off + 8 * i + 4, n);
    }
    // Code items, then string data, class data, encoded arrays.
    align4(&mut b);
    let code_start = b.len();
    let mut code_offs = Vec::new();
    for c in &spec.classes {
        for (_, _, insns) in &c.direct {
            let Some(insns) = insns else {
                code_offs.push(0);
                continue;
            };
            align4(&mut b);
            code_offs.push(b.len() as u32);
            for v in [4u16, 1, 1, 0] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend_from_slice(&((insns.len() / 2) as u32).to_le_bytes());
            b.extend_from_slice(insns);
        }
    }
    let n_code = code_offs.iter().filter(|&&o| o != 0).count();
    let str_start = b.len();
    for (i, s) in spec.strings.iter().enumerate() {
        let at = b.len();
        put(&mut b, s_off + 4 * i, at as u32);
        uleb(s.len() as u32, &mut b);
        b.extend_from_slice(s.as_bytes());
        b.push(0);
    }
    let cd_start = b.len();
    let mut codes = code_offs.into_iter();
    let mut cd_offs = Vec::new();
    for c in &spec.classes {
        cd_offs.push(b.len() as u32);
        for n in [c.static_fields.len(), c.instance_fields.len(), c.direct.len(), 0] {
            uleb(n as u32, &mut b);
        }
        for list in [&c.static_fields, &c.instance_fields] {
            let mut prev = 0;
            for &(idx, flags) in list {
                uleb(idx - prev, &mut b);
                uleb(flags, &mut b);
                prev = idx;
            }
        }
        let mut prev = 0;
        for &(idx, flags, _) in &c.direct {
            uleb(idx - prev, &mut b);
            uleb(flags, &mut b);
            uleb(codes.next().unwrap(), &mut b);
            prev = idx;
        }
    }
    let ea_start = b.len();
    let mut ea_offs = Vec::new();
    for c in &spec.classes {
        if c.static_values.is_empty() {
            ea_offs.push(0);
            continue;
        }
        ea_offs.push(b.len() as u32);
        uleb(c.static_values.len() as u32, &mut b);
        for v in &c.static_values {
            b.extend_from_slice(v);
        }
    }
    let n_ea = ea_offs.iter().filter(|&&o| o != 0).count();
    for (i, c) in spec.classes.iter().enumerate() {
        let o = c_off + 32 * i;
        for (k, v) in [c.type_idx, 1, c.super_idx, 0, 0, 0, cd_offs[i], ea_offs[i]].into_iter().enumerate() {
            put(&mut b, o + 4 * k, v);
        }
    }
    align4(&mut b);
    let map = b.len();
    let mut entries: Vec<(u16, usize, usize)> = vec![
        (0, 1, 0),
        (1, n_s, s_off),
        (2, n_t, t_off),
        (3, n_p, p_off),
        (4, n_f, f_off),
        (5, n_m, m_off),
        (6, n_c, c_off),
        (0x2001, n_code, code_start),
        (0x2002, n_s, str_start),
        (0x2000, n_c, cd_start),
        (0x2005, n_ea, ea_start),
    ];
    entries.retain(|e| e.1 != 0);
    entries.push((0x1000, 1, map));
    b.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (ty, size, off) in entries {
        b.extend_from_slice(&ty.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&(size as u32).to_le_bytes());
        b.extend_from_slice(&(off as u32).to_le_bytes());
    }
    b[0..8].copy_from_slice(b"dex\n035\0");
    let len = b.len() as u32;
    put(&mut b, 32, len);
    put(&mut b, 36, 0x70);
    put(&mut b, 40, 0x12345678);
    put(&mut b, 52, map as u32);
    for (k, (n, off)) in [(n_s, s_off), (n_t, t_off), (n_p, p_off), (n_f, f_off), (n_m, m_off), (n_c, c_off)].into_iter().enumerate() {
        put(&mut b, 56 + 8 * k, n as u32);
        put(&mut b, 60 + 8 * k, off as u32);
    }
    Dex::parse(b).expect("test DEX parses")
}
