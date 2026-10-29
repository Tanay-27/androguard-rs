//! Runs every query the bindings expose on untrusted input, for the fuzzers
//! (`spike fuzz` and the cargo-fuzz targets in fuzz/). Results are thrown
//! away: the point is that nothing panics, hangs or allocates without bound.

use anyhow::Result;

use crate::arsc::Arsc;
use crate::classes::class_info;
use crate::dex::Dex;
use crate::index::Index;
use crate::model::{Model, const_strings, hierarchy, xrefs};
use crate::render::{AgResolver, invalid_instruction_str, py_lower};

/// Everything a single DEX goes through: per-class metadata, per-method
/// bytecode text (and the androguard error text when rejected), then the
/// whole index and its queries.
pub fn dex(dex: Dex) -> Result<()> {
    let _ = crate::apk::androguard_header_check(&dex.data, true);
    for i in 0..dex.class_count() {
        let _ = class_info(&dex, i);
    }
    let resolver = AgResolver { dex: &dex };
    if let Ok(methods) = dex.methods_with_code() {
        for m in methods {
            if let Ok(code) = dex.code(m.code_off) {
                match dex_bytecode::decode_all_with_resolver(code, 0, &resolver) {
                    Ok(insns) => {
                        for i in insns {
                            let _ = py_lower(&i.operands);
                        }
                    }
                    Err(e) => {
                        let _ = invalid_instruction_str(&e);
                    }
                }
                let _ = crate::insn_rows::insn_rows(&dex, code);
            }
        }
    }
    index(Index::build(vec![dex])?);
    Ok(())
}

/// The per-DEX object queries (`androguard_rs.dex.DEX`): class names, each
/// class_def's header, each distinct class_data's members, the member
/// lookups and the SSL pre-filter.
pub fn dex_objects(dex: &Dex) {
    let _ = crate::dexview::class_names(dex);
    let mut seen = rustc_hash::FxHashSet::default();
    for ci in 0..dex.class_count() {
        if let Ok(h) = crate::dexview::class_header(dex, ci)
            && seen.insert(h.class_data_off)
        {
            let _ = crate::dexview::class_members(dex, ci);
        }
    }
    let _ = crate::dexview::field_names(dex);
    let _ = crate::dexview::find_member(dex, b"La;a()V", false);
    let _ = crate::dexview::find_member(dex, b"La;aI", true);
    let _ = crate::dexview::ssl_candidates(dex);
}

/// Every query on a built index.
pub fn index(idx: Index) {
    let _ = crate::strict::first_invalid(&idx.dexes);
    for d in &idx.dexes {
        dex_objects(d);
    }
    let _ = idx.methods_using_string(b"a");
    let model = Model::build(&idx);
    let extra = |h| model.r_segments(&idx, h);
    let _ = idx.search_instruction_text(&["v0".to_string(), "l".to_string()], &extra);
    for g in 0..idx.method_count() as u32 {
        let _ = idx.sig(g);
        let _ = idx.callers_of(g);
        let _ = idx.callees_of(g);
        let _ = idx.code_of(g);
        let _ = xrefs(&idx, g, true);
        let _ = xrefs(&idx, g, false);
    }
    for (name, _) in model.classes(&idx) {
        let _ = idx.resolve_sig(&name);
        if let Some(ms) = model.class_methods(&idx, &name) {
            for m in ms.own.iter().chain(ms.tail_entries()) {
                let _ = idx.resolve_sig(&m.sig);
                let _ = model.sig_xrefs(&idx, &m.sig, true);
                let _ = model.sig_xrefs(&idx, &m.sig, false);
                if let crate::index::HitKey::Full(k) = m.key {
                    let _ = model.r_xrefs(&idx, k, true);
                    let _ = model.r_xrefs(&idx, k, false);
                    let _ = model.listed(&idx, k);
                }
            }
        }
        let _ = model.class_fields(&idx, &name);
        let _ = model.class_position(&idx, name.as_bytes());
    }
    for i in 0..model.class_count(&idx) {
        let _ = model.class_at(&idx, i);
        let _ = crate::model::class_hierarchy(&idx, i);
    }
    let _ = model.class_methods(&idx, "La;");
    let _ = hierarchy(&idx);
    let _ = const_strings(&idx, true, &extra);
    // Every MethodAnalysis of the first irregular class_defs, listed or not.
    for j in 0..idx.irr.defs.len().min(64) as u32 {
        let b = idx.irr.defs[j as usize].block;
        if b == crate::irregular::NONE {
            continue;
        }
        for e in idx.irr.em_range(b).take(256) {
            let k = crate::irregular::key(j, e);
            let _ = model.r_xrefs(&idx, k, true);
            let _ = model.r_xrefs(&idx, k, false);
        }
    }
}

/// Every resources query on a parsed `resources.arsc`: each package and
/// locale's public XML, the resolved strings, and names and resolved values
/// for (up to 256) rids plus a few misses.
pub fn arsc(arsc: Arsc) {
    let _ = arsc.analysis_error();
    let packages: Vec<String> = arsc.package_names().into_iter().map(str::to_owned).collect();
    for p in &packages {
        let locales: Vec<String> = arsc.locales(p).into_iter().map(str::to_owned).collect();
        for l in &locales {
            let _ = arsc.public_resources(p, l);
        }
    }
    let _ = arsc.public_resources("x", crate::arsc::DEFAULT_LOCALE);
    let _ = arsc.resolved_strings();
    let mut rids = arsc.rids();
    rids.truncate(256);
    rids.extend([1, 0x7F01_0000, u32::MAX]);
    for rid in rids {
        let _ = arsc.resolved_res_configs(rid);
        let _ = arsc.resource_xml_name(rid as i64, None);
        for p in &packages {
            let _ = arsc.resource_xml_name(rid as i64, Some(p));
        }
    }
    let _ = arsc.heap_bytes();
}
