//! Spike: can a Rust DEX index replace androguard's AnalyzeAPK for the
//! queries our tools make, at a fraction of the memory and time?
//!
//!   spike stats <apk>                 build the whole-APK index, print timings, counts and sample queries
//!   spike edges <apk> <classesN.dex>  dump one DEX's invoke edges (caller \t callee \t offset) for parity
//!   spike insns <apk> <classesN.dex>  dump every instruction's androguard-style text (method \t offset \t name \t output)
//!   spike classes <apk> <classesN.dex> dump class metadata: C (class), M (method) and F (field) lines
//!   spike fuzz <apk> <classesN.dex> <iterations> <seed> <out_dir>   mutation-fuzz one DEX (build with --profile fuzz)


use std::io::{BufWriter, Write};
use std::time::Instant;

use anyhow::{Result, bail};

use androguard_core::apk::{dex_entries, load};
use androguard_core::index::Index;
use androguard_core::{classes, render};

mod fuzz;

fn mib(b: usize) -> f64 {
    b as f64 / (1024.0 * 1024.0)
}

fn stats(apk: &str) -> Result<()> {
    let t0 = Instant::now();
    let entries = dex_entries(apk)?;
    let dexes = load(apk, &entries)?;
    let t_load = t0.elapsed();

    let t1 = Instant::now();
    let idx = Index::build(dexes)?;
    let t_index = t1.elapsed();

    let s = idx.stats;
    println!("dex files            {}", entries.len());
    println!("dex bytes            {:.1} MiB", mib(idx.dex_bytes()));
    println!("classes              {}", s.classes);
    println!("methods with code    {}", s.methods_with_code);
    println!("instructions         {}  (incl. {} payloads)", s.instructions, s.payloads);
    println!("invoke edges         {}", s.invoke_edges);
    println!("const-string refs    {}", s.string_refs);
    println!("field refs           {}", s.field_refs);
    println!("type refs            {}", s.type_refs);
    println!("methods (global)     {}  ({} internal)", idx.method_count(), idx.internal_count());
    println!("truncated methods    {}", s.truncated_methods);
    println!("bad method refs      {}", s.bad_method_refs);
    println!("index structures     {:.1} MiB", mib(idx.index_bytes()));
    println!();
    println!("unzip + parse        {:.2}s", t_load.as_secs_f64());
    println!("decode + index       {:.2}s", t_index.as_secs_f64());
    println!("total                {:.2}s", t0.elapsed().as_secs_f64());
    println!();

    // Sample queries, the shapes our tools ask for.
    let t = Instant::now();
    let busiest = (0..idx.method_count() as u32).max_by_key(|&g| idx.callers_of(g).len()).unwrap_or(0);
    println!("busiest callee: {} ({} call sites) — scan {:.0}ms", idx.sig(busiest), idx.callers_of(busiest).len(), t.elapsed().as_secs_f64() * 1e3);

    for sig in [
        "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;",
        "Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
        "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I",
    ] {
        let t = Instant::now();
        match idx.gid_of(sig) {
            Some(g) => {
                let callers = idx.callers_of(g);
                let sample = callers.first().map(|c| idx.sig(c[0])).unwrap_or_default();
                println!("callers_of {sig}\n  -> {} call sites in {:.3}ms, e.g. {sample}", callers.len(), t.elapsed().as_secs_f64() * 1e3);
            }
            None => println!("callers_of {sig}\n  -> not referenced"),
        }
    }
    for needle in ["http://", "AES/ECB"] {
        let t = Instant::now();
        let (strings, methods) = idx.methods_using_string(needle.as_bytes());
        println!("strings containing {needle:?}: {strings} strings, {} methods — {:.0}ms", methods.len(), t.elapsed().as_secs_f64() * 1e3);
    }
    Ok(())
}

fn edges(apk: &str, entry: &str) -> Result<()> {
    let dexes = load(apk, &[entry.to_string()])?;
    let idx = Index::build(dexes)?;
    let mut out = BufWriter::new(std::io::stdout().lock());
    for caller in 0..idx.method_count() as u32 {
        let callees = idx.callees_of(caller);
        if callees.is_empty() {
            continue;
        }
        let caller_sig = idx.sig(caller);
        for &[callee, off] in callees {
            writeln!(out, "{caller_sig}\t{}\t{off}", idx.sig(callee))?;
        }
    }
    Ok(())
}

/// One line per instruction: `method \t offset \t mnemonic \t operands`,
/// or `method \tERR` when androguard would reject the method's bytecode.
fn insns(apk: &str, entry: &str) -> Result<()> {
    let dexes = load(apk, &[entry.to_string()])?;
    let dex = &dexes[0];
    let resolver = render::AgResolver { dex };
    let mut out = BufWriter::new(std::io::stdout().lock());
    let mut line = String::new();
    for m in dex.methods_with_code()? {
        let sig = resolver.method_key(m.method_idx);
        let Ok(code) = dex.code(m.code_off) else {
            writeln!(out, "{sig}\tERR\tunreadable code_item")?;
            continue;
        };
        let decoded = match dex_bytecode::decode_all_with_resolver(code, 0, &resolver) {
            Ok(d) => d,
            Err(e) => {
                line.clear();
                render::escape_field(&sig, &mut line);
                line.push_str("\tERR\t");
                render::escape_field(&render::invalid_instruction_str(&e), &mut line);
                writeln!(out, "{line}")?;
                continue;
            }
        };
        for ins in decoded {
            line.clear();
            render::escape_field(&sig, &mut line);
            line.push_str(&format!("\t{}\t{}\t", ins.offset, ins.mnemonic));
            render::escape_field(&ins.operands, &mut line);
            writeln!(out, "{line}")?;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("stats") if args.len() == 3 => stats(&args[2]),
        Some("edges") if args.len() == 4 => edges(&args[2], &args[3]),
        Some("insns") if args.len() == 4 => insns(&args[2], &args[3]),
        Some("replay") if args.len() == 3 => fuzz::replay(&args[2]),
        Some("fuzz") if args.len() == 7 => fuzz::run(&args[2], &args[3], args[4].parse()?, args[5].parse()?, &args[6]),
        Some("classes") if args.len() == 4 => {
            let dexes = load(&args[2], &[args[3].clone()])?;
            let mut out = BufWriter::new(std::io::stdout().lock());
            let mut line = String::new();
            classes::dump(&dexes[0], &mut |l| {
                line.clear();
                for (i, field) in l.split('\t').enumerate() {
                    if i > 0 {
                        line.push('\t');
                    }
                    render::escape_field(field, &mut line);
                }
                Ok(writeln!(out, "{line}")?)
            })
        }
        _ => bail!("usage: spike stats <apk> | spike edges <apk> <classesN.dex> | spike insns <apk> <classesN.dex> | spike classes <apk> <classesN.dex>"),
    }
}
