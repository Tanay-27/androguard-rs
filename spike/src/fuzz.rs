//! Mutation fuzzer for the parsing and rendering paths, on stable Rust.
//!
//! Mutates a real DEX (header table sizes/offsets, random bytes, bit flips,
//! truncation) and runs the whole pipeline on each mutant under
//! catch_unwind. A malformed DEX must come back as an error: any panic or
//! slow case is reported and its input saved for replay.

use std::panic::{self, AssertUnwindSafe};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::Result;

use androguard_core::apk::load;
use androguard_core::dex::Dex;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn mutate(data: &mut Vec<u8>, rng: &mut Rng) {
    let len = data.len() as u32;
    let interesting = [0, 1, 2, 0x7f, 0x80, 0xff, 0xffff, 0x7fff_ffff, 0xffff_ffff, len, len - 1, len + 1];
    for _ in 0..1 + rng.below(8) {
        let pick = rng.below(100);
        let n = data.len();
        if n < 8 {
            break;
        }
        if pick < 30 && n >= 112 {
            // Header sizes/offsets (bytes 32..112): the fields every table read trusts.
            let off = 32 + 4 * rng.below(20);
            let v = if rng.below(4) == 0 { rng.next() as u32 } else { interesting[rng.below(interesting.len())] };
            data[off..off + 4].copy_from_slice(&v.to_le_bytes());
        } else if pick < 60 {
            let i = rng.below(n);
            data[i] = rng.next() as u8;
        } else if pick < 80 {
            let i = rng.below(n);
            data[i] ^= 1 << rng.below(8);
        } else if pick < 92 {
            let off = rng.below(n - 4) & !3;
            let v = interesting[rng.below(interesting.len())];
            data[off..off + 4].copy_from_slice(&v.to_le_bytes());
        } else {
            data.truncate(8 + rng.below(n - 8));
        }
    }
}

fn exercise(data: Vec<u8>) -> Result<()> {
    androguard_core::exercise::dex(Dex::parse(data)?)
}

/// Run one saved input through the same pipeline, for debugging a finding.
pub fn replay(path: &str) -> Result<()> {
    let data = std::fs::read(path)?;
    let t = Instant::now();
    let res = exercise(data);
    println!("{path}: {:?} in {:.1}ms", res.map(|_| "ok"), t.elapsed().as_secs_f64() * 1e3);
    Ok(())
}

pub fn run(apk: &str, entry: &str, iterations: u64, seed: u64, out_dir: &str) -> Result<()> {
    let base = load(apk, &[entry.to_string()])?.remove(0).data;
    std::fs::create_dir_all(out_dir)?;
    static LOCATION: Mutex<String> = Mutex::new(String::new());
    panic::set_hook(Box::new(|info| {
        *LOCATION.lock().unwrap() = info.location().map(|l| l.to_string()).unwrap_or_default();
    }));
    let mut rng = Rng(seed | 1);
    let (mut ok, mut rejected, mut panics, mut slow) = (0u64, 0u64, 0u64, 0u64);
    let mut slowest = 0f64;
    let base_t = Instant::now();
    exercise(base.clone())?;
    let base_secs = base_t.elapsed().as_secs_f64();
    for it in 0..iterations {
        let mut data = base.clone();
        if panic::catch_unwind(AssertUnwindSafe(|| mutate(&mut data, &mut rng))).is_err() {
            anyhow::bail!("harness bug: mutate() panicked at iteration {it} ({})", LOCATION.lock().unwrap());
        }
        // Saved before running, so an input that kills the process outright
        // (abort, OOM kill) is still on disk afterwards.
        std::fs::write(format!("{out_dir}/current-{seed}.dex"), &data)?;
        let t = Instant::now();
        let res = panic::catch_unwind(AssertUnwindSafe(|| exercise(data.clone())));
        let secs = t.elapsed().as_secs_f64();
        slowest = slowest.max(secs);
        match res {
            Ok(Ok(())) => ok += 1,
            Ok(Err(_)) => rejected += 1,
            Err(p) => {
                panics += 1;
                let msg = p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()));
                eprintln!("PANIC at iteration {it} ({}): {}", LOCATION.lock().unwrap(), msg.unwrap_or_default());
                std::fs::write(format!("{out_dir}/panic-{seed}-{it}.dex"), &data)?;
            }
        }
        if secs > 1.0 + 20.0 * base_secs {
            slow += 1;
            std::fs::write(format!("{out_dir}/slow-{seed}-{it}.dex"), &data)?;
        }
    }
    // Restore the default hook so a panic outside catch_unwind (a harness
    // bug) is never silent again.
    let _ = panic::take_hook();
    println!(
        "{entry}: {iterations} mutants — {ok} parsed, {rejected} rejected with an error, {panics} panics, {slow} slow (> 20x the unmutated {:.1}ms); slowest {:.1}ms",
        base_secs * 1e3,
        slowest * 1e3
    );
    Ok(())
}
