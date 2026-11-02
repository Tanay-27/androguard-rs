//! The thread pool every parallel loop runs on, safe across `fork()`.
//!
//! rayon's global pool can't be used after a fork: the child gets a copy of
//! the pool's state but none of its threads, so the first parallel loop
//! queues work nobody picks up and waits forever. This pool remembers the
//! process that built it; a forked child builds its own on first use (about
//! a millisecond) and never touches the parent's copy.
//!
//! Size: `ANDROGUARD_RS_THREADS`, else rayon's default (`RAYON_NUM_THREADS`,
//! else the available CPUs, which on Linux honours the cgroup CPU limit).
//!
//! Fork while no other thread is inside an androguard-rs call: a lock held by
//! another thread at the moment of the fork stays held in the child.

use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

use rayon::{ThreadPool, ThreadPoolBuilder};

struct Entry {
    pid: u32,
    pool: ThreadPool,
}

/// The current process's pool. Entries are never freed: a stale one belongs
/// to a parent whose threads don't exist here, and dropping it would signal
/// them, so it's leaked (one per fork, a few hundred bytes of live memory).
static CURRENT: AtomicPtr<Entry> = AtomicPtr::new(ptr::null_mut());

fn threads() -> usize {
    std::env::var("ANDROGUARD_RS_THREADS").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(0)
}

fn pool() -> &'static ThreadPool {
    let pid = std::process::id();
    loop {
        let cur = CURRENT.load(Ordering::Acquire);
        // SAFETY: non-null pointers in CURRENT come from Box::into_raw below
        // and are never freed, so they stay valid for the program's life.
        if let Some(e) = unsafe { cur.as_ref() }
            && e.pid == pid
        {
            return &e.pool;
        }
        let pool = ThreadPoolBuilder::new()
            .num_threads(threads())
            .thread_name(|i| format!("androguard-rs-{i}"))
            .build()
            .expect("androguard-rs: starting the thread pool");
        let fresh = Box::into_raw(Box::new(Entry { pid, pool }));
        match CURRENT.compare_exchange(cur, fresh, Ordering::AcqRel, Ordering::Acquire) {
            // SAFETY: just published; never freed (see CURRENT).
            Ok(_) => return unsafe { &(*fresh).pool },
            Err(_) => {
                // Another thread of this process installed one first. Ours
                // was never published and its threads are alive here, so
                // dropping it is fine; loop to read the winner.
                // SAFETY: `fresh` came from Box::into_raw and nothing else
                // has seen it.
                drop(unsafe { Box::from_raw(fresh) });
            }
        }
    }
}

/// Run `f` on the pool, so the parallel iterators inside it use it. Inside a
/// pool thread this just calls `f`.
pub fn install<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    pool().install(f)
}

/// Threads in the current process's pool.
pub fn current_threads() -> usize {
    pool().current_num_threads()
}
