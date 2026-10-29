"""Differential load fuzzer: mutate real DEX files, load each mutant with
androguard 4.1.3 and with androguard_rs (DEX(), Analysis.add(),
create_xref(), as AnalyzeAPK and manual loads do, one DEX or two), compare
accept/reject and the exception (stage, type, repr(args), str()).

    python scripts/load_difffuzz.py SEEDDIR OUTDIR N [--start K] [--jobs J] [--deep] [--only I]

Needs androguard 4.1.3 + mutf8 1.1.0 and androguard_rs importable in the
same venv. SEEDDIR holds real *.dex files (not committed); mutations hit
map entries (type, size, offset, dropped entries), header fields, values
inside sections, code items (tries, insns_size, instructions, handlers),
random bytes, truncation/appending, insertions/deletions and offset fields;
the Adler-32 checksum is fixed 97% of the time. Case i is determined by i
and the seed list, so a run resumes with --start and a difference replays
with --only i (which also writes the DEX files). An androguard run that
doesn't finish in 10 s (read_null_terminated_string at the end of the
file loops forever) matches our MemoryError. --deep also compares, for
mutants both load, what the objects show (classes, methods, instruction
text, xrefs; oracle.view()). Differences go to OUTDIR/run_*.log.
"""
import argparse
import glob
import os
import random
import signal
import struct
import sys
import zlib
from multiprocessing import Pool

sys.path.insert(0, os.path.dirname(__file__))
import load_oracle as oracle  # noqa: E402

SEEDS = []
AG = RS = None

MAP_TYPES = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1000, 0x1001, 0x1002, 0x1003,
             0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0xF000]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def fix(b, rnd):
    """Recompute the Adler-32 checksum (most of the time)."""
    if len(b) >= 12 and rnd.random() < 0.97:
        struct.pack_into("<I", b, 8, zlib.adler32(bytes(b[12:])))
    return b


def map_entries(b):
    try:
        mo = u32(b, 52)
        n = u32(b, mo)
        return [(mo + 4 + 12 * i, struct.unpack_from("<HHII", b, mo + 4 + 12 * i)) for i in range(min(n, 64))]
    except struct.error:
        return []


def sections(b):
    """(type, start, end) of each map section, sorted by start."""
    ents = sorted((e[1][3], e[1][0]) for e in map_entries(b))
    out = []
    for k, (off, t) in enumerate(ents):
        end = ents[k + 1][0] if k + 1 < len(ents) else len(b)
        out.append((t, off, max(off, end)))
    return out


def code_items(b):
    """(offset, insns_size, tries_size) of the code items (walking the
    CODE_ITEM section as androguard does, valid files only)."""
    out = []
    for _, (t, _u, size, off) in map_entries(b):
        if t != 0x2001:
            continue
        p = off
        try:
            for _ in range(size):
                p = (p + 3) & ~3
                regs, ins, outs, tries, dbg, n = struct.unpack_from("<4H2I", b, p)
                out.append((p, n, tries))
                q = p + 16 + 2 * n
                if tries:
                    if n % 2:
                        q += 2
                    q += 8 * tries
                    # handlers: skip with a tolerant uleb walk
                    def uleb(q):
                        r = 0
                        for i in range(5):
                            c = b[q]
                            q += 1
                            r |= (c & 0x7f) << (7 * i)
                            if c < 0x80:
                                break
                        return r, q

                    def sleb(q):
                        r = 0
                        s = 0
                        while True:
                            c = b[q]
                            q += 1
                            r |= (c & 0x7f) << s
                            s += 7
                            if c < 0x80:
                                break
                        if c & 0x40:
                            r -= 1 << s
                        return r, q
                    cnt, q = uleb(q)
                    for _ in range(cnt):
                        sz, q = sleb(q)
                        for _ in range(abs(sz)):
                            _, q = uleb(q)
                            _, q = uleb(q)
                        if sz <= 0:
                            _, q = uleb(q)
                p = q
        except (struct.error, IndexError):
            pass
    return out


def rint(rnd, cur, bits):
    m = (1 << bits) - 1
    c = rnd.random()
    if c < 0.25:
        return (cur + rnd.randint(-4, 4)) & m
    if c < 0.4:
        return 0
    if c < 0.5:
        return m
    if c < 0.6:
        return (cur + rnd.choice([1, 2, 3, 4, 8, 12, 16, 32])) & m
    if c < 0.75:
        return rnd.randint(0, min(m, 1 << 20))
    return rnd.randint(0, m)


def mutate(seed: bytes, rnd: random.Random) -> bytearray:
    b = bytearray(seed)
    for _ in range(rnd.choice([1, 1, 1, 2, 2, 3])):
        try:
            mutate1(b, rnd)
        except (IndexError, struct.error, ValueError):
            pass
    return fix(b, rnd)


def mutate1(b, rnd):
    if True:
        op = rnd.random()
        ents = map_entries(b)
        secs = sections(b)
        if op < 0.22 and ents:
            # a map entry's type, size or offset
            pos, (t, unused, size, off) = rnd.choice(ents)
            f = rnd.random()
            if f < 0.2:
                t = rnd.choice(MAP_TYPES) if rnd.random() < 0.9 else rnd.randint(0, 0xFFFF)
            elif f < 0.6:
                size = rint(rnd, size, 32)
            else:
                off = rint(rnd, off, 32)
            if rnd.random() < 0.1:
                # drop the entry (move the last one here, shrink the count)
                mo = u32(b, 52)
                n = u32(b, mo)
                if n:
                    last = mo + 4 + 12 * (n - 1)
                    b[pos:pos + 12] = b[last:last + 12]
                    struct.pack_into("<I", b, mo, n - 1)
                return
            struct.pack_into("<HHII", b, pos, t, unused, size, off)
        elif op < 0.28 and len(b) >= 0x70:
            # header fields (id table sizes/offsets, map_off, sizes)
            o = rnd.choice(list(range(32, 0x70, 4)))
            struct.pack_into("<I", b, o, rint(rnd, u32(b, o), 32))
        elif op < 0.45 and secs:
            # a u16/u32/byte inside a section, aligned to the section's items
            t, s, e = rnd.choice(secs)
            if e <= s:
                return
            o = rnd.randrange(s, e)
            w = rnd.choice([1, 2, 4])
            o -= o % w
            if o + w > len(b):
                return
            cur = int.from_bytes(b[o:o + w], "little")
            b[o:o + w] = rint(rnd, cur, 8 * w).to_bytes(w, "little")
        elif op < 0.6:
            # a code item's header or try items
            cis = code_items(b)
            if not cis:
                return
            p, n, tries = rnd.choice(cis)
            f = rnd.random()
            if f < 0.3 and tries:
                q = p + 16 + 2 * n + (2 if n % 2 else 0) + 8 * rnd.randrange(tries)
                fld = rnd.choice([(0, 4), (4, 2), (6, 2)])
                cur = int.from_bytes(b[q + fld[0]:q + fld[0] + fld[1]], "little")
                b[q + fld[0]:q + fld[0] + fld[1]] = rint(rnd, cur, 8 * fld[1]).to_bytes(fld[1], "little")
            elif f < 0.5:
                struct.pack_into("<H", b, p + 6, rint(rnd, tries, 16))
            elif f < 0.7:
                struct.pack_into("<I", b, p + 12, rint(rnd, n, 32))
            elif f < 0.85 and n:
                # an instruction byte
                o = p + 16 + rnd.randrange(2 * n)
                b[o] = rnd.randrange(256)
            else:
                # bytes right after the insns (handlers)
                o = p + 16 + 2 * n + rnd.randrange(0, 24)
                if o < len(b):
                    b[o] = rnd.randrange(256)
        elif op < 0.72:
            # random bytes anywhere
            for _ in range(rnd.randint(1, 4)):
                o = rnd.randrange(0x70 if len(b) > 0x70 else 0, len(b))
                b[o] = rnd.randrange(256) if rnd.random() < 0.5 else b[o] ^ (1 << rnd.randrange(8))
        elif op < 0.8:
            # truncate, or append junk
            if rnd.random() < 0.7:
                del b[rnd.randrange(0x70, len(b)) if len(b) > 0x70 else len(b) - 1:]
            else:
                b += bytes(rnd.randrange(256) for _ in range(rnd.randint(1, 64)))
        elif op < 0.88:
            # insert or delete bytes in the data area
            o = rnd.randrange(0x70, len(b)) if len(b) > 0x70 else 0
            if rnd.random() < 0.5:
                del b[o:o + rnd.randint(1, 8)]
            else:
                b[o:o] = bytes(rnd.randrange(256) for _ in range(rnd.randint(1, 8)))
        elif secs:
            # point an offset field (class_def, proto, code_off...) somewhere else
            t, s, e = rnd.choice([x for x in secs if x[0] in (0x6, 0x3, 0x2000)] or secs)
            if e <= s + 4:
                return
            o = rnd.randrange(s, e - 4) & ~3
            struct.pack_into("<I", b, o, rnd.choice([0, 1, 2, 3, rnd.randrange(len(b) + 16), u32(b, o) + rnd.choice([-4, -1, 1, 4])]) & 0xFFFFFFFF)


class Timeout(BaseException):
    pass


def _alarm(signum, frame):
    raise Timeout()


def init(seeds, deep=False):
    global SEEDS, AG, RS, DEEP
    DEEP = deep
    SEEDS = seeds
    signal.signal(signal.SIGALRM, _alarm)
    AG = oracle.setup("ag")
    RS = oracle.setup("rs")


def mutant(i):
    rnd = random.Random(i * 7919 + 17)
    seed = SEEDS[rnd.randrange(len(SEEDS))]
    return bytes(mutate(open(seed, "rb").read(), rnd)), seed


def blobs_of(i):
    """The DEX files of case i: the mutant, alone or (1 in 6) loaded with
    another seed or mutant before or after it, as a multi-DEX APK."""
    b, seed = mutant(i)
    rnd = random.Random(i * 31 + 5)
    if rnd.random() < 1 / 6:
        other = open(SEEDS[rnd.randrange(len(SEEDS))], "rb").read()
        if rnd.random() < 0.3:
            other = bytes(mutate(other, rnd))
        return ([b, other] if rnd.random() < 0.5 else [other, b]), seed + "+"
    return [b], seed


DEEP = False


def one(i):
    blobs, seed = blobs_of(i)
    signal.alarm(10)
    try:
        a = oracle.run(*AG, blobs, DEEP)
    except Timeout:
        a = ("timeout",)
    finally:
        signal.alarm(0)
    signal.alarm(60)
    try:
        r = oracle.run(*RS, blobs, DEEP)
    except Timeout:
        r = ("rs-timeout",)
    finally:
        signal.alarm(0)
    same = a == r or (a == ("timeout",) and r[1:3] == ("MemoryError", "()"))
    if not same and a[0] == "ok" and r[0] == "ok":
        # where the views differ, briefly
        a, r = ("ok", "view differs"), ("ok", first_diff(a[1], r[1]))
    return i, os.path.basename(seed), a, r, same


def first_diff(x, y):
    if type(x) != type(y) or not isinstance(x, (list, tuple)):
        return (repr(x)[:300], repr(y)[:300])
    for k, (p, q) in enumerate(zip(x, y)):
        if p != q:
            return (k, first_diff(p, q))
    return ("len", len(x), len(y))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("seeddir")
    ap.add_argument("outdir")
    ap.add_argument("n", type=int)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--only", type=int, default=None)
    ap.add_argument("--deep", action="store_true")
    args = ap.parse_args()
    seeds = sorted(glob.glob(os.path.join(args.seeddir, "*.dex")))
    os.makedirs(args.outdir, exist_ok=True)
    if args.only is not None:
        init(seeds, args.deep)
        r = one(args.only)
        print(r)
        for k, b in enumerate(blobs_of(args.only)[0]):
            open(os.path.join(args.outdir, f"m{args.only}_{k}.dex"), "wb").write(b)
        return
    from collections import Counter
    outcomes = Counter()
    ndiff = 0
    log = open(os.path.join(args.outdir, f"run_{args.start}_{args.n}.log"), "w")
    with Pool(args.jobs, initializer=init, initargs=(seeds, args.deep)) as pool:
        for k, (i, seed, a, r, same) in enumerate(pool.imap_unordered(one, range(args.start, args.start + args.n), chunksize=64)):
            outcomes[a[:2] if a[0] != "ok" else ("ok",)] += 1
            if a[0] == "ok" and same:
                a = ("ok",)
            if not same:
                ndiff += 1
                print("DIFF", i, seed, a, r, file=log, flush=True)
                if ndiff <= 30:
                    print("DIFF", i, seed, a, r, flush=True)
            if (k + 1) % 5000 == 0:
                print(f"{k + 1} done, {ndiff} diffs", flush=True)
    print(f"total {args.n}, diffs {ndiff}")
    for k, v in outcomes.most_common():
        print(v, k)
    print(f"total {args.n}, diffs {ndiff}", file=log)
    for k, v in outcomes.most_common():
        print(v, k, file=log)


if __name__ == "__main__":
    main()
