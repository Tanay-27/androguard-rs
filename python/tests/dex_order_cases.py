"""Synthetic APKs for DEX selection and order, shared by test_dex_order.py
(standalone, goldens), test_dex_order_parity.py (live against androguard)
and scripts/gen_dex_order_goldens.py (which wrote dex_order_goldens.py from
androguard 4.1.3).

androguard's AnalyzeAPK loads `a.get_all_dex()`: `get_file(name)` for each
name of `get_files()` (apkInspector's namelist(): central directory order, a
repeated name at its first position) matching `^classes(\\d*).dex$` with
`re.match` (unescaped `.`, `$` also before a final newline, Unicode digits).
Every DEX here defines LA; and LI; (so a later one replaces them; LA;->foo's
const-string says which DEX won) and its own LB<k>;.
"""

import struct
import zlib

import apkbuild as b
import dexbuild


def variant(k: int) -> bytes:
    """dexbuild's base DEX with "hello" -> "hello<k>" and LB; -> LB<k>;
    (both keep the string table sorted)."""
    spec = dexbuild.base_spec()
    strings = list(spec["strings"])
    strings[strings.index(b"hello")] = b"hello%d" % k
    strings[strings.index(b"LB;")] = b"LB%d;" % k
    spec["strings"] = strings
    # No try/catch-all in baz: androguard's Analysis can't take that one
    # (determineException raises IndexError).
    spec["codes"]["c_baz"] = dexbuild.code_item(1, 1, 0, bytes.fromhex("0e00"))
    return dexbuild.build(spec)[0]


def _deflate(data: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def zip_raw(entries, comment=b""):
    """entries: dicts with
    name (bytes, central directory name), data, and optionally
    local_name (bytes, default name), store ("deflate" / "stored", how the
    payload is written; default deflate), cd_method / local_method (default
    8 for deflate, 0 for stored), cd_sizes / local_sizes ((compressed,
    uncompressed), default the true ones; None in either keeps that one), bad_local (local header signature
    broken), extra_cd (bool: list this entry's central directory record
    twice)."""
    out = bytearray()
    cd = bytearray()
    n = 0
    for e in entries:
        name = e["name"]
        local_name = e.get("local_name", name)
        data = e["data"]
        store = e.get("store", "deflate")
        payload = _deflate(data) if store == "deflate" else data
        method = 8 if store == "deflate" else 0
        cd_method = e.get("cd_method", method)
        local_method = e.get("local_method", method)
        true_sizes = (len(payload), len(data))
        lcs, lus = (t if v is None else v for v, t in zip(e.get("local_sizes", true_sizes), true_sizes))
        ccs, cus = (t if v is None else v for v, t in zip(e.get("cd_sizes", true_sizes), true_sizes))
        crc = zlib.crc32(data)
        off = len(out)
        sig = 0x04034B51 if e.get("bad_local") else 0x04034B50
        out += struct.pack("<IHHHHHIIIHH", sig, 20, 0, local_method, 0, 0x21, crc, lcs, lus, len(local_name), 0)
        out += local_name + payload
        rec = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, cd_method, 0, 0x21, crc, ccs, cus,
                          len(name), 0, 0, 0, 0, 0, off) + name
        for _ in range(2 if e.get("extra_cd") else 1):
            cd += rec
            n += 1
    cd_off = len(out)
    out += cd
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, n, n, len(cd), cd_off, len(comment))
    out += comment
    return bytes(out)


def _manifest():
    return {"name": b"AndroidManifest.xml", "data": b.manifest()}


def _dex(name, k, **kw):
    return dict(name=name.encode() if isinstance(name, str) else name, data=variant(k), **kw)


def _short(name):
    # androguard's DEX(): "Not a DEX file, Header too small."
    return {"name": name.encode(), "data": b"dex\n035\0" + b"\0" * 50, "store": "stored"}


def _bad_tag(name):
    # "This is not a DEX file! Wrong endian tag: '0xcafebabe'"
    return {"name": name.encode(), "data": b"dex\n035\0" + b"\0" * 32 + struct.pack("<I", 0xCAFEBABE) + b"\0" * 68,
            "store": "stored"}


def _junk_local(dex_k: int):
    """An entry whose *local* header claims the name classes2.dex, written
    after the real classes2.dex: apkInspector keys local headers by their
    own name, so classes2.dex is read with this header's fields (stored,
    same name length) at classes2.dex's own offset. classes2.dex's own
    header says deflate over stored bytes, so it only reads with this one."""
    n = len(variant(dex_k))
    return {"name": b"zz.bin", "local_name": b"classes2.dex", "data": b"junk", "store": "stored", "local_sizes": (n, n)}


CASES = {
    # Central directory order, not multidex number: classes10 before classes2
    # before classes.
    "cd_order": lambda: zip_raw([_manifest(), _dex("classes10.dex", 10), _dex("classes2.dex", 2),
                                 _dex("classes.dex", 1)]),
    # The loose regex: classesXdex, classes1.dex (alongside classes.dex),
    # classes3odex, a trailing newline, a Unicode digit; and names it
    # rejects: classes.dex.bak, sub/classes4.dex, Classes5.dex, classes-1.dex,
    # "classes6.dex\n\n", "classes7.dex\nx", classesdex.
    "loose_names": lambda: zip_raw([
        _manifest(), _dex("classesXdex", 11), _dex("classes.dex", 1), _dex("classes1.dex", 12),
        _dex("classes3odex", 13), _dex("classes2.dex\n", 14), _dex("classes٣.dex", 15),
        _dex("classes.dex.bak", 20), _dex("sub/classes4.dex", 21), _dex("Classes5.dex", 22),
        _dex("classes-1.dex", 23), _dex("classes6.dex\n\n", 24), _dex("classes7.dex\nx", 25),
        _dex("classesdex", 26)]),
    # Repeated names: first position, last entry's bytes; an invalid UTF-8
    # byte dropped from a name makes it a repeat too.
    "duplicates": lambda: zip_raw([
        _manifest(), _dex("classes2.dex", 2), _dex("classes.dex", 1), _dex("classes2.dex", 3),
        _dex(b"classes\xff3.dex", 4), _dex("classes3.dex", 5), _dex("classes4.dex", 6, extra_cd=True)]),
    # Local header vs central directory, as apkInspector resolves them: local
    # method wins (stored data, central directory says deflate); zero local
    # sizes fall back to the central directory's; deflate ignores a wrong
    # declared uncompressed size (smaller and larger) and wrong central
    # directory sizes when the local ones are set; a later entry's local header
    # named like an earlier entry replaces that entry's header.
    "local_vs_cd": lambda: zip_raw([
        _manifest(), _dex("classes.dex", 1, store="stored", cd_method=8),
        _dex("classes2.dex", 2, store="stored", local_method=8), _junk_local(2),
        _dex("classes3.dex", 3, local_sizes=(0, 0)),
        _dex("classes4.dex", 4, local_sizes=(None, 1), cd_sizes=(None, 1)),
        _dex("classes5.dex", 5, cd_sizes=(0xFFFFFFF0, 0xFFFFFFF0)),
        _dex("classes6.dex", 6, local_sizes=(None, 0xFFFFFFF0))]),
    # Duplicate classes and the earlier DEX's code: classes9 (listed last)
    # wins over classes.dex.
    "dup_last_wins": lambda: zip_raw([_manifest(), _dex("classes.dex", 1), _dex("classes9.dex", 9)]),
    # Failures: a DEX whose local header is missing or named differently
    # (FileNotPresent), one whose payload isn't a DEX.
    "missing_local": lambda: zip_raw([_manifest(), _dex("classes.dex", 1), _dex("classes2.dex", 2, bad_local=True)]),
    "renamed_local": lambda: zip_raw([_manifest(), _dex("classes.dex", 1),
                                      _dex("classes2.dex", 2, local_name=b"classes8.dex")]),
    # A tolerant load: skipped DEX in get_all_dex() order.
    "tolerant": lambda: zip_raw([_manifest(), _bad_tag("classes10.dex"), _dex("classes3.dex", 3), _short("classes2.dex"),
                                 _dex("classes.dex", 1), _short("classesZdex")]),
}

# Cases AnalyzeAPK loads (the others raise in androguard, and so must we).
NOT_DEX = {"tolerant"}


def outcome(f):
    try:
        return f()
    except Exception:
        return ("raises",)


def snapshot(a, d, dx):
    """What AnalyzeAPK's result says about which DEX loaded, in what order,
    and which duplicate won. Xref sets are sorted (androguard's order isn't
    defined). get_methods() is taken once per (name, descriptor), first
    occurrence: for a class defined in several DEX files androguard appends
    the earlier definitions' calling methods after the winner's own (see
    duplicate_extras() and dup_cases.py)."""
    classes = list(dx.get_classes())
    out = {"dex_names": list(a.get_dex_names()), "n_dex": len(d),
           "classes": [(c.name, c.is_external()) for c in classes]}
    methods = []
    xrefs = []
    fields = []
    for c in classes:
        seen = set()
        for m in c.get_methods():
            if c.is_external():
                xrefs.append((m.class_name, m.name, m.descriptor,
                              sorted((r.class_name, r.name, r.descriptor, off) for _, r, off in m.get_xref_from())))
                continue
            if (m.name, m.descriptor) in seen:
                continue
            seen.add((m.name, m.descriptor))
            em = m.get_method()
            methods.append((m.class_name, m.name, m.descriptor, em.get_access_flags_string(),
                            [(i.get_name(), i.get_output()) for i in em.get_instructions()]))
        if not c.is_external():
            fields.append((c.name, [(f.name, f.get_field().get_class_name()) for f in c.get_fields()]))
    out["methods"] = methods
    out["xref_from"] = xrefs
    out["fields"] = fields
    return out


def duplicate_extras(dx, name="LA;"):
    """get_methods() of a class defined in several DEX files, in full, with
    each method's get_xref_to() (sorted)."""
    return [(m.name, m.descriptor, sorted((r.class_name, r.name, off) for _, r, off in m.get_xref_to()))
            for m in dx.get_class_analysis(name).get_methods()]


def tolerant_load(raw, dex_cls, analysis_cls):
    """A manual DEX()/Analysis.add() load with androguard's APK that skips a
    DEX failing with one of the two header errors Apk(..., tolerant=True)
    skips: ([(dex name, message) skipped, in get_all_dex() order], classes)."""
    from androguard.core.apk import APK

    from strict_cases import _tolerated

    apk = APK(raw, raw=True)
    analysis = analysis_cls()
    skipped = []
    for name, data in zip(list(apk.get_dex_names()), list(apk.get_all_dex())):
        try:
            analysis.add(dex_cls(data))
        except Exception as exc:
            if not _tolerated(exc):
                raise
            skipped.append((name, str(exc)))
    analysis.create_xref()
    return skipped, [(c.name, c.is_external()) for c in analysis.get_classes()]
