"""The object-model queries (and search_instruction_text) on a crafted DEX whose class_defs all share one
large class_data_item: time and memory must stay bounded by the input.

androguard shows each of those classes with all of the shared methods, and
so do classes()/class_methods()/const_strings(), but what one class_data
renders to must be built once and shared, not once per class. Before that
was so, a 9.5 MB file of this shape took ~5 GB.
"""

import json
import os
import struct
import subprocess
import sys
import zipfile

import dexbuild as db

N_CLASSES = 4000
N_METHODS = 1500
N_FIELDS = 200

# Every query the model exposes, on every class and method, in a fresh
# process so ru_maxrss is this run's peak alone.
CHILD = r"""
import json, resource, sys, time
import androguard_rs
apk = androguard_rs.Apk(sys.argv[1])
t = time.perf_counter()
classes = apk.classes()
rows = 0
sigs = set()
fields = 0
for name, _ in classes:
    ms = apk.class_methods(name)
    rows += len(ms)
    fields += len(apk.class_fields(name))
    apk.class_entry(name)
    apk.class_hierarchy(name)
    if not sigs:
        sigs = {m[0] for m in ms}
hier = apk.hierarchy()
cs = apk.const_strings()
cs_rows = sum(len(m) for _, m in cs)
cs_j = apk.const_strings(include_jumbo=True)
xrefs = sum(len(apk.xref_from(s)) + len(apk.xref_to(s)) for s in sigs)
search = len(apk.search_instruction_text(["v0"]))
peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
peak = peak if sys.platform == "darwin" else peak * 1024
print(json.dumps({"secs": time.perf_counter() - t, "peak": peak, "classes": len(classes), "rows": rows,
                  "hier": len(hier), "cs_rows": cs_rows, "cs_j": len(cs_j), "xrefs": xrefs, "search": search,
                  "fields": fields, "count": apk.class_count()}))
"""


def shared_class_data_dex(same_name: bool = False, redefined: bool = False) -> bytes:
    """N_CLASSES class_defs sharing one class_data; with `same_name`, all
    of them define the same class (a class defined N_CLASSES times); with
    `redefined`, each class is defined again after all of them with an
    empty class_data, so every class lists the shared methods as an
    earlier definition's callers."""
    names = [f"Lc/C{i:05d};".encode() for i in range(1 if same_name else N_CLASSES)]
    mnames = [f"m{i:05d}".encode() for i in range(N_METHODS)]
    fnames = [f"f{i:05d}".encode() for i in range(N_FIELDS)]
    strings = sorted([b"<init>", b"I", b"Ljava/lang/Object;", b"V", b"hello"] + names + mnames + fnames)
    s = {v: i for i, v in enumerate(strings)}
    type_strs = sorted([b"I", b"Ljava/lang/Object;", b"V"] + names)
    types = [s[v] for v in type_strs]
    t = {v: i for i, v in enumerate(type_strs)}
    obj, owner = t[b"Ljava/lang/Object;"], t[names[0]]
    # Method ids sorted by (class, name): the shared methods on the first class,
    # then Object.<init>, which every method calls (an external method).
    methods = sorted([(owner, 0, s[m]) for m in mnames] + [(obj, 0, s[b"<init>"])])
    init = methods.index((obj, 0, s[b"<init>"]))
    # Instance fields of the first class, which the shared class_data declares.
    fields = [(owner, t[b"I"], s[f]) for f in fnames]
    # const-string v0, "hello" ; invoke-direct {v0}, Object.<init>()V ;
    # iget v0, v0, f00000 ; return-void
    code = db.code_item(1, 1, 1, struct.pack("<BBH", 0x1A, 0, s[b"hello"])
                        + struct.pack("<BBHH", 0x70, 0x10, init, 0) + struct.pack("<BBH", 0x52, 0, 0)
                        + bytes([0x0E, 0]))
    owned = [i for i, m in enumerate(methods) if m[0] == owner]
    spec = db.base_spec()
    spec.update({
        "strings": strings,
        "types": types,
        "protos": [(s[b"V"], t[b"V"], None)],
        "fields": fields,
        "methods": methods,
        "type_lists": {},
        "codes": {"c": code},
        "class_datas": {"cd": lambda L: db.class_data(instance=[(i, 0x1) for i in range(N_FIELDS)],
                                                      direct=[(i, 0x1, L["c"]) for i in owned]),
                        "empty": lambda L: db.class_data()},
        "encoded_arrays": {},
        "classes": [(t[names[0 if same_name else i]], 0x1, obj, None, "cd", None) for i in range(N_CLASSES)]
        + ([(t[n], 0x1, obj, None, "empty", None) for n in names] if redefined else []),
    })
    dex, _ = db.build(spec)
    return dex


def test_shared_class_data_is_bounded(tmp_path):
    apk = tmp_path / "shared.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("classes.dex", shared_class_data_dex())
    out = subprocess.run([sys.executable, "-c", CHILD, str(apk)], capture_output=True, text=True, timeout=300,
                         cwd=os.path.dirname(__file__))
    assert out.returncode == 0, out.stderr
    r = json.loads(out.stdout)
    # The answers still show every class with every shared method, as androguard does.
    assert r["classes"] == N_CLASSES + 1  # plus external Ljava/lang/Object;
    assert r["rows"] == N_CLASSES * N_METHODS + 1  # + Object.<init> on the external class
    assert r["hier"] == N_CLASSES
    assert r["cs_rows"] == N_CLASSES * N_METHODS and r["cs_j"] == N_CLASSES
    assert r["xrefs"] == N_METHODS  # one call each to Object.<init>
    assert r["search"] == N_CLASSES * N_METHODS
    # Every class lists the shared fields once (its code reads one of them,
    # the same EncodedField, so nothing is added).
    assert r["fields"] == N_CLASSES * N_FIELDS and r["count"] == r["classes"]
    # Rendered per class (the regression), this workload measured 3 GB and
    # 5 s; shared, it measures 0.05 s and about 100 MB peak RSS.
    assert r["secs"] < 10, r
    assert r["peak"] < 600 << 20, r


def test_one_class_defined_many_times_is_bounded(tmp_path):
    """N_CLASSES class_defs of one class, all with the same class_data (the
    same EncodedMethods): androguard keeps one class with each method once,
    and the per-definition handling reads that class_data once."""
    apk = tmp_path / "dup.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("classes.dex", shared_class_data_dex(same_name=True))
    out = subprocess.run([sys.executable, "-c", CHILD, str(apk)], capture_output=True, text=True, timeout=300,
                         cwd=os.path.dirname(__file__))
    assert out.returncode == 0, out.stderr
    r = json.loads(out.stdout)
    assert r["classes"] == 2 and r["count"] == 2
    assert r["rows"] == N_METHODS + 1 and r["hier"] == 1
    assert r["cs_rows"] == N_METHODS and r["cs_j"] == 1
    assert r["xrefs"] == N_METHODS and r["search"] == N_METHODS
    assert r["fields"] == N_FIELDS
    assert r["secs"] < 10, r
    assert r["peak"] < 600 << 20, r


def test_redefined_classes_listing_a_shared_class_data_are_bounded(tmp_path):
    """Every class defined twice, first over one shared class_data, then
    with an empty one: androguard lists all the shared methods (they call
    Object.<init>) in every class, after create_xref(). Kept as one run per
    class, expanded only when asked."""
    apk = tmp_path / "redefined.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("classes.dex", shared_class_data_dex(redefined=True))
    out = subprocess.run([sys.executable, "-c", CHILD, str(apk)], capture_output=True, text=True, timeout=300,
                         cwd=os.path.dirname(__file__))
    assert out.returncode == 0, out.stderr
    r = json.loads(out.stdout)
    assert r["classes"] == N_CLASSES + 1
    assert r["rows"] == N_CLASSES * N_METHODS + 1
    # const-string/search walk get_methods(): the appended methods too.
    assert r["cs_rows"] == N_CLASSES * N_METHODS and r["search"] == N_CLASSES * N_METHODS
    # Rendered per class this measured 2.2 GB and 14.5 s; shared, about
    # 80 MB and 0.3 s.
    assert r["secs"] < 10, r
    assert r["peak"] < 600 << 20, r
