"""Synthetic APKs with irregular classes (defined more than once, sharing
a class_data, listing another class's method_id or a method twice; see
core/src/irregular.rs for androguard's rules), shared by
test_dup_classes.py (standalone, goldens), test_dup_classes_parity.py (live
against androguard) and scripts/gen_dup_goldens.py (which wrote
dup_goldens.py once from androguard 4.1.3 + mutf8 1.1.0).

What androguard 4.1.3 does with a class defined more than once (in one DEX
or across DEX files), from analysis.py:
- Analysis.add() makes a new ClassAnalysis for every class_def, so the
  last definition loaded wins (at the first one's dict position), with its
  own methods and fields. Every definition's EncodedMethods get a
  MethodAnalysis in dx.methods, and the (class, name, descriptor) table
  that resolves calls keeps the last definition of each signature.
- create_xref() then runs over every class_def, earlier definitions too.
  Each invoke appends to the winning ClassAnalysis's get_methods() the
  calling method if it isn't there yet (add_method_xref_to: an earlier
  definition's caller, with its own code and get_xref_to()), and the
  resolved callee (add_method_xref_from: a signature only an earlier
  definition has). ExternalMethods are appended as before, all in one
  order: the order create_xref() meets them.
- Callers always resolve to the last definition of a signature, so an
  earlier definition's method that a later one overrides has no
  get_xref_from().
"""

import struct
import zlib

import dex_order_cases as D
import fixture_apk as F
from fixture_apk import RETURN_VOID, cls, const_string, iget, invoke, meth, new_instance, sget

C, X, Y = "Lp/C;", "Lp/X;", "Lp/Y;"
OBJ, EXT = "Ljava/lang/Object;", "Lext/Lib;"


def _code(*parts):
    return lambda c: b"".join(p(c) for p in parts) + RETURN_VOID


def call(op, owner, name, ret="V", params=()):
    return lambda c: invoke(op, c.m(owner, name, ret, params), *range(len(params) + (op != 0x71)))


def string(text):
    return lambda c: const_string(0, c.s(text))


def get_static(owner, name, ty="I"):
    return lambda c: sget(0x60, 0, c.f(owner, name, ty))


def get_inst(owner, name, ty="I"):
    return lambda c: iget(0x52, 0, 1, c.f(owner, name, ty))


def new(ty):
    return lambda c: new_instance(0, c.t(ty))


def m(name, *parts, flags=0x1, ret="V", params=()):
    return meth(name, ret=ret, params=params, flags=flags, code=_code(*parts) if parts else None,
                regs=4, ins=1 + len(params), outs=2)


def init(sup=OBJ):
    return m("<init>", call(0x70, sup, "<init>"), flags=0x10001)


def apk(*dexes):
    """A zip with a manifest and classes.dex, classes2.dex, ... in that order."""
    entries = [{"name": b"AndroidManifest.xml", "data": D.b.manifest()}]
    for i, d in enumerate(dexes):
        entries.append({"name": (b"classes%d.dex" % (i + 1)) if i else b"classes.dex", "data": F.dex(d)})
    return D.zip_raw(entries)


def _caller(*targets):
    """LX; whose `go` calls each (owner, name, ret, params) target."""
    return cls(X, direct=[init()], virtual=[m("go", *(call(0x6E, *t) for t in targets))])


# Earlier definition calls, the winner doesn't: the earlier `a` (calls X.go
# and an inherited method), `b` (no calls: not listed), `early` (only the
# earlier definition has it; X calls it, so it is appended as a callee).
def early_calls():
    c1 = cls(C, direct=[init()], virtual=[
        m("a", string("a-early"), call(0x6E, X, "go"), call(0x6E, C, "inherited")),
        m("b", string("b-early")),
        m("early", string("only-early"), call(0x6E, EXT, "ext1"))])
    c2 = cls(C, direct=[init()], virtual=[m("a", string("a-win")), m("b", string("b-win"))])
    return apk([c1, _caller((C, "early"), (C, "a"))], [c2])


# The winner calls, the earlier definition doesn't: nothing extra is
# listed, and the earlier definition's code is never shown.
def winner_calls():
    c1 = cls(C, direct=[init()], virtual=[m("a", string("a-early")), m("b", string("b-early"))])
    c2 = cls(C, direct=[init()], virtual=[
        m("a", string("a-win"), call(0x6E, X, "go"), call(0x6E, C, "inherited")),
        m("b", string("b-win"), call(0x71, EXT, "ext2"))])
    return apk([c1, _caller((C, "a"))], [c2])


# The same class twice in one DEX (two class_defs, two class_data, one
# set of method_ids), the first definition with calls.
def same_dex():
    c1 = cls(C, direct=[init()], virtual=[
        m("a", string("a-first"), call(0x6E, X, "go")),
        m("first_only", string("first-only"), call(0x6E, C, "a"))])
    c2 = cls(C, direct=[m("<init>", string("init-second"), call(0x70, OBJ, "<init>"), flags=0x10001)],
             virtual=[m("a", string("a-second"))])
    return apk([c1, _caller((C, "a"), (C, "first_only")), c2])


# Three definitions across three DEX files; the middle one is the only one
# defining `mid`, the first and last both call.
def three_dex():
    c1 = cls(C, direct=[init()], virtual=[
        m("a", string("a-1"), call(0x6E, C, "mid"), call(0x6E, C, "inh1")),
        m("one", string("one-1"), call(0x71, EXT, "ext1"))])
    c2 = cls(C, direct=[init()], virtual=[
        m("a", string("a-2"), call(0x6E, X, "go")),
        m("mid", string("mid-2"), call(0x6E, C, "a"), call(0x6E, C, "inh2"))])
    c3 = cls(C, direct=[init()], virtual=[m("a", string("a-3"), call(0x6E, C, "inh3"), call(0x6E, C, "mid"))])
    return apk([c1], [c2, _caller((C, "a"), (C, "one"))], [c3])


# External method references (inherited methods and an external class) in
# both definitions, interleaved with the earlier definition's callers.
def externals_both():
    c1 = cls(C, direct=[init()], virtual=[
        m("a", call(0x6E, C, "inh_a"), call(0x71, EXT, "e1"), call(0x6E, C, "shared_inh")),
        m("b", call(0x6E, C, "inh_b"), new(EXT)),
        m("c", string("c-early"))])
    c2 = cls(C, direct=[init()], virtual=[
        m("a", call(0x6E, C, "shared_inh"), call(0x6E, C, "inh_win")),
        m("c", call(0x6E, C, "inh_c"), call(0x71, EXT, "e2"))])
    return apk([c1], [c2, _caller((C, "inh_a"), (C, "c"))])


# get_fields(): each definition's own fields; the winner lists its own, then
# the fields both definitions' code reads or writes (the earlier definition's
# own field is a different EncodedField).
def fields():
    c1 = cls(C, static=[("s1", "I", 0x9, None)], instance=[("f", "I", 0x1)], direct=[init()], virtual=[
        m("a", get_static(C, "s1"), get_static(Y, "y"), get_inst(C, "f"), call(0x6E, X, "go")),
        m("b", get_static(Y, "y2"))])
    c2 = cls(C, static=[("s2", "I", 0x9, None)], instance=[("f", "I", 0x1)], direct=[init()], virtual=[
        m("a", get_inst(C, "f"), get_static(Y, "y"), get_static(C, "s2"))])
    y1 = cls(Y, static=[("y", "I", 0x9, None), ("y2", "I", 0x9, None)])
    y2 = cls(Y, static=[("y", "I", 0x9, None)])
    return apk([c1, y1, _caller((C, "a"))], [y2, c2])


# The winner declares `a` abstract (no code), the earlier definition has
# code that calls: calls to C.a resolve to the winner's, which has no code;
# the earlier one is listed with its own.
def abstract_winner():
    c1 = cls(C, direct=[init()], virtual=[m("a", string("a-early"), call(0x6E, X, "go"))])
    c2 = cls(C, flags=0x401, direct=[init()], virtual=[m("a", flags=0x401)])
    return apk([c1, _caller((C, "a"))], [c2])


# A signature only an earlier definition has, abstract there: a call to it
# lists that method, without code.
def abstract_early_target():
    c1 = cls(C, flags=0x401, direct=[init()], virtual=[m("early", flags=0x401), m("a", string("a-early"))])
    c2 = cls(C, direct=[init()], virtual=[m("a", string("a-win"))])
    return apk([c1, _caller((C, "early"))], [c2])


def _share_class_data(dex: bytes, src: int, dst: int) -> bytes:
    """class_def `dst` pointed at class_def `src`'s class_data (checksum fixed)."""
    buf = bytearray(dex)
    size, off = struct.unpack_from("<II", buf, 0x60)
    assert max(src, dst) < size
    data_off = struct.unpack_from("<I", buf, off + 32 * src + 24)[0]
    struct.pack_into("<I", buf, off + 32 * dst + 24, data_off)
    struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:])))
    return bytes(buf)


def _apk_raw(*dexes: bytes) -> bytes:
    entries = [{"name": b"AndroidManifest.xml", "data": D.b.manifest()}]
    for i, d in enumerate(dexes):
        entries.append({"name": (b"classes%d.dex" % (i + 1)) if i else b"classes.dex", "data": d})
    return D.zip_raw(entries)


# Two class_defs of LC; sharing one class_data (the same EncodedMethods) in
# the first DEX, the winner in the second: the shared methods are listed
# once, and their xrefs counted once.
def shared_data():
    c = cls(C, direct=[init()], virtual=[m("a", string("a-shared"), call(0x6E, X, "go"), call(0x6E, C, "inh"))])
    c_other = cls(C, direct=[init()], virtual=[m("a", string("a-unused"))])
    one = _share_class_data(F.dex([c, _caller((C, "a")), c_other]), 0, 2)
    two = F.dex([cls(C, direct=[init()], virtual=[m("a", string("a-win"))])])
    return _apk_raw(one, two)


# The winner shares the earlier definition's class_data (same DEX): nothing
# extra at all.
def shared_with_winner():
    c = cls(C, direct=[init()], virtual=[m("a", string("a-shared"), call(0x6E, X, "go"))])
    c_other = cls(C, direct=[init()], virtual=[m("a", string("a-unused"), call(0x6E, X, "go"))])
    return _apk_raw(_share_class_data(F.dex([c, _caller((C, "a")), c_other]), 0, 2))


P, Q, B = "Lp/P;", "Lp/Q;", "Lp/B;"


# A class_data shared by an earlier definition of LC; and a differently
# named class LP; (whose class_def points at it, so its methods' method_ids
# name LC;): androguard's add() gives each class_def its own MethodAnalysis
# objects, dx.methods keeps the last one per EncodedMethod, and the
# (class, name, descriptor) table is keyed by the class_def's name.
def shared_dup_other():
    s = cls(C, direct=[init()], virtual=[m("a", string("a-S"), call(0x6E, X, "go")), m("b", string("b-S"))])
    p_stub = cls(P, virtual=[m("unused", string("p-own"))])
    x = cls(X, direct=[init()], virtual=[m("go", call(0x6E, C, "a"), call(0x6E, P, "a"), call(0x6E, C, "b"),
                                          call(0x6E, P, "b"))])
    one = _share_class_data(F.dex([s, p_stub, x]), 0, 1)
    two = F.dex([cls(C, direct=[init()], virtual=[m("a", string("a-win"))])])
    return _apk_raw(one, two)


# The same method listed twice in one class_data (two EncodedMethods for one
# method_id): both listed, each with its own code; calls resolve to the
# second.
def repeated_method():
    c = cls(C, direct=[init()], virtual=[m("a", string("a-first"), call(0x6E, X, "go")),
                                         m("a", string("a-second"), call(0x6E, C, "inh"))])
    return apk([c, _caller((C, "a"))])


# Two differently named classes sharing one class_data: each lists the
# shared methods, and a callee's get_xref_from() has one entry per class.
def shared_names():
    s = cls(P, direct=[init()], virtual=[m("a", string("a-S"), call(0x6E, X, "go")), m("b", string("b-S"))])
    q = cls(Q, virtual=[m("unused")])
    x = cls(X, direct=[init()], virtual=[m("go", call(0x6E, P, "a"), call(0x6E, Q, "a"), call(0x6E, Q, "b"))])
    return _apk_raw(_share_class_data(F.dex([s, q, x]), 0, 1))


# A class_data listing another class's method_id: LB;'s `Lp/X;->m` is
# filed under LB; (calls to LB;->m resolve to it, calls to LX;->m don't).
def mismatch():
    b = cls(B, direct=[init()], virtual=[m("Lp/X;->m", string("m-in-B"), call(0x6E, Y, "y"))])
    x = cls(X, direct=[init()], virtual=[m("go", call(0x6E, B, "m"), call(0x6E, X, "m"), call(0x6E, X, "go"))])
    y = cls(Y, direct=[init()], virtual=[m("y", string("y"))])
    return apk([b, x, y])


# An earlier definition of LC; reusing LP;'s class_data (already visited
# under LP;): its calling methods are listed in LC; at that class_def, but
# `b`, which a call from LP;'s code already put there (LC;'s winner has no
# `b`), isn't listed twice.
def run_case():
    s = cls(P, direct=[init()], virtual=[m("a", string("a-S"), call(0x6E, X, "go"), call(0x6E, C, "b")),
                                         m("b", string("b-S"), call(0x6E, X, "go")),
                                         m("c", string("c-S"))])
    c_stub = cls(C, virtual=[m("unused")])
    x = cls(X, direct=[init()], virtual=[m("go", call(0x6E, C, "a"), call(0x6E, P, "c"))])
    one = _share_class_data(F.dex([s, x, c_stub]), 0, 2)
    two = F.dex([cls(C, direct=[init()], virtual=[m("a", string("a-win"))])])
    return _apk_raw(one, two)


# Three names over one class_data (LP; twice, LQ;, LR;), one of them also
# listing a method twice.
def shared_three():
    r = "Lp/R;"
    s = cls(P, direct=[init()], virtual=[m("a", string("a-1"), call(0x6E, X, "go")),
                                         m("a", string("a-2"), call(0x6E, Y, "y")), m("b", string("b"))])
    q = cls(Q, virtual=[m("unused")])
    rr = cls(r, virtual=[m("unused")])
    p2 = cls(P, virtual=[m("unused2", string("p2"), call(0x6E, P, "a"))])
    x = cls(X, direct=[init()], virtual=[m("go", call(0x6E, P, "a"), call(0x6E, Q, "a"), call(0x6E, r, "b"),
                                          call(0x6E, r, "zz"))])
    y = cls(Y, virtual=[m("y", call(0x71, EXT, "e"))])
    one = F.dex([s, q, rr, x, y])
    one = _share_class_data(_share_class_data(one, 0, 1), 0, 2)
    return _apk_raw(one, F.dex([p2]))


CASES = {
    "early_calls": early_calls,
    "winner_calls": winner_calls,
    "same_dex": same_dex,
    "three_dex": three_dex,
    "externals_both": externals_both,
    "fields": fields,
    "abstract_winner": abstract_winner,
    "abstract_early_target": abstract_early_target,
    "shared_data": shared_data,
    "shared_with_winner": shared_with_winner,
    "shared_dup_other": shared_dup_other,
    "repeated_method": repeated_method,
    "shared_names": shared_names,
    "mismatch": mismatch,
    "run_case": run_case,
    "shared_three": shared_three,
}

# Needle sets for the instruction-text search (search_instruction_text),
# strings for methods_using_string, and find_methods()
# patterns.
NEEDLES = [["a-early"], ["lp/x;->go"], ["lp/c;->"], ["early", "win"], ["-1", "-2", "-3"], ["lext/lib;"]]
STRINGS = ["a-", "early", "win", "only", "shared", "mid"]
FIND = [(".*", ".*", ".*", ".*", False), ("Lp/C;", "a", ".*", ".*", False), ("Lp/C;", ".*", ".*", "public", False),
        ("Lp/", "inh.*", ".*", ".*", False), ("Lp/C;", ".*", ".*", ".*", True), ("L", "<init>", r"\(\)V", ".*", True)]


def _code_text(em):
    try:
        if em.get_code() is None:
            return None
        return [(off, i.get_name(), i.get_output()) for off, i in em.get_instructions_idx()]
    except AttributeError:
        return "external"


def _insn_objects(em):
    """The instruction objects of get_code().get_bc().get_instructions()
    (androguard_rs.dex's for the facade, fetched by the method's key, so each
    definition shows its own code)."""
    code = em.get_code() if hasattr(em, "get_code") else None
    if code is None:
        return None
    return [(i.get_op_value(), i.get_length(), bytes(i.get_raw()).hex(), i.get_name(), i.get_output())
            for i in code.get_bc().get_instructions()]


def _xrefs(rows):
    # The endpoint's own code tells which definition it is.
    return sorted((r.class_name, r.name, r.descriptor, off, repr(_code_text(r.get_method()))) for _, r, off in rows)


def sig(ma) -> str:
    return f"{ma.class_name}->{ma.name}{ma.descriptor.replace(' ', '')}"


def snapshot(dx):
    """Everything a duplicate changes, for every class (external ones too):
    get_methods() in order with flags, code and both xref lists (sorted, as
    androguard's are sets), get_fields(), and find_methods()."""
    out = {"classes": [(c.name, c.is_external()) for c in dx.get_classes()]}
    methods, fields = {}, {}
    for c in dx.get_classes():
        rows = []
        for ma in c.get_methods():
            em = ma.get_method()
            rows.append((ma.name, ma.descriptor, em.get_access_flags_string(), ma.is_external(), _code_text(em),
                         _xrefs(ma.get_xref_to()), _xrefs(ma.get_xref_from())))
        methods[c.name] = rows
        if not c.is_external():
            fields[c.name] = [(f.name, f.get_field().get_class_name(), f.get_field().get_descriptor())
                              for f in c.get_fields()]
    out["methods"] = methods
    out["insns"] = {c.name: [_insn_objects(ma.get_method()) for ma in c.get_methods()]
                    for c in dx.get_classes() if not c.is_external()}
    out["fields"] = fields
    out["find_methods"] = [[(ma.class_name, ma.name, ma.descriptor, repr(_code_text(ma.get_method())))
                            for ma in dx.find_methods(*f)] for f in FIND]
    return out


def ag_views(dx):
    """What the native whole-APK queries must answer, derived from an
    androguard-shaped dx: the const-string
    index and instruction-text blob (get_classes() -> get_methods() ->
    instructions, duplicates included), callers()/callees() (every
    definition of a signature), methods_using_string() (StringAnalysis)."""
    out = {"snapshot": snapshot(dx)}
    cs = []
    for ca in dx.get_classes():
        if ca.is_external():
            continue
        rows = []
        for ma in ca.get_methods():
            code = _code_text(ma.get_method())
            if not isinstance(code, list):
                continue
            outs = [o for _, n, o in code if n == "const-string"]
            if outs:
                rows.append((ma.name, ma.descriptor, outs))
        if rows:
            cs.append((ca.name, rows))
    out["const_strings"] = cs
    search = []
    for needles in NEEDLES:
        hits = []
        for ca in dx.get_classes():
            if ca.is_external():
                continue
            for ma in ca.get_methods():
                code = _code_text(ma.get_method())
                if isinstance(code, list) and any(n in o.lower() for _, _, o in code if o for n in needles):
                    hits.append((sig(ma), code))
        search.append(hits)
    out["search"] = search
    callers, callees = {}, {}
    for ma in dx.get_methods():
        callees.setdefault(sig(ma), set()).update((sig(m), off) for _, m, off in ma.get_xref_to())
        callers.setdefault(sig(ma), set()).update((sig(m), off) for _, m, off in ma.get_xref_from())
    out["callers"] = {k: sorted(v) for k, v in sorted(callers.items()) if v}
    out["callees"] = {k: sorted(v) for k, v in sorted(callees.items()) if v}
    out["strings"] = {n: sorted({sig(m) for s in dx.get_strings() if n in s.get_value() for _, m in s.get_xref_from()})
                      for n in STRINGS}
    return out


def rs_views(apk, dx):
    """ag_views()'s answers from androguard_rs.Apk `apk` and the facade `dx` over it."""
    out = {"snapshot": snapshot(dx)}
    out["const_strings"] = [(c, [(n, d, list(o)) for n, d, o in rows]) for c, rows in apk.const_strings()]

    def code(key):
        rows = apk.bytecode(key)
        return None if rows is None else [tuple(r) for r in rows]

    out["search"] = [[(s, code(s if k is None else (c, k[0]) if isinstance(k, tuple) else k))
                      for s, k, c in apk.search_instruction_text(n, keys=True)] for n in NEEDLES]
    sigs = sorted({r[0] for c, _ in apk.classes() for r in apk.class_methods(c)})
    out["callers"] = {s: v for s in sigs if (v := sorted(set(apk.callers(s))))}
    out["callees"] = {s: v for s in sigs if (v := sorted(set(apk.callees(s))))}
    out["strings"] = {n: sorted(apk.methods_using_string(n)) for n in STRINGS}
    return out
