"""A small two-DEX APK exercising the whole-APK index and facade APIs, for the
standalone tests (no androguard, no PARITY_APKS).

Classes are described symbolically; `dex(classes)` collects every string,
type, proto, field and method they mention, sorts the id tables as a real
DEX does, and lays the file out with dexbuild. Method code is a function of
an index context (`ctx.s()`, `.t()`, `.f()`, `.m()`), called once to collect
references and once to emit.

What's in it (see test_standalone.py / test_compat.py for what each piece
checks):
- classes.dex: com/ex/R$string (static int fields, as aapt emits them),
  com/ex/Values (one static field per encoded_value type), com/ex/Base,
  com/ex/Main extends Base implements Runnable (const-int resource ids,
  field reads/writes of its own, R's, Base's and an inherited field, calls
  to internal and external methods, new-instance/const-class of external
  classes, const-string and const-string/jumbo), com/ex/Dup (defined again
  in classes2.dex), and optionally com/ex/Bad (bytecode androguard rejects).
- classes2.dex: com/ex/Second (calls into classes.dex, reads a field
  defined in classes.dex and one defined here), com/ex/Dup again (its code
  touches a different field than the first definition's).
- resources.arsc from arscbuild ("utf8" synthetic table, package com.example).
"""

import io
import struct
import zipfile

import arscbuild
import dexbuild as db


class _Collect:
    def __init__(self):
        self.strings, self.types, self.fields, self.methods = set(), set(), set(), set()

    def s(self, v):
        self.strings.add(v)
        return 0

    def t(self, v):
        self.types.add(v)
        return 0

    def f(self, cls, name, ty):
        self.fields.add((cls, name, ty))
        return 0

    def m(self, cls, name, ret, params=()):
        self.methods.add((cls, name, ret, tuple(params)))
        return 0


class _Index:
    def __init__(self, strings, types, fields, methods):
        self._s, self._t, self._f, self._m = strings, types, fields, methods

    def s(self, v):
        return self._s[v]

    def t(self, v):
        return self._t[v]

    def f(self, cls, name, ty):
        return self._f[(cls, name, ty)]

    def m(self, cls, name, ret, params=()):
        return self._m[(cls, name, ret, tuple(params))]


# ── instruction encoders ─────────────────────────────────────────────────────


def const4(a, v):
    return bytes([0x12, ((v & 0xF) << 4) | a])


def const(a, v):
    return struct.pack("<BBI", 0x14, a, v & 0xFFFFFFFF)


def const_high16(a, v):
    return struct.pack("<BBH", 0x15, a, v >> 16)


def const_string(a, idx):
    return struct.pack("<BBH", 0x1A, a, idx)


def const_string_jumbo(a, idx):
    return struct.pack("<BBI", 0x1B, a, idx)


def const_class(a, idx):
    return struct.pack("<BBH", 0x1C, a, idx)


def new_instance(a, idx):
    return struct.pack("<BBH", 0x22, a, idx)


def sget(op, a, idx):  # 0x60 sget, 0x62 sget-object, 0x67 sput
    return struct.pack("<BBH", op, a, idx)


def iget(op, a, b, idx):  # 0x52 iget, 0x59 iput
    return struct.pack("<BBH", op, (b << 4) | a, idx)


def invoke(op, idx, *regs):  # 0x6e virtual, 0x70 direct, 0x71 static
    r = list(regs) + [0] * (5 - len(regs))
    return struct.pack("<BBHBB", op, (len(regs) << 4) | r[4], idx, r[0] | r[1] << 4, r[2] | r[3] << 4)


RETURN_VOID = bytes([0x0E, 0])


# ── encoded values ───────────────────────────────────────────────────────────


def _uint(ty, v, size=None):
    n = size or max(1, (v.bit_length() + 7) // 8)
    return bytes([((n - 1) << 5) | ty]) + v.to_bytes(n, "little")


def ev_byte(v):
    return bytes([0x00, v & 0xFF])


def ev_short(v):
    return _uint(0x02, v & 0xFFFF)


def ev_char(v):
    return _uint(0x03, v)


def ev_int(v):
    return _uint(0x04, v & 0xFFFFFFFF)


def ev_long(v):
    return _uint(0x06, v & 0xFFFFFFFFFFFFFFFF)


def ev_float(bits):
    return _uint(0x10, bits, 4)


def ev_double(bits):
    return _uint(0x11, bits, 8)


def ev_null():
    return bytes([0x1E])


def ev_bool(v):
    return bytes([0x1F | (0x20 if v else 0)])


def ev_idx(ty):
    return lambda idx: _uint(ty, idx)


ev_string, ev_type, ev_field, ev_method, ev_enum = (ev_idx(t) for t in (0x17, 0x18, 0x19, 0x1A, 0x1B))


def ev_array(*items):
    return bytes([0x1C]) + db.uleb(len(items)) + b"".join(items)


def ev_annotation(type_idx, *elements):
    return bytes([0x1D]) + db.uleb(type_idx) + db.uleb(len(elements)) + b"".join(
        db.uleb(n) + v for n, v in elements)


# ── class spec ───────────────────────────────────────────────────────────────


def cls(name, sup="Ljava/lang/Object;", flags=0x1, ifaces=(), static=(), instance=(), direct=(), virtual=()):
    """static: (name, type, flags, value_fn or None); instance: (name, type,
    flags); methods: (name, ret, params, flags, code_fn or None, registers,
    ins, outs)."""
    return dict(name=name, sup=sup, flags=flags, ifaces=tuple(ifaces), static=list(static),
                instance=list(instance), direct=list(direct), virtual=list(virtual))


def meth(name, ret="V", params=(), flags=0x1, code=None, regs=4, ins=1, outs=2):
    return (name, ret, tuple(params), flags, code, regs, ins, outs)


def _owner(c, m):
    """(class, name) of a method entry: its class, unless the name is given
    as "Lowner;->name" (a method_id of another class, as crafted files do)."""
    if "->" in m[0]:
        owner, name = m[0].split("->", 1)
        return owner, name
    return c["name"], m[0]


def _walk(classes, ctx):
    for c in classes:
        ctx.t(c["name"])
        ctx.t(c["sup"])
        for i in c["ifaces"]:
            ctx.t(i)
        for n, ty, *_ in c["static"] + c["instance"]:
            ctx.f(c["name"], n, ty)
        for m in c["direct"] + c["virtual"]:
            ctx.m(*_owner(c, m), m[1], m[2])
            if m[4]:
                m[4](ctx)
        for f in c["static"]:
            if f[3]:
                f[3](ctx)


def dex(classes) -> bytes:
    col = _Collect()
    _walk(classes, col)
    for cl, n, ty in col.fields:
        col.t(cl), col.t(ty), col.s(n)
    for cl, n, ret, params in col.methods:
        col.t(cl), col.t(ret), col.s(n), [col.t(p) for p in params]
    shorty = lambda ret, params: "".join("L" if x[0] in "L[" else x for x in (ret,) + params)  # noqa: E731
    protos_set = {(ret, params) for _, _, ret, params in col.methods}
    for ret, params in protos_set:
        col.s(shorty(ret, params))
    for t in col.types:
        col.s(t)
    strings = sorted(s.encode() for s in col.strings)
    s_idx = {v.decode(): i for i, v in enumerate(strings)}
    types = sorted(col.types, key=lambda t: s_idx[t])
    t_idx = {v: i for i, v in enumerate(types)}
    protos = sorted(protos_set, key=lambda p: (t_idx[p[0]], [t_idx[x] for x in p[1]]))
    p_idx = {v: i for i, v in enumerate(protos)}
    fields = sorted(col.fields, key=lambda f: (t_idx[f[0]], s_idx[f[1]], t_idx[f[2]]))
    f_idx = {v: i for i, v in enumerate(fields)}
    methods = sorted(col.methods, key=lambda m: (t_idx[m[0]], s_idx[m[1]], p_idx[(m[2], m[3])]))
    m_idx = {v: i for i, v in enumerate(methods)}
    ctx = _Index(s_idx, t_idx, {k: v for k, v in f_idx.items()},
                 {(c, n, r, p): i for (c, n, r, p), i in m_idx.items()})

    type_lists = {}
    for i, (ret, params) in enumerate(protos):
        if params:
            type_lists[f"p{i}"] = [t_idx[x] for x in params]
    codes, class_datas, arrays, class_rows = {}, {}, {}, []
    for ci, c in enumerate(classes):
        if c["ifaces"]:
            type_lists[f"i{ci}"] = [t_idx[x] for x in c["ifaces"]]
        meths = {}
        for kind in ("direct", "virtual"):
            for k, m in enumerate(c[kind]):
                mi = m_idx[(*_owner(c, m), m[1], m[2])]
                if m[4]:
                    label = f"c{ci}_{mi}" if k == 0 or c[kind][k - 1][0] != m[0] else f"c{ci}_{mi}_{k}"
                    codes[label] = db.code_item(m[5], m[6], m[7], m[4](ctx))
                    meths.setdefault(kind, []).append((mi, m[3], label))
                else:
                    meths.setdefault(kind, []).append((mi, m[3], None))
        static = sorted((f_idx[(c["name"], f[0], f[1])], f[2]) for f in c["static"])
        instance = sorted((f_idx[(c["name"], f[0], f[1])], f[2]) for f in c["instance"])

        def cd(L, meths=meths, static=static, instance=instance):
            res = lambda lst: sorted((i, fl, L[lb] if lb else 0) for i, fl, lb in lst)  # noqa: E731
            return db.class_data(static=static, instance=instance, direct=res(meths.get("direct", [])),
                                 virtual=res(meths.get("virtual", [])))

        has_data = c["static"] or c["instance"] or c["direct"] or c["virtual"]
        if has_data:
            class_datas[f"cd{ci}"] = cd
        # static values follow the field order of the class_data (by field idx)
        values = [v for _, v in sorted((f_idx[(c["name"], f[0], f[1])], f[3]) for f in c["static"])]
        while values and values[-1] is None:
            values.pop()
        if values:
            arrays[f"ea{ci}"] = db.uleb(len(values)) + b"".join(v(ctx) if v else ev_int(0) for v in values)
        class_rows.append((t_idx[c["name"]], c["flags"], t_idx[c["sup"]], f"i{ci}" if c["ifaces"] else None,
                           f"cd{ci}" if has_data else None, f"ea{ci}" if values else None))
    spec = db.base_spec()
    spec.update({
        "strings": strings,
        "types": [s_idx[t] for t in types],
        "protos": [(s_idx[shorty(r, p)], t_idx[r], f"p{i}" if p else None) for i, (r, p) in enumerate(protos)],
        "fields": [(t_idx[c], t_idx[ty], s_idx[n]) for c, n, ty in fields],
        "methods": [(t_idx[c], p_idx[(r, p)], s_idx[n]) for c, n, r, p in methods],
        "type_lists": type_lists,
        "codes": codes,
        "class_datas": class_datas,
        "encoded_arrays": arrays,
        "classes": class_rows,
    })
    out, _ = db.build(spec)
    return out


# ── the fixture ──────────────────────────────────────────────────────────────

MAIN, BASE, R_STRING, VALUES = "Lcom/ex/Main;", "Lcom/ex/Base;", "Lcom/ex/R$string;", "Lcom/ex/Values;"
SECOND, DUP, BAD = "Lcom/ex/Second;", "Lcom/ex/Dup;", "Lcom/ex/Bad;"
OBJ, STR, RUNNABLE = "Ljava/lang/Object;", "Ljava/lang/String;", "Ljava/lang/Runnable;"
APP_NAME_ID = 0x7F0B0001
TITLE_ID = 0x7F0B0002
HIGH_ID = 0x7F0C0000  # loaded with const/high16


def _main_run(c):
    return (const(0, APP_NAME_ID)
            + const_high16(1, HIGH_ID)
            + const4(2, -1)
            + sget(0x60, 0, c.f(R_STRING, "title", "I"))          # foreign: R$string.title
            + sget(0x62, 0, c.f(VALUES, "s", STR))                 # foreign: Values.s
            + iget(0x52, 0, 3, c.f(MAIN, "count", "I"))            # own field
            + iget(0x59, 0, 3, c.f(BASE, "baseField", "I"))        # foreign: Base.baseField (write)
            + iget(0x52, 0, 3, c.f(MAIN, "baseField", "I"))        # inherited via Main: no such field -> skipped
            + sget(0x60, 0, c.f(R_STRING, "title", "I"))          # again: listed once
            + const_string(1, c.s("https://example.com/api"))
            + const_string_jumbo(1, c.s("Bearer token"))
            + new_instance(1, c.t("Ljava/lang/StringBuilder;"))
            + const_class(1, c.t("Lcom/ext/Thing;"))
            + invoke(0x70, c.m("Ljava/lang/StringBuilder;", "<init>", "V"), 1)
            + invoke(0x6E, c.m(MAIN, "helper", "V", ("I",)), 3, 0)
            + invoke(0x6E, c.m(MAIN, "baseMethod", "V"), 3)      # inherited: ExternalMethod on Main
            + invoke(0x71, c.m("Lcom/ext/Lib;", "call", STR, (STR,)), 1)
            + RETURN_VOID)


def _main_helper(c):
    return (const(0, TITLE_ID)
            + invoke(0x6E, c.m(BASE, "baseMethod", "V"), 3)
            + RETURN_VOID)


def _init(owner_super):
    return lambda c: invoke(0x70, c.m(owner_super, "<init>", "V"), 0) + RETURN_VOID


def _second_go(c):
    return (invoke(0x71, c.m(MAIN, "helper", "V", ("I",)), 0, 1)
            + sget(0x60, 0, c.f(R_STRING, "title", "I"))         # defined in classes.dex: not listed
            + sget(0x60, 0, c.f(SECOND, "local", "I"))            # own
            + sget(0x60, 0, c.f(DUP, "two", "I"))                 # foreign, same DEX
            + RETURN_VOID)


def classes1():
    return [
        cls(R_STRING, flags=0x11, static=[("app_name", "I", 0x19, lambda c: ev_int(APP_NAME_ID)),
                                          ("title", "I", 0x19, lambda c: ev_int(TITLE_ID)),
                                          ("z_no_value", "I", 0x19, None)]),
        cls(VALUES, static=[
            ("a_byte", "B", 0x19, lambda c: ev_byte(0xFE)),
            ("b_short", "S", 0x19, lambda c: ev_short(-2)),
            ("c_char", "C", 0x19, lambda c: ev_char(0x41)),
            ("d_int", "I", 0x19, lambda c: ev_int(-1)),
            ("e_long", "J", 0x19, lambda c: ev_long(0x123456789)),
            ("f_float", "F", 0x19, lambda c: ev_float(0x3FC00000)),
            ("g_double", "D", 0x19, lambda c: ev_double(0x3FF8000000000000)),
            ("h_string", STR, 0x19, lambda c: ev_string(c.s("it's \"q\"\né"))),
            ("i_type", "Ljava/lang/Class;", 0x19, lambda c: ev_type(c.t("Lcom/ext/Thing;"))),
            ("j_field", "Ljava/lang/Object;", 0x19, lambda c: ev_field(c.f(R_STRING, "title", "I"))),
            ("k_method", "Ljava/lang/Object;", 0x19, lambda c: ev_method(c.m(MAIN, "helper", "V", ("I",)))),
            ("l_enum", "Ljava/lang/Object;", 0x19, lambda c: ev_enum(c.f(R_STRING, "app_name", "I"))),
            ("m_array", "[I", 0x19, lambda c: ev_array(ev_int(1), ev_int(2))),
            ("n_annotation", "Ljava/lang/Object;", 0x19,
             lambda c: ev_annotation(c.t("Lcom/ext/Thing;"), (c.s("value"), ev_int(3)))),
            ("o_null", "Ljava/lang/Object;", 0x19, lambda c: ev_null()),
            ("p_true", "Z", 0x19, lambda c: ev_bool(True)),
            ("q_false", "Z", 0x19, lambda c: ev_bool(False)),
            ("s", STR, 0x9, None),
        ]),
        cls(BASE, flags=0x401, instance=[("baseField", "I", 0x4)],
            direct=[meth("<init>", flags=0x10001, code=_init(OBJ), regs=1, ins=1, outs=1)],
            virtual=[meth("baseMethod", flags=0x1, code=lambda c: RETURN_VOID, regs=1, ins=1, outs=0)]),
        cls(MAIN, sup=BASE, ifaces=[RUNNABLE], instance=[("count", "I", 0x2)],
            static=[("TAG", STR, 0x1A, lambda c: ev_string(c.s("Main")))],
            direct=[meth("<init>", flags=0x10001, code=_init(BASE), regs=1, ins=1, outs=1)],
            virtual=[meth("abstractish", flags=0x401),
                     meth("helper", params=("I",), flags=0x1, code=_main_helper, regs=4, ins=2, outs=1),
                     meth("run", flags=0x1, code=_main_run, regs=4, ins=1, outs=2)]),
        cls(DUP, static=[("one", "I", 0x9, lambda c: ev_int(1))],
            direct=[meth("touch", flags=0x9, code=lambda c: sget(0x60, 0, c.f(DUP, "one", "I"))
                         + sget(0x60, 0, c.f(R_STRING, "app_name", "I")) + RETURN_VOID, regs=1, ins=0, outs=0)]),
    ]


def bad_class():
    """A method androguard can't disassemble. In androguard 4.1.3 it makes
    AnalyzeAPK fail outright, so goldens come from the APK without it."""
    return cls(BAD, direct=[meth("broken", flags=0x9, code=lambda c: bytes([0x3E, 0x00]) + RETURN_VOID,
                                 regs=1, ins=0, outs=0)])


def classes2():
    return [
        cls(SECOND, static=[("local", "I", 0x9, None)],
            direct=[meth("go", flags=0x9, code=_second_go, regs=2, ins=0, outs=2)]),
        cls(DUP, static=[("two", "I", 0x9, lambda c: ev_int(2))],
            direct=[meth("touch", flags=0x9, code=lambda c: sget(0x60, 0, c.f(DUP, "two", "I"))
                         + sget(0x60, 0, c.f(SECOND, "local", "I")) + RETURN_VOID, regs=1, ins=0, outs=0)]),
    ]


def arsc() -> bytes:
    return arscbuild.synthetic_tables()["utf8"]


def build_apk(path, with_arsc=True, with_bad=False) -> str:
    """Write the fixture APK to `path`; returns it as a str. `with_bad` adds
    com/ex/Bad to classes.dex."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("classes.dex", dex(classes1() + ([bad_class()] if with_bad else [])))
        z.writestr("classes2.dex", dex(classes2()))
        if with_arsc:
            z.writestr("resources.arsc", arsc())
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    return str(path)
