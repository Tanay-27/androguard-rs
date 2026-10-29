"""Synthetic APKs androguard 4.1.3 fails (or doesn't fail) to load, shared by
test_strict.py (standalone, goldens), test_strict_parity.py (live against
androguard) and scripts/gen_dexobj_goldens.py (which wrote strict_goldens.py
once from androguard 4.1.3 + mutf8 1.1.0).

androguard's AnalyzeAPK builds, for each DEX in get_all_dex() order,
`DEX(bytes)` (whose HeaderItem raises ValueError/NotImplementedError for a
short file, a wrong or byte-swapped endian tag, a wrong magic, a bad
Adler-32 checksum, a wrong header size, too many type or proto ids) and then
`Analysis.add()`, whose MethodAnalysis objects disassemble every method with
code: the first one that can't be disassembled raises InvalidInstruction,
which nothing catches. So the first failure in that order is what
AnalyzeAPK raises. `manual_load` below does the same by hand, but skips a
DEX whose DEX() raises "Not a DEX file, Header too small." or "This is not
a DEX file! Wrong endian tag: ...": the two header errors that
`androguard_rs.Apk(..., tolerant=True)` also skips.
"""

import struct
import zlib

import dexbuild as DB
import fixture_apk as F
from dup_cases import C, X, _apk_raw, call, cls, init, m, string

OK = cls(C, direct=[init()], virtual=[m("a", string("a"))])


def bad(*ops):
    """Code androguard can't disassemble: an unused opcode (0x3e, 0x73,
    0xe3..0xf9), or an instruction cut off at the end."""
    return lambda c: bytes(ops)


def ok_dex() -> bytes:
    return F.dex([OK])


def bad_dex(tag="x", op=0x3e) -> bytes:
    """LX; whose second method can't be disassembled, its third neither."""
    return F.dex([OK, cls(X, direct=[init()], virtual=[
        m("ok", string("ok-" + tag)),
        m("bad", string("bad-" + tag), bad(op, 0)),
        m("bad2", bad(0x73, 0)),
        m("calls", call(0x6E, X, "ok"))])])


def truncated_dex() -> bytes:
    # const-wide (5 code units) with only 2 present.
    return F.dex([OK, cls(X, direct=[init()], virtual=[m("cut", bad(0x18, 0, 1, 2))])])


def _fix(buf: bytearray) -> bytes:
    struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:])))
    return bytes(buf)


def patched(dex: bytes, off: int, fmt: str, value, fix=True) -> bytes:
    buf = bytearray(dex)
    struct.pack_into(fmt, buf, off, value)
    return _fix(buf) if fix else bytes(buf)


def short() -> bytes:
    return ok_dex()[:0x60]


def endian() -> bytes:
    return patched(ok_dex(), 40, "<I", 0x11223344)


def byteswap() -> bytes:
    return patched(ok_dex(), 40, "<I", 0x78563412)


def magic() -> bytes:
    return patched(ok_dex(), 4, "4s", b"03X\x01")


def dey() -> bytes:
    return patched(ok_dex(), 0, "4s", b"dey\n")


def checksum() -> bytes:
    d = ok_dex()
    return patched(d, 8, "<I", (struct.unpack_from("<I", d, 8)[0] + 1) & 0xFFFFFFFF, fix=False)


def header_size() -> bytes:
    return patched(ok_dex(), 36, "<I", 0x78)


def type_ids() -> bytes:
    return patched(ok_dex(), 64, "<I", 70000)


def proto_ids() -> bytes:
    return patched(ok_dex(), 72, "<I", 65536)


def _share(dex: bytes) -> bytes:
    """class_def 0 pointed at class_def 1's class_data (so LC; lists LX;'s
    methods, the bad one included, before LX; itself)."""
    buf = bytearray(dex)
    _size, off = struct.unpack_from("<II", buf, 0x60)
    data_off = struct.unpack_from("<I", buf, off + 32 * 1 + 24)[0]
    struct.pack_into("<I", buf, off + 24, data_off)
    return _fix(buf)


# Past the header: androguard's DEX() parses every map section up front
# (MapList in TypeMapItem load order) and fails on a broken map list or
# item; Analysis.add() fails on try/catch handlers it can't match and on
# hidden-API flags missing for a class; create_xref() fails on an empty
# type name. Built on dexbuild.base_spec() (classes LA;, LB;, LI;; LA;.foo
# has a const-string, LB;.baz a try/catch-all).


def _base():
    """dexbuild.base_spec() with LB;.baz's try pointing at its handler (the
    handler list's first handler is 1 byte in, after its count; base_spec's
    0 is itself an IndexError in Analysis.add())."""
    sp = DB.base_spec()
    sp["codes"]["c_baz"] = DB.code_item(1, 1, 0, bytes.fromhex("0e00"), tries=struct.pack("<IHH", 0, 1, 1),
                                        handlers=DB.uleb(1) + DB.sleb(0) + DB.uleb(0), n_tries=1)
    return sp


def _spec(**kw):
    sp = _base()
    sp.update(kw)
    return sp


def _built(**kw) -> bytes:
    return DB.build(_spec(**kw))[0]


def _map_edit(fn):
    """A map_hook that applies fn(entries, labels)."""
    return fn


def _drop(ty):
    return lambda entries, L: entries.__setitem__(slice(None), [e for e in entries if e[0] != ty])


def _grow(ty, by):
    def hook(entries, L):
        for e in entries:
            if e[0] == ty:
                e[1] += by
    return hook


def _move(ty, off):
    def hook(entries, L):
        for e in entries:
            if e[0] == ty:
                e[2] = off
    return hook


def _patch_u32(label, delta, value):
    return lambda buf, L: struct.pack_into("<I", buf, L[label] + delta, value)


def _patch_u16(label, delta, value):
    return lambda buf, L: struct.pack_into("<H", buf, L[label] + delta, value)


def _append_section(ty, payload: bytes):
    """A patch that appends `payload` and a map entry of type `ty` for it
    (the map list moves to the end)."""
    def patch(buf, L):
        while len(buf) % 4:
            buf.append(0)
        off = len(buf)
        buf += payload
        mo = L["map"]
        n = struct.unpack_from("<I", buf, mo)[0]
        ents = bytes(buf[mo + 4:mo + 4 + 12 * n]) + struct.pack("<HHII", ty, 0, 1, off)
        while len(buf) % 4:
            buf.append(0)
        new = len(buf)
        buf += struct.pack("<I", n + 1) + ents
        struct.pack_into("<I", buf, 52, new)
        for k in range(n + 1):
            if struct.unpack_from("<H", buf, new + 4 + 12 * k)[0] == DB.MAP_LIST:
                struct.pack_into("<I", buf, new + 4 + 12 * k + 8, new)
        struct.pack_into("<I", buf, 32, len(buf))
    return patch


def _hidden(flags, n=None):
    """A HIDDENAPI_CLASS_DATA_ITEM with `n` class offsets (default: one per
    flag) and those flags."""
    n = len(flags) if n is None else n
    body = b"".join(struct.pack("<I", 4 + 4 * n) for _ in range(n)) + b"".join(DB.uleb(f) for f in flags)
    return struct.pack("<I", 4 + len(body)) + body


def _nested(n, kind="array"):
    """An encoded_array_item (or annotation_item) nesting n arrays (or
    annotations) in each other, ending in null."""
    if kind == "array":
        return DB.uleb(1) + (b"\x1c" + DB.uleb(1)) * n + b"\x1e"
    one = DB.uleb(0) + DB.uleb(1) + DB.uleb(0)
    return b"\x01" + one + (b"\x1d" + one) * n + b"\x1e"


def _foo_insns(insns: bytes):
    """_base() with LA;.foo's code replaced (same length, 8 bytes)."""
    sp = _base()
    sp["codes"]["c_foo"] = DB.code_item(3, 2, 0, insns)
    return sp


def _with_type(name: bytes, insns_fn):
    """base_spec plus a type named `name` (string and type appended last),
    LA;.foo's code from insns_fn(type_idx, method_idx); a method of that
    type is added too."""
    sp = _base()
    sp["strings"] = sp["strings"] + [name]
    sp["types"] = sp["types"] + [len(sp["strings"]) - 1]
    t = len(sp["types"]) - 1
    sp["methods"] = sp["methods"] + [(t, 0, sp["strings"].index(b"bar"))]
    sp["codes"]["c_foo"] = DB.code_item(3, 2, 1, insns_fn(t, len(sp["methods"]) - 1))
    return sp


def _odd_tail(buf, L):
    """Move LA;.foo's code to a new last CODE_ITEM section at the end of the
    file, its insns cut to an odd length by the end of the file."""
    while len(buf) % 4:
        buf.append(0)
    at = len(buf)
    old = DB.uleb(L["c_foo"])
    new = DB.uleb(at)
    assert len(old) == len(new)
    cd = L["cd_A"]
    i = buf.index(old, cd)
    buf[i:i + len(old)] = new
    # registers, ins, outs, tries, debug, insns_size=4; then 5 bytes
    buf += struct.pack("<4H2I", 3, 2, 0, 0, 0, 4) + bytes([0x12, 0x00, 0x0F, 0x00, 0x0E])
    mo = L["map"]
    n = struct.unpack_from("<I", buf, mo)[0]
    for k in range(n):
        if struct.unpack_from("<H", buf, mo + 4 + 12 * k)[0] == DB.CODE:
            struct.pack_into("<II", buf, mo + 4 + 12 * k + 4, 1, at)
    struct.pack_into("<I", buf, 32, len(buf))


def _no_nul_tail(buf, L):
    """A last STRING_DATA_ITEM section whose string runs to the end of the
    file without a NUL: androguard's read_null_terminated_string never
    returns."""
    while len(buf) % 4:
        buf.append(0)
    _append_section(DB.STRING_DATA, b"\x03abc")(buf, L)
    # the map list is now last: put the string after it
    buf += b""
    mo = struct.unpack_from("<I", buf, 52)[0]
    n = struct.unpack_from("<I", buf, mo)[0]
    struct.pack_into("<I", buf, mo + 4 + 12 * (n - 1) + 8, len(buf))
    buf += b"\x05abcde"
    struct.pack_into("<I", buf, 32, len(buf))


LOAD_CASES = {
    # DEX(): the map list and its sections
    "map_unknown_type": lambda: _built(map_hook=lambda e, L: e.insert(1, [0x1234, 1, 0x70])),
    "map_count_past_end": lambda: _built(patch=lambda b, L: struct.pack_into("<I", b, L["map"], 100)),
    "map_off_past_end": lambda: _built(patch=lambda b, L: struct.pack_into("<I", b, 52, len(b) - 2)),
    "string_ids_past_end": lambda: _built(map_hook=_grow(DB.STRING_ID, 10000)),
    "class_defs_past_end": lambda: _built(map_hook=_grow(DB.CLASS_DEF, 100)),
    "code_past_end": lambda: _built(map_hook=_grow(DB.CODE, 1000)),
    "no_type_ids": lambda: _built(map_hook=_drop(DB.TYPE_ID)),
    "no_string_ids": lambda: _built(map_hook=_drop(DB.STRING_ID)),
    "no_proto_ids": lambda: _built(map_hook=_drop(DB.PROTO_ID)),
    "interfaces_undeclared": lambda: _built(patch=_patch_u32("class_defs", 12, 0x70)),
    "proto_out_of_range": lambda: _built(patch=_patch_u16("method_ids", 8 + 2, 0x7FFF)),
    "proto_params_undeclared": lambda: _built(patch=_patch_u32("proto_ids", 12 + 8, 0x70)),
    "annotations_no_directory": lambda: _built(patch=_patch_u32("class_defs", 32 + 20, 0x70)),
    "static_values_not_found": lambda: _built(patch=_patch_u32("class_defs", 32 + 28, 0x70)),
    "static_values_no_section": lambda: _built(map_hook=_drop(DB.ENCODED_ARRAY)),
    "header_item_moved": lambda: _built(map_hook=_move(DB.HEADER, 0x10)),
    "hidden_bad_restriction": lambda: _built(patch=_append_section(0xF000, _hidden([1, 7, 2]))),
    "hidden_bad_domain": lambda: _built(patch=_append_section(0xF000, _hidden([1, 3 << 3, 2]))),
    "nested_annotations_ok": lambda: _built(patch=_append_section(0x2004, _nested(50, "annotation"))),
    "nested_arrays_recursion": lambda: _built(patch=_append_section(DB.ENCODED_ARRAY, _nested(3000))),
    "nested_annotations_recursion": lambda: _built(patch=_append_section(0x2004, _nested(3000, "annotation"))),
    # Analysis.add()
    "no_map": lambda: _built(patch=lambda b, L: struct.pack_into("<I", b, 52, 0)),
    "no_method_ids": lambda: _built(map_hook=_drop(DB.METHOD_ID)),
    "hidden_short": lambda: _built(patch=_append_section(0xF000, _hidden([1, 2]))),
    "bad_handler_off": lambda: _built(patch=lambda b, L: struct.pack_into("<H", b, L["c_baz"] + 16 + 2 + 2 + 6, 5)),
    "base_spec_handler": lambda: DB.build(DB.base_spec())[0],
    "odd_code_at_end": lambda: _built(patch=_odd_tail),
    # create_xref()
    "const_class_empty_type": lambda: DB.build(_with_type(b"[", lambda t, mi: struct.pack("<BBH", 0x1C, 0, t) + bytes([0x0F, 0, 0, 0])))[0],
    "new_instance_empty_type": lambda: DB.build(_with_type(b"", lambda t, mi: struct.pack("<BBH", 0x22, 0, t) + bytes([0x0F, 0, 0, 0])))[0],
    "invoke_array_class": lambda: DB.build(_with_type(b"[[", lambda t, mi: struct.pack("<BBHH", 0x6E, 0x10, mi, 0) + bytes([0x0F, 0])))[0],
    "sget_no_field_ids": lambda: DB.build(dict(_foo_insns(struct.pack("<BBH", 0x60, 0, 0) + bytes([0x0F, 0, 0, 0])),
                                                map_hook=_drop(DB.FIELD_ID)))[0],
    "const_class_ok_array": lambda: DB.build(_with_type(b"[I", lambda t, mi: struct.pack("<BBH", 0x1C, 0, t) + bytes([0x0F, 0, 0, 0])))[0],
}

# androguard never returns on this one (see _no_nul_tail); not in CASES.
HANG_CASES = {"string_no_nul_at_end": lambda: _built(patch=_no_nul_tail),
              "string_data_past_end": lambda: _built(map_hook=_grow(DB.STRING_DATA, 1000))}

CASES = {
    "ok": lambda: _apk_raw(ok_dex()),
    "ok_two": lambda: _apk_raw(ok_dex(), F.dex([cls(X, direct=[init()])])),
    "bad": lambda: _apk_raw(bad_dex()),
    "bad_payload_op": lambda: _apk_raw(bad_dex(op=0xe5)),
    "truncated_insn": lambda: _apk_raw(truncated_dex()),
    "bad_second": lambda: _apk_raw(ok_dex(), bad_dex("2")),
    "bad_both": lambda: _apk_raw(bad_dex("1"), bad_dex("2", op=0xf0)),
    "bad_shared": lambda: _apk_raw(_share(bad_dex())),
    "short": lambda: _apk_raw(ok_dex(), short()),
    "endian": lambda: _apk_raw(endian()),
    "byteswap": lambda: _apk_raw(ok_dex(), byteswap()),
    "magic": lambda: _apk_raw(magic()),
    "dey_magic_checksum": lambda: _apk_raw(dey(), ok_dex()),
    "checksum": lambda: _apk_raw(ok_dex(), checksum()),
    "header_size": lambda: _apk_raw(header_size()),
    "type_ids": lambda: _apk_raw(type_ids()),
    "proto_ids": lambda: _apk_raw(proto_ids()),
    "bad_then_checksum": lambda: _apk_raw(bad_dex(), checksum()),
    "checksum_then_bad": lambda: _apk_raw(checksum(), bad_dex()),
    "endian_then_bad": lambda: _apk_raw(endian(), bad_dex()),
    "short_then_ok": lambda: _apk_raw(short(), ok_dex()),
    "byteswap_then_bad": lambda: _apk_raw(byteswap(), bad_dex()),
    "bad_then_byteswap": lambda: _apk_raw(bad_dex(), byteswap()),
    **{name: (lambda mk=mk: _apk_raw(mk())) for name, mk in LOAD_CASES.items()},
    # orders across DEX files: DEX() and add() of each in turn, create_xref() last
    "xref_then_add": lambda: _apk_raw(LOAD_CASES["const_class_empty_type"](), LOAD_CASES["bad_handler_off"]()),
    "add_then_load": lambda: _apk_raw(LOAD_CASES["hidden_short"](), LOAD_CASES["map_unknown_type"]()),
    "load_then_add": lambda: _apk_raw(LOAD_CASES["no_type_ids"](), LOAD_CASES["no_map"]()),
    "ok_then_xref": lambda: _apk_raw(ok_dex(), LOAD_CASES["sget_no_field_ids"]()),
    "xref_then_xref": lambda: _apk_raw(LOAD_CASES["invoke_array_class"](), LOAD_CASES["sget_no_field_ids"]()),
}


def outcome(fn):
    """("ok", value) or ("raise", type name, repr(args), str(exception))."""
    try:
        return ("ok", fn())
    except Exception as e:  # noqa: BLE001 - every kind is compared
        return ("raise", type(e).__name__, repr(e.args), str(e))


def summary(d, dx):
    """What loaded: the DEX objects' class names and dx's classes."""
    return {"dex": [[c.get_name() for c in vm.get_classes()] for vm in d],
            "classes": [(c.name, c.is_external()) for c in dx.get_classes()]}


def analyze(analyze_apk, raw: bytes):
    return outcome(lambda: summary(*analyze_apk(raw, raw=True)[1:]))


TOO_SMALL = "Not a DEX file, Header too small."
WRONG_ENDIAN = "This is not a DEX file! Wrong endian tag:"


def _tolerated(exc: Exception) -> bool:
    msg = str(exc)
    return isinstance(exc, ValueError) and (msg == TOO_SMALL or msg.startswith(WRONG_ENDIAN))


def manual_load(APK, DEX, Analysis, raw: bytes):
    """APK.get_all_dex() -> DEX() -> Analysis.add() -> create_xref() with
    the given classes, skipping (and recording) a DEX that fails with one of
    the two tolerated header errors; any other error propagates."""
    apk = APK(raw, raw=True)
    analysis = Analysis()
    loaded, skipped = [], []
    for data in list(apk.get_all_dex()):
        try:
            dex = DEX(data)
            analysis.add(dex)
        except Exception as exc:
            if not _tolerated(exc):
                raise
            skipped.append(str(exc))
            continue
        loaded.append(dex)
        dex.set_analysis(analysis)
    analysis.create_xref()
    return {"skipped": skipped, **summary(loaded, analysis)}


def manual(APK, DEX, Analysis, raw: bytes):
    return outcome(lambda: manual_load(APK, DEX, Analysis, raw))
