"""A tiny DEX writer for differential tests on crafted files.

`build(spec)` lays out a small, valid DEX with a map list, then lets a test
redirect offsets at copies the map doesn't declare, add or change map
entries, and so on. Every item's offset is returned by label, and the
Adler-32 checksum is recomputed last (androguard rejects a wrong one).
"""

import struct
import zlib

# map_list item types
HEADER, STRING_ID, TYPE_ID, PROTO_ID, FIELD_ID, METHOD_ID, CLASS_DEF = 0, 1, 2, 3, 4, 5, 6
MAP_LIST, TYPE_LIST, CLASS_DATA, CODE, STRING_DATA, ENCODED_ARRAY, ANNOTATIONS_DIR = (
    0x1000, 0x1001, 0x2000, 0x2001, 0x2002, 0x2005, 0x2006)


def uleb(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if (v == 0 and not b & 0x40) or (v == -1 and b & 0x40):
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def code_item(registers: int, ins: int, outs: int, insns: bytes, tries: bytes = b"", handlers: bytes = b"",
              n_tries: int = 0) -> bytes:
    assert len(insns) % 2 == 0
    out = struct.pack("<4H2I", registers, ins, outs, n_tries, 0, len(insns) // 2) + insns
    if n_tries:
        if (len(insns) // 2) % 2:
            out += b"\0\0"
        out += tries + handlers
    return out


def class_data(static=(), instance=(), direct=(), virtual=()) -> bytes:
    """Lists of (idx, flags) for fields and (idx, flags, code_off) for methods,
    idx absolute (delta-encoded here). code_off may be raw bytes (an
    already-encoded uleb, to craft odd encodings)."""
    out = uleb(len(static)) + uleb(len(instance)) + uleb(len(direct)) + uleb(len(virtual))
    for lst, is_method in ((static, False), (instance, False), (direct, True), (virtual, True)):
        prev = 0
        for e in lst:
            out += uleb(e[0] - prev)
            prev = e[0]
            out += e[1] if isinstance(e[1], bytes) else uleb(e[1])
            if is_method:
                out += e[2] if isinstance(e[2], bytes) else uleb(e[2])
    return out


def base_spec() -> dict:
    """Three classes: LA; (implements LI;, static values, methods with code),
    LB; extends LA;, and interface LI;. Code/class_data offsets are written as
    labels and resolved at layout time."""
    strings = [b"<init>", b"I", b"LA;", b"LB;", b"LI;", b"Ljava/lang/Object;", b"Ljava/lang/String;", b"V", b"bar",
               b"baz", b"f", b"foo", b"hello", b"s0", b"s1", b"II", b"VI"]
    s = {v: i for i, v in enumerate(strings)}
    types = [s[b"I"], s[b"LA;"], s[b"LB;"], s[b"LI;"], s[b"Ljava/lang/Object;"], s[b"Ljava/lang/String;"], s[b"V"]]
    t = {strings[v]: i for i, v in enumerate(types)}
    protos = [(s[b"V"], t[b"V"], None), (s[b"II"], t[b"I"], "tl_I")]
    fields = [(t[b"LA;"], t[b"I"], s[b"f"]), (t[b"LA;"], t[b"I"], s[b"s0"]),
              (t[b"LA;"], t[b"Ljava/lang/String;"], s[b"s1"])]
    methods = [(t[b"LA;"], 0, s[b"<init>"]), (t[b"LA;"], 0, s[b"bar"]), (t[b"LA;"], 1, s[b"foo"]),
               (t[b"LB;"], 0, s[b"baz"]), (t[b"Ljava/lang/Object;"], 0, s[b"<init>"])]
    # invoke-direct {v0}, Ljava/lang/Object;-><init>()V ; return-void
    init = code_item(1, 1, 1, bytes.fromhex("7010 0400 0000 0e00".replace(" ", "")))
    # const-string v0, "hello" ; add-int/lit8 v0, v2, 1 ; return v0
    foo = code_item(3, 2, 0, struct.pack("<BBH", 0x1A, 0, s[b"hello"]) + bytes([0xD8, 0, 2, 1]) + bytes([0x0F, 0]))
    # return-void, with one try/catch-all, to exercise handler sizing
    baz = code_item(1, 1, 0, bytes.fromhex("0e00"), tries=struct.pack("<IHH", 0, 1, 0),
                    handlers=uleb(1) + sleb(0) + uleb(0), n_tries=1)
    return {
        "strings": strings,
        "types": types,
        "protos": protos,
        "fields": fields,
        "methods": methods,
        "type_lists": {"tl_I": [t[b"I"]], "tl_LI": [t[b"LI;"]]},
        "codes": {"c_init": init, "c_foo": foo, "c_baz": baz},
        "class_datas": {
            "cd_A": lambda L: class_data(static=[(1, 0x9), (2, 0x9)], instance=[(0, 0x2)],
                                        direct=[(0, 0x10001, L["c_init"])],
                                        virtual=[(1, 0x401, 0), (2, 0x1, L["c_foo"])]),
            "cd_B": lambda L: class_data(virtual=[(3, 0x1, L["c_baz"])]),
        },
        # value_type 0x04 (int) arg 0: 7 ; value_type 0x17 (string) arg 0: "hello"
        "encoded_arrays": {"ea_A": uleb(2) + bytes([0x04, 7, 0x17, s[b"hello"]])},
        # class, flags, super, interfaces label, class_data label, static_values label
        "classes": [
            (t[b"LA;"], 0x1, t[b"Ljava/lang/Object;"], "tl_LI", "cd_A", "ea_A"),
            (t[b"LB;"], 0x1, t[b"LA;"], None, "cd_B", None),
            (t[b"LI;"], 0x601, t[b"Ljava/lang/Object;"], None, None, None),
        ],
        # Undeclared copies a test can point offsets at: label -> bytes or
        # callable(labels) -> bytes (labels of type lists and code known).
        "extra": {},
        # Called with (entries, labels) to edit the map: entries are
        # [type, size, offset] lists, in file order.
        "map_hook": None,
        # Called with (bytearray, labels) right before the checksum.
        "patch": None,
    }


def build(spec: dict) -> tuple[bytes, dict]:
    buf = bytearray(0x70)
    L = {}

    def align(n=4):
        while len(buf) % n:
            buf.append(0)

    # Fixed-size id tables, filled in once data offsets are known.
    L["string_ids"] = len(buf)
    buf += bytes(4 * len(spec["strings"]))
    L["type_ids"] = len(buf)
    for v in spec["types"]:
        buf += struct.pack("<I", v)
    L["proto_ids"] = len(buf)
    buf += bytes(12 * len(spec["protos"]))
    L["field_ids"] = len(buf)
    for c, ty, n in spec["fields"]:
        buf += struct.pack("<HHI", c, ty, n)
    L["method_ids"] = len(buf)
    for c, p, n in spec["methods"]:
        buf += struct.pack("<HHI", c, p, n)
    L["class_defs"] = len(buf)
    buf += bytes(32 * len(spec["classes"]))
    data_off = len(buf)

    align()
    L["type_list_section"] = len(buf)
    for k, lst in spec["type_lists"].items():
        L[k] = len(buf)
        buf += struct.pack("<I", len(lst)) + b"".join(struct.pack("<H", x) for x in lst)
        align()
    L["code_section"] = len(buf)
    for k, c in spec["codes"].items():
        align()
        L[k] = len(buf)
        buf += c
    # Undeclared extras sit right after the code section, so growing the
    # CODE_ITEM count by one declares the first of them.
    for k, v in spec["extra"].items():
        align()
        L[k] = len(buf)
        buf += v(L) if callable(v) else v
    L["string_data_section"] = len(buf)
    for i, v in enumerate(spec["strings"]):
        L[f"str{i}"] = len(buf)
        buf += uleb(len(v)) + v + b"\0"
    L["class_data_section"] = len(buf)
    # class_data refers to code offsets, which are known by now.
    for k, f in spec["class_datas"].items():
        L[k] = len(buf)
        buf += f(L)
    L["encoded_array_section"] = len(buf)
    for k, v in spec["encoded_arrays"].items():
        L[k] = len(buf)
        buf += v
    align()
    entries = [
        [HEADER, 1, 0], [STRING_ID, len(spec["strings"]), L["string_ids"]], [TYPE_ID, len(spec["types"]), L["type_ids"]],
        [PROTO_ID, len(spec["protos"]), L["proto_ids"]], [FIELD_ID, len(spec["fields"]), L["field_ids"]],
        [METHOD_ID, len(spec["methods"]), L["method_ids"]], [CLASS_DEF, len(spec["classes"]), L["class_defs"]],
        [TYPE_LIST, len(spec["type_lists"]), L["type_list_section"]], [CODE, len(spec["codes"]), L["code_section"]],
        [STRING_DATA, len(spec["strings"]), L["string_data_section"]],
        [CLASS_DATA, len(spec["class_datas"]), L["class_data_section"]],
        [ENCODED_ARRAY, len(spec["encoded_arrays"]), L["encoded_array_section"]],
    ]
    entries = [e for e in entries if e[1] or e[0] in (HEADER,)]
    L["map"] = len(buf)
    entries.append([MAP_LIST, 1, L["map"]])
    if spec["map_hook"]:
        spec["map_hook"](entries, L)
    buf += struct.pack("<I", len(entries))
    for ty, size, off in entries:
        buf += struct.pack("<HHII", ty, 0, size, off)

    # Now the tables that point into data.
    for i in range(len(spec["strings"])):
        struct.pack_into("<I", buf, L["string_ids"] + 4 * i, L[f"str{i}"])
    for i, (shorty, ret, params) in enumerate(spec["protos"]):
        struct.pack_into("<3I", buf, L["proto_ids"] + 12 * i, shorty, ret, L[params] if params else 0)
    for i, (c, flags, sup, ifaces, cd, sv) in enumerate(spec["classes"]):
        struct.pack_into("<8I", buf, L["class_defs"] + 32 * i, c, flags, sup, L[ifaces] if ifaces else 0,
                         0xFFFFFFFF, 0, L[cd] if cd else 0, L[sv] if sv else 0)

    header = struct.pack(
        "<8sI20s20I", b"dex\n035\0", 0, bytes(20), len(buf), 0x70, 0x12345678, 0, 0, L["map"],
        len(spec["strings"]), L["string_ids"], len(spec["types"]), L["type_ids"], len(spec["protos"]),
        L["proto_ids"], len(spec["fields"]), L["field_ids"], len(spec["methods"]), L["method_ids"],
        len(spec["classes"]), L["class_defs"], len(buf) - data_off, data_off)
    buf[:0x70] = header
    if spec["patch"]:
        spec["patch"](buf, L)
    struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:])))
    return bytes(buf), L


def set_class_field(buf: bytearray, L: dict, class_no: int, word: int, value: int) -> None:
    """Overwrite u32 `word` (3 interfaces_off, 6 class_data_off, 7 static_values_off) of class_def `class_no`."""
    struct.pack_into("<I", buf, L["class_defs"] + 32 * class_no + 4 * word, value)
