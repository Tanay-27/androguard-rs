"""A tiny resources.arsc writer: string pools, packages, type/spec chunks,
and the synthetic tables the resource tests use. No androguard needed."""

import struct


def u8len(n):
    return bytes([n]) if n < 0x80 else bytes([0x80 | (n >> 8), n & 0xFF])


def u16len(n):
    return struct.pack("<H", n) if n < 0x8000 else struct.pack("<HH", 0x8000 | (n >> 16), n & 0xFFFF)


def string_pool(strings, utf8=True):
    data, offsets = b"", []
    for s in strings:
        offsets.append(len(data))
        if utf8:
            b = s if isinstance(s, bytes) else s.encode("utf-8")
            data += u8len(len(b) if isinstance(s, bytes) else len(s)) + u8len(len(b)) + b + b"\0"
        else:
            # raw bytes: a lone surrogate, then the bytes padded to whole units
            b = b"\x00\xd8" + s + b"\0" * (len(s) % 2) if isinstance(s, bytes) else s.encode("utf-16-le")
            data += u16len(len(b) // 2) + b + b"\0\0"
    data += b"\0" * (-len(data) % 4)
    start = 28 + 4 * len(strings)
    head = struct.pack("<HHIIIIII", 1, 28, start + len(data), len(strings), 0, 0x100 if utf8 else 0, start, 0)
    return head + b"".join(struct.pack("<I", o) for o in offsets) + data


def config(locale=b"\0\0\0\0", density=0, sdk=0):
    body = struct.pack("<I", 0) + locale[:4].ljust(4, b"\0") + struct.pack("<I", density << 16)
    body += struct.pack("<III", 0, 0, sdk) + b"\0" * 36
    return struct.pack("<I", 4 + len(body)) + body


def simple(key, ty, data, flags=0):
    return struct.pack("<HHI", 8, flags, key) + struct.pack("<HBBI", 8, 0, ty, data)


def compact(key, ty, data):
    return struct.pack("<HHI", key, 8 | (ty << 8), data)


def complex_(key, items, parent=0):
    body = b"".join(struct.pack("<I", n) + struct.pack("<HBBI", 8, 0, t, d) for n, t, d in items)
    return struct.pack("<HHI", 16, 1, key) + struct.pack("<II", parent, len(items)) + body


def type_chunk(type_id, entries, cfg=None, flags=0):
    cfg = cfg or config()
    head_size = 20 + len(cfg)
    offs, data = [], b""
    for idx, e in enumerate(entries):
        if e is None:
            if not flags & 1:
                offs.append(0xFFFF if flags & 2 else 0xFFFFFFFF)
        else:
            # FLAG_SPARSE: (index, offset / 4) pairs for present entries only
            offs.append(idx | (len(data) // 4) << 16 if flags & 1 else len(data) // 4 if flags & 2 else len(data))
            data += e + b"\0" * (-len(e) % 4)
    table = b"".join(struct.pack("<H" if flags & 2 and not flags & 1 else "<I", o) for o in offs)
    table += b"\0" * (-len(table) % 4)
    start = head_size + len(table)
    count = len(offs) if flags & 1 else len(entries)
    head = struct.pack("<HHIBBHII", 0x201, head_size, start + len(data), type_id, flags, 0, count, start)
    return head + cfg + table + data


def spec_chunk(type_id, n):
    return struct.pack("<HHIBBHI", 0x202, 16, 16 + 4 * n, type_id, 0, 0, n) + b"\0" * (4 * n)


def package(pid, name, types, keys, chunks, utf8=True):
    tp, kp = string_pool(types, utf8), string_pool(keys, utf8)
    name_b = name.encode("utf-16-le")[:256].ljust(256, b"\0")
    body = struct.pack("<I", pid) + name_b + struct.pack("<IIIII", 288, len(types), 288 + len(tp), len(keys), 0)
    rest = tp + kp + b"".join(chunks)
    return struct.pack("<HHI", 0x200, 288, 288 + len(rest)) + body + rest


def table(strings, packages, utf8=True, package_count=None):
    body = string_pool(strings, utf8) + b"".join(packages)
    n = len(packages) if package_count is None else package_count
    return struct.pack("<HHII", 2, 12, 12 + len(body), n) + body


TYPES = ["string", "id", "bool", "integer", "color", "dimen", "style", "drawable", "fraction", "xml"]


def ref(t, i, pid=0x7F):
    return pid << 24 | (TYPES.index(t) + 1) << 16 | i


def synthetic_tables():
    """Tables exercising what real APKs rarely have."""
    strings = ["hello", "<b>&amp;</b>", "", "res/xml/a.xml", "üñï©ødé", "😀 astral", b"\xc3(\xed\xa0\x80", "x" * 200]
    keys = ["app_name", "title", "flag", "count", "accent", "margin", "Theme", "icon", "ratio", "config", "dup"]
    s, i, k = 0x03, 0x10, keys.index

    def pkg_chunks(variant):
        fr = config(b"fr\0\0")
        en_us = config(b"enUS")
        packed = config(bytes([0x80 | (5 << 2) | 0, 0x41]) + b"\0\0")  # a packed 3-letter language
        return [
            spec_chunk(1, 3),
            type_chunk(1, [simple(k("app_name"), s, 0), simple(k("title"), s, 1), simple(k("dup"), s, 7)]),
            type_chunk(1, [simple(k("app_name"), s, 4), None, simple(k("dup"), s, 5)], fr),
            type_chunk(1, [simple(k("app_name"), 0x01, ref("string", 1)), simple(k("title"), s, 6)], en_us),
            type_chunk(1, [compact(k("app_name"), s, 2), compact(1, s, 3)], packed),
            type_chunk(2, [simple(k("flag"), 0x12, 0), simple(k("title"), 0x12, 1)]),
            type_chunk(3, [simple(k("flag"), 0x12, 0xFFFFFFFF), simple(k("count"), 0x12, 0)]),
            type_chunk(4, [simple(k("count"), 0x10, 0xFFFFFFFE), compact(k("count"), 0x10, 42), simple(k("margin"), 0x11, 0xBEEF)], flags=2),
            type_chunk(5, [simple(k("accent"), 0x1C, 0x80FF00FF), simple(k("title"), 0x1F, 0xF00)]),
            type_chunk(6, [simple(k("margin"), 0x05, 0x00001001), simple(k("ratio"), 0x05, 0x7FFF0033), simple(k("count"), 0x04, 0x3FC00000)]),
            type_chunk(7, [complex_(k("Theme"), [(0x01010000, 0x02, 0x01010098), (0x7F010000, 0x01, ref("string", 0)),
                                                  (0x7F010001, 0x01, ref("style", 0)), (0x7F010002, s, 3),
                                                  (0x7F010003, 0x01, ref("color", 0)), (5, 0x04, 0x7F800000),
                                                  (6, 0x06, 0x00800001), (7, 0x00, 0), (8, 0x20, 9)])]),
            type_chunk(8, [simple(k("icon"), s, 3), simple(k("config"), 0x01, ref("drawable", 1)),
                           simple(k("ratio"), 0x01, ref("drawable", 3)), simple(k("dup"), 0x01, ref("drawable", 2))]),
            type_chunk(8, [simple(k("icon"), s, 3), simple(k("config"), 0x01, ref("drawable", 0))], config(density=480)),
            type_chunk(9, [simple(k("ratio"), 0x06, 0x00000301), simple(k("title"), 0x02, 0x01010000)]),
            type_chunk(10, [simple(k("config"), 0x01, ref("xml", 0)), simple(k("dup"), 0x01, 0)] if variant == "cycle"
                       else [simple(k("config"), s, 3)]),
        ]

    out = {
        "utf8": table(strings, [package(0x7F, "com.example", TYPES, keys, pkg_chunks(""))]),
        "utf16": table(strings, [package(0x7F, "com.example", TYPES, keys, pkg_chunks(""), utf8=False)], utf8=False),
        "self-reference": table(strings, [package(0x7F, "com.example", TYPES, keys, pkg_chunks("cycle"))]),
        "two-packages": table(strings, [
            package(0x7F, "com.example", TYPES, keys, pkg_chunks("")),
            package(0x01, "android", ["string", "attr"], ["ok", "cancel"], [type_chunk(1, [simple(0, s, 0), simple(1, s, 4)])]),
            package(0x7F, "com.example", ["string"], ["extra"], [type_chunk(1, [simple(0, s, 5)], config(b"de\0\0"))]),
        ], package_count=3),
        "empty-package-name": table(strings, [package(0x7F, "", TYPES, keys, pkg_chunks(""))]),
        "too-many-packages": table(strings, [package(1, "a", ["string"], ["x"], []), package(2, "b", ["string"], ["x"], []),
                                             package(3, "c", ["string"], ["x"], [])], package_count=1),
        # 4.1.3 ignores FLAG_SPARSE and reads the (index, offset) pairs as offsets.
        "sparse": table(strings, [package(0x7F, "com.example", TYPES, keys,
                                          [type_chunk(1, [simple(0, s, 0), None, simple(1, s, 1)], flags=1)])]),
        # A complex entry in a "string" type aborts _analyse() part-way.
        "complex-string": table(strings, [package(0x7F, "com.example", TYPES, keys, [
            type_chunk(2, [simple(k("flag"), 0x12, 1)]),
            type_chunk(1, [simple(0, s, 0), complex_(1, [(1, s, 0)]), simple(2, s, 1)]),
            type_chunk(1, [simple(0, s, 4)], config(b"fr\0\0")),
        ])]),
        "unterminated-utf8": table(strings, [package(0x7F, "com.example", TYPES, keys,
                                                     [type_chunk(1, [simple(0, s, 0)])])]).replace(b"hello\0", b"hellox"),
    }
    # A reference chain A -> B -> A (androguard: RecursionError).
    cyc = [type_chunk(1, [simple(0, 0x01, ref("string", 1)), simple(1, 0x01, ref("string", 0)), simple(2, s, 0)])]
    out["cycle"] = table(strings, [package(0x7F, "com.example", TYPES, keys, cyc)])
    return out
