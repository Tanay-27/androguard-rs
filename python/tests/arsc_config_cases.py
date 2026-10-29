"""resources.arsc tables whose type chunks carry every shape of
ResTable_config androguard 4.1.3's ARSCResTableConfig reads: each size
from 16 bytes up (optional fields missing), localeScript/localeVariant,
screenConfig2, padding past the known fields, every qualifier field set,
and two chunks with equal `_get_tuple()`s but different script/variant
(androguard keys resource_values by config, so the first chunk's object
is the one returned). No androguard needed."""

import struct

from arscbuild import package, simple, spec_chunk, table, type_chunk


def raw_config(size, imsi=0, locale=0, screen_type=0, inp=0, screen_size=0, version=0, screen_config=0,
               screen_size_dp=0, script=b"", variant=b"", screen_config2=0, pad=b""):
    """A ResTable_config of `size` bytes: the fields that fit, in order."""
    fields = struct.pack("<IIIIIIII", imsi, locale, screen_type, inp, screen_size, version, screen_config,
                         screen_size_dp)
    body = fields + script.ljust(4, b"\0")[:4] + variant.ljust(8, b"\0")[:8] + struct.pack("<I", screen_config2)
    body = (body + pad)[: size - 4]
    return struct.pack("<I", size) + body.ljust(size - 4, b"\0")


CONFIGS = [
    raw_config(16, imsi=310 | 260 << 16, locale=0x5355_6E65),
    raw_config(20, locale=0x0000_7266, screen_type=1 | 3 << 8 | 480 << 16, inp=2 | 3 << 8 | 0x05 << 16),
    raw_config(24, screen_size=1080 | 1920 << 16),
    raw_config(28, version=21 | 1 << 16),
    raw_config(32, screen_config=0x40 | 0x02 | 0x20 | (0x24 << 8) | (600 << 16)),
    raw_config(36, screen_size_dp=320 | 480 << 16, screen_type=0xFFFE << 16),
    raw_config(40, locale=0x0000_6E65, script=b"Latn"),
    raw_config(48, locale=0x0000_6E65, script=b"Latn", variant=b"posix"),
    raw_config(52, screen_config2=0x02 | 0x05 << 8, screen_type=2 | 0xFFFF << 16),
    raw_config(64, version=33, screen_config2=0x01 | 0x0A << 8, pad=b"\x00" * 4 + b"PADDINGBYTES"),
    raw_config(56, screen_config=0x80 | 0x0F | 0x30 | (0x3F << 8), inp=7 | 9 << 8 | 0x0F << 16, screen_type=4 | 7 << 8 | 77 << 16),
    raw_config(52, locale=bytes([0x80 | (5 << 2), 0x41, 0x80 | 3, 0x22]) and struct.unpack("<I", bytes([0x80 | (5 << 2), 0x41, 0x80 | 3, 0x22]))[0]),
    # equal tuples, different script: the first is the dict key
    raw_config(48, locale=0x0000_7273, script=b"Cyrl", variant=b"a"),
    raw_config(48, locale=0x0000_7273, script=b"Latn", variant=b"b"),
]


def tables():
    """{name: arsc bytes}."""
    s = 0x03
    strings = ["v%d" % i for i in range(len(CONFIGS) + 2)]
    keys = ["a", "b", "c"]
    chunks = [spec_chunk(1, 3), type_chunk(1, [simple(0, s, 0), simple(1, s, 1), simple(2, s, 2)])]
    for n, cfg in enumerate(CONFIGS):
        # entry 0 in every config; entry 1 only in the later of the twins
        entries = [simple(0, s, n + 1)]
        if n == len(CONFIGS) - 1:
            entries.append(simple(1, s, n + 1))
        chunks.append(type_chunk(1, entries, cfg))
    one = table(strings, [package(0x7F, "com.example", ["string"], keys, chunks)])
    # A complex (style) entry under a sized config, and references through it.
    style = struct.pack("<HHI", 16, 1, 2) + struct.pack("<II", 0, 2) + \
        struct.pack("<I", 0x01010000) + struct.pack("<HBBI", 8, 0, 0x01, 0x7F010000) + \
        struct.pack("<I", 0x01010001) + struct.pack("<HBBI", 8, 0, 0x03, 1)
    two = table(strings, [package(0x7F, "com.example", ["string", "style"], keys, [
        spec_chunk(1, 2), type_chunk(1, [simple(0, s, 0), simple(1, 0x01, 0x7F010000)], CONFIGS[7]),
        type_chunk(1, [simple(0, s, 3)], CONFIGS[9]),
        spec_chunk(2, 1), type_chunk(2, [style], CONFIGS[2]),
    ])])
    return {"config-shapes": one, "complex-and-references": two}


RIDS = [0x7F010000, 0x7F010001, 0x7F010002, 0x7F020000]
