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
