"""Tiny synthetic seed corpora for the CI fuzz smoke job (stdlib only, no APKs).

Writes fuzz/corpus/<target>/ seeds that are valid enough to get past the
first parse, so a short run reaches the deeper code:

  dex_pipeline  python/tests/dexbuild.py's three-class DEX, fixture_apk.py's two DEX,
                the DEX files of python/tests/dup_cases.py (a class defined
                twice in one DEX, class_defs sharing a class_data),
                insn_apk.py's DEX (every instruction format, payloads, bad code)
                and the DEX files of strict_cases.py, sig_cases.py and
                dexobj_cases.py
  decode        that DEX's method code (insns), insn_apk.py's methods, plus a few
                hand-written methods
  text          MUTF-8 edge cases
  apk           zips around the DEX, around a resources.arsc, and around both,
                python/tests/dex_order_cases.py's tampered multi-DEX zips,
                dup_cases.py's APKs (classes defined more than once) and
                arsc_zip_cases.py's tampered resources.arsc entries,
                strict_cases.py's (header errors, bad code), sig_cases.py's and
                dexobj_cases.py's APKs
  arsc          a one-package resources.arsc with a string and an int
  axml          python/tests/apkbuild.py's manifest, layout and packer-style XML
  apkzip        apkbuild.py's synthetic APK (zip, v1 files, v2/v3 signing block)

Real-APK seeds come from scripts/fuzz_seeds.py instead (gitignored output).

usage: python scripts/ci_fuzz_seeds.py <out_corpus_dir>
"""

import hashlib
import io
import os
import struct
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python", "tests"))
import apkbuild as ab  # noqa: E402
import arsc_zip_cases as az  # noqa: E402
import dex_order_cases as dc  # noqa: E402
import dup_cases as du  # noqa: E402
import dexbuild as db  # noqa: E402
import dexobj_cases as do  # noqa: E402
import fixture_apk as fx  # noqa: E402
import insn_apk  # noqa: E402
import sig_cases as sg  # noqa: E402
import strict_cases as sc  # noqa: E402


def put(dirpath: str, data: bytes) -> None:
    os.makedirs(dirpath, exist_ok=True)
    with open(os.path.join(dirpath, hashlib.sha256(data).hexdigest()[:40]), "wb") as f:
        f.write(data)


def zip_of(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


# --- a minimal resources.arsc (same layout as python/tests/test_resources.py's builders)


def string_pool(strings):
    data, offsets = b"", []
    for s in strings:
        b = s.encode("utf-8")
        offsets.append(len(data))
        data += bytes([len(s)]) + bytes([len(b)]) + b + b"\0"
    data += b"\0" * (-len(data) % 4)
    start = 28 + 4 * len(strings)
    head = struct.pack("<HHIIIIII", 1, 28, start + len(data), len(strings), 0, 0x100, start, 0)
    return head + b"".join(struct.pack("<I", o) for o in offsets) + data


def arsc_table() -> bytes:
    cfg_body = struct.pack("<I", 0) + b"\0" * 4 + struct.pack("<I", 0) + struct.pack("<III", 0, 0, 0) + b"\0" * 36
    cfg = struct.pack("<I", 4 + len(cfg_body)) + cfg_body
    # entry 0: string "hello" (global pool index 0); entry 1: int 42
    entries = [struct.pack("<HHI", 8, 0, 0) + struct.pack("<HBBI", 8, 0, 0x03, 0),
               struct.pack("<HHI", 8, 0, 1) + struct.pack("<HBBI", 8, 0, 0x10, 42)]
    offs, data = [], b""
    for e in entries:
        offs.append(len(data))
        data += e
    table = b"".join(struct.pack("<I", o) for o in offs)
    head_size = 20 + len(cfg)
    start = head_size + len(table)
    type_chunk = struct.pack("<HHIBBHII", 0x201, head_size, start + len(data), 1, 0, 0, len(entries), start) + cfg + table + data
    spec_chunk = struct.pack("<HHIBBHI", 0x202, 16, 16 + 4 * len(entries), 1, 0, 0, len(entries)) + b"\0" * (4 * len(entries))
    tp, kp = string_pool(["string"]), string_pool(["app_name", "answer"])
    name = "com.example".encode("utf-16-le").ljust(256, b"\0")
    body = struct.pack("<I", 0x7F) + name + struct.pack("<IIIII", 288, 1, 288 + len(tp), 2, 0)
    rest = tp + kp + spec_chunk + type_chunk
    pkg = struct.pack("<HHI", 0x200, 288, 288 + len(rest)) + body + rest
    tbody = string_pool(["hello"]) + pkg
    return struct.pack("<HHII", 2, 12, 12 + len(tbody), 1) + tbody


class _Any(dict):
    """An index table where every reference is index 1 (decode has no DEX)."""

    def __getitem__(self, key):
        return 1


def main() -> None:
    out = sys.argv[1]
    dex, _ = db.build(db.base_spec())
    arsc = arsc_table()

    put(f"{out}/dex_pipeline", dex)
    # fixture_apk.py's DEX files: typed static values, field accesses and
    # duplicate-free multidex, for class_fields()/class_entry() and the rest.
    fx_dexes = [fx.dex(fx.classes1() + [fx.bad_class()]), fx.dex(fx.classes2())]
    for d in fx_dexes:
        put(f"{out}/dex_pipeline", d)
    put(f"{out}/apk", zip_of({"classes.dex": fx_dexes[0], "classes2.dex": fx_dexes[1], "resources.arsc": fx.arsc()}))

    for name, code in db.base_spec()["codes"].items():
        n_insns = struct.unpack_from("<I", code, 12)[0]
        put(f"{out}/decode", code[16:16 + 2 * n_insns])
    # insn_apk.py: every opcode, payloads, truncated payloads, rejected code.
    put(f"{out}/dex_pipeline", insn_apk.dex())
    for m in insn_apk.classes()[0]["direct"]:
        put(f"{out}/decode", m[4](fx._Index(*[_Any()] * 4)))
    for hexcode in ["0e00", "1200 0f00", "1a00 0000 0e00", "3200 0300 0e00 0e00", "2b00 0300 0000 0001 0100 0000 0000 0000 0000 0000"]:
        put(f"{out}/decode", bytes.fromhex(hexcode.replace(" ", "")))

    for edge in [b"hello", b"\xed\xa0\x80", b"\xed\xa1\x80\xed\xb0\x80", b"\xf0\x9f\x98\x80\xc0\x80", b"\xc3", b"\xe2\x82",
                 "ΣaΣ".encode()]:
        put(f"{out}/text", edge)

    put(f"{out}/apk", zip_of({"classes.dex": dex}))
    put(f"{out}/apk", zip_of({"resources.arsc": arsc}))
    put(f"{out}/apk", zip_of({"classes.dex": dex, "classes2.dex": dex, "resources.arsc": arsc}))
    # DEX selection/order edge cases: loose names, repeats, local header vs
    # central directory, duplicate classes.
    for mk in dc.CASES.values():
        put(f"{out}/apk", mk())
    # Classes defined more than once (in one DEX, across DEX files), and
    # their DEX files on their own.
    for mk in du.CASES.values():
        raw = mk()
        put(f"{out}/apk", raw)
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            for name in z.namelist():
                if name.endswith(".dex"):
                    put(f"{out}/dex_pipeline", z.read(name))
    # resources.arsc entries whose local header and central directory disagree.
    for mk in az.CASES.values():
        put(f"{out}/apk", mk())
    # Load errors (header checks, code androguard can't disassemble), string
    # indices and "->" in class names, dexobj_cases.py's TLS/intent/field shapes:
    # the APKs and their DEX files.
    for raw in [mk() for mk in sc.CASES.values()] + [mk() for mk in sg.CASES.values()] + [do.apk()]:
        put(f"{out}/apk", raw)
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            for name in z.namelist():
                if name.endswith(".dex"):
                    put(f"{out}/dex_pipeline", z.read(name))

    put(f"{out}/arsc", arsc)

    for x in (ab.manifest(), ab.layout(), ab.packed()):
        put(f"{out}/axml", x)
    put(f"{out}/apkzip", ab.synthetic_apk(dex))
    put(f"{out}/apkzip", ab.synthetic_apk(dex, signing=False))


if __name__ == "__main__":
    main()
