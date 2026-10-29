"""Seed the cargo-fuzz corpora (fuzz/corpus/<target>/) from real APKs.

  dex_pipeline  every DEX under 64 KiB
  decode        individual methods' code (insns) bytes
  text          raw string_data bytes, plus MUTF-8 edge cases
  apk           a fresh zip around each small DEX, and around each small resources.arsc
  arsc          each resources.arsc (libFuzzer truncates past -max_len)

usage: python fuzz_seeds.py <out_corpus_dir> <apk> [<apk> ...]   (needs androguard)
"""

import hashlib
import io
import os
import sys
import zipfile

from loguru import logger

logger.disable("androguard")

from androguard.core.dex import DEX  # noqa: E402

MAX_DEX = 64 << 10
MAX_ARSC_IN_APK = 256 << 10


def put(dirpath: str, data: bytes) -> None:
    os.makedirs(dirpath, exist_ok=True)
    with open(os.path.join(dirpath, hashlib.sha1(data).hexdigest()), "wb") as f:
        f.write(data)


def main() -> None:
    out, apks = sys.argv[1], sys.argv[2:]
    for edge in [b"\xed\xa0\x80", b"\xed\xa1\x80\xed\xb0\x80", b"\xf0\x9f\x98\x80\xc0\x80", b"\xc3", b"\xe2\x82", "ΣaΣ".encode()]:
        put(f"{out}/text", edge)
    for apk in apks:
        with zipfile.ZipFile(apk) as z:
            dexes = [z.read(n) for n in z.namelist() if n.startswith("classes") and n.endswith(".dex")]
            arsc = z.read("resources.arsc") if "resources.arsc" in z.namelist() else None
        if arsc is not None:
            put(f"{out}/arsc", arsc)
            if len(arsc) <= MAX_ARSC_IN_APK:
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                    z.writestr("resources.arsc", arsc)
                put(f"{out}/apk", buf.getvalue())
        for raw in dexes:
            d = DEX(raw)
            codes = [m.get_code().get_bc().get_insn() for m in d.get_encoded_methods() if m.get_code() is not None]
            for c in codes[:: max(1, len(codes) // 300)]:
                put(f"{out}/decode", bytes(c))
            for s in list(d.get_strings())[:: max(1, len(d.get_strings()) // 200)]:
                put(f"{out}/text", s.encode("utf-8", "surrogatepass"))
            if len(raw) <= MAX_DEX:
                put(f"{out}/dex_pipeline", raw)
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                    z.writestr("classes.dex", raw)
                put(f"{out}/apk", buf.getvalue())


if __name__ == "__main__":
    main()
