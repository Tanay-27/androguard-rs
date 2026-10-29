"""Parity check: spike vs androguard 4.1.3, for every DEX of every APK given.

For each classesN.dex it compares, line for line after sorting:
  insns    - every instruction's (method, offset, get_name(), get_output())
  edges    - every invoke xref (caller, callee, byte offset)
  classes  - class flags/superclass/interfaces, method name/descriptor/flags,
             field flags/name/type/repr(init value)

androguard runs one DEX at a time, so a big multi-DEX APK fits in memory.

usage: python parity.py --spike <path/to/spike> --out <dir> <apk> [<apk> ...]
       (run with a Python that has androguard 4.1.3 installed)
"""

import argparse
import os
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))


def sorted_lines(cmd: list[str]) -> list[bytes]:
    out = subprocess.run(cmd, check=True, capture_output=True).stdout
    return sorted(out.splitlines())


def compare(a: list[bytes], b: list[bytes]) -> tuple[list[bytes], list[bytes]]:
    sa, sb = set(a), set(b)
    return [x for x in a if x not in sb], [x for x in b if x not in sa]


def dex_entries(apk: str) -> list[str]:
    with zipfile.ZipFile(apk) as z:
        names = [n for n in z.namelist() if n.startswith("classes") and n.endswith(".dex") and "/" not in n]
    return sorted(names, key=lambda n: int(n[7:-4] or 1))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--spike", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("apks", nargs="+")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    py = sys.executable
    failures = 0
    checks = [("insns", "androguard_insns.py", 9), ("edges", "androguard_edges.py", 8), ("classes", "androguard_classes.py", 8)]
    totals = {k: 0 for k, _, _ in checks}
    header = " ".join(f"{k:>{w}s} {'diff':>5s}" for k, _, w in checks)
    print(f"{'apk':40s} {'dex':14s} {header}", flush=True)
    for apk in args.apks:
        name = os.path.basename(apk)
        with tempfile.TemporaryDirectory() as tmp:
            for entry in dex_entries(apk):
                with zipfile.ZipFile(apk) as z:
                    dex = os.path.join(tmp, entry)
                    with open(dex, "wb") as f:
                        f.write(z.read(entry))
                row = [f"{name[:40]:40s}", f"{entry:14s}"]
                for kind, ag_script, width in checks:
                    rust = sorted_lines([args.spike, kind, apk, entry])
                    ag = sorted_lines([py, "-I", os.path.join(HERE, ag_script), dex])
                    only_rust, only_ag = compare(rust, ag)
                    ndiff = len(only_rust) + len(only_ag)
                    totals[kind] += len(ag)
                    row += [f"{len(ag):>{width}d}", f"{ndiff:>5d}"]
                    if ndiff:
                        failures += 1
                        stem = os.path.join(args.out, f"{name}.{entry}.{kind}")
                        with open(stem + ".only_rust", "wb") as f:
                            f.write(b"\n".join(only_rust[:2000]))
                        with open(stem + ".only_androguard", "wb") as f:
                            f.write(b"\n".join(only_ag[:2000]))
                print(" ".join(row), flush=True)
    print(f"\ntotal: {totals['insns']:,} instruction lines, {totals['edges']:,} invoke edges, "
          f"{totals['classes']:,} class/method/field lines; {failures} DEX/check pairs with differences", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
