"""Fail unless every wheel / sdist given carries the license files.

Wheels must have, under dist-info/licenses/: LICENSE (Apache-2.0) and NOTICE
(the project's), dex-bytecode-LICENSE (Apache-2.0) and
dex-bytecode-VENDORED.md (the vendored crate's license and modification
notice), and androguard-VENDORED.md; an sdist must contain
vendor/dex-bytecode/LICENSE and the same files under licenses/. Also checks
METADATA lists them as License-File and declares Apache-2.0.

usage: python scripts/check_dist_licenses.py dist/*.whl dist/*.tar.gz
"""

import sys
import tarfile
import zipfile

REQUIRED = ("LICENSE", "NOTICE", "dex-bytecode-LICENSE", "dex-bytecode-VENDORED.md", "androguard-VENDORED.md")


def check_wheel(path: str) -> list[str]:
    errors = []
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        meta = next((n for n in names if n.endswith(".dist-info/METADATA")), None)
        metadata = z.read(meta).decode() if meta else ""
        for req in REQUIRED:
            hits = [n for n in names if ".dist-info/licenses/" in n and n.endswith("/" + req)]
            if not hits:
                errors.append(f"{path}: no {req} under .dist-info/licenses/")
                continue
            body = z.read(hits[0])
            if req.endswith("LICENSE") and b"Apache License" not in body:
                errors.append(f"{path}: {hits[0]} is not the Apache-2.0 text")
            if f"License-File: licenses/{req}" not in metadata:
                errors.append(f"{path}: METADATA has no License-File for {req}")
        if "License-Expression: Apache-2.0" not in metadata:
            errors.append(f"{path}: METADATA has no License-Expression: Apache-2.0")
    return errors


def check_sdist(path: str) -> list[str]:
    with tarfile.open(path) as t:
        names = t.getnames()
    want = [n for n in names if n.endswith("/vendor/dex-bytecode/LICENSE")]
    errors = []
    if not want:
        errors.append(f"{path}: no vendor/dex-bytecode/LICENSE")
    for req in REQUIRED:
        if not any(n.endswith("/licenses/" + req) for n in names):
            errors.append(f"{path}: no licenses/{req} (wheels built from it would lack it)")
    return errors


def main() -> int:
    paths = sys.argv[1:]
    if not paths:
        print("no distributions given", file=sys.stderr)
        return 2
    errors = []
    for p in paths:
        if p.endswith(".whl"):
            errors += check_wheel(p)
        elif p.endswith(".tar.gz"):
            errors += check_sdist(p)
        else:
            errors.append(f"{p}: not a .whl or .tar.gz")
    for e in errors:
        print(e, file=sys.stderr)
    if not errors:
        print(f"license files present in {len(paths)} distribution(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
