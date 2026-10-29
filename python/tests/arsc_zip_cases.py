"""Synthetic APKs whose resources.arsc entry is tampered with (local header
vs central directory), for test_arsc_zip.py: `Resources.from_apk()` must
read the bytes androguard's `APK.get_android_resources()` reads, i.e.
apkInspector's `ZipEntry.read("resources.arsc")` (local method and sizes,
central directory sizes when a local one is 0, a repeated name's last entry,
a later local header named resources.arsc replacing the entry's own), and
fail where it raises. Each table names a different package, so which bytes
were read shows. Goldens: arsc_zip_goldens.py, generated once from
androguard 4.1.3 by scripts/gen_arsc_zip_goldens.py.
"""

import hashlib

import apkbuild as b
from dex_order_cases import zip_raw


def table(pkg):
    return b.arsc_strings(pkg, [("app_name", pkg), ("title", "T")])


def _arsc(pkg, **kw):
    return dict(name=b"resources.arsc", data=table(pkg), **kw)


def _manifest():
    return {"name": b"AndroidManifest.xml", "data": b.manifest()}


def _junk_local(pkg):
    """A later entry whose local header says resources.arsc, stored, with the
    table's size: apkInspector reads resources.arsc with it."""
    n = len(table(pkg))
    return {"name": b"zz.bin", "local_name": b"resources.arsc", "data": b"junk", "store": "stored",
            "local_sizes": (n, n)}


CASES = {
    "plain": lambda: zip_raw([_manifest(), _arsc("com.plain")]),
    "absent": lambda: zip_raw([_manifest()]),
    # The local header's method wins: stored data the central directory calls deflate, and the reverse.
    "cd_deflate_local_stored": lambda: zip_raw([_manifest(), _arsc("com.ls", store="stored", cd_method=8)]),
    "cd_stored_local_deflate": lambda: zip_raw([_manifest(), _arsc("com.ld", cd_method=0)]),
    # Zero local sizes fall back to the central directory's; wrong central
    # directory sizes don't matter when the local ones are set; deflate
    # ignores a wrong declared uncompressed size.
    "local_sizes_zero": lambda: zip_raw([_manifest(), _arsc("com.lz", store="stored", local_sizes=(0, 0))]),
    "cd_sizes_wrong": lambda: zip_raw([_manifest(), _arsc("com.cw", store="stored", cd_sizes=(3, 3))]),
    "uncompressed_wrong": lambda: zip_raw([_manifest(), _arsc("com.uw", local_sizes=(None, 5), cd_sizes=(None, 5))]),
    # A repeated name: first position, last entry's bytes.
    "repeated": lambda: zip_raw([_manifest(), _arsc("com.first"), _arsc("com.second")]),
    # A later local header named resources.arsc replaces the entry's own
    # (which says deflate over stored bytes, so only that one reads).
    "junk_local": lambda: zip_raw([_manifest(), _arsc("com.junk", store="stored", local_method=8),
                                   _junk_local("com.junk")]),
    # Listed in the central directory, no readable local header: androguard raises.
    "missing_local": lambda: zip_raw([_manifest(), _arsc("com.ml", bad_local=True)]),
    "renamed_local": lambda: zip_raw([_manifest(), _arsc("com.rl", local_name=b"resources.arsx")]),
}


def outcome(f):
    try:
        return f()
    except Exception:
        return ("raises",)


def view(res, raw):
    """What the parsed table says: None, or (sha256 of the bytes read,
    package names, each package's get_public_resources())."""
    if res is None:
        return None
    pkgs = list(res.get_packages_names())
    return (hashlib.sha256(raw).hexdigest() if raw is not None else None, pkgs,
            [res.get_public_resources(p) for p in pkgs])
