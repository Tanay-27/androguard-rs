# The APK side: `androguard_rs.apk`, `.axml`, `.misc`

Native replacements for androguard 4.1.3's `APK`, `AXMLPrinter`,
`AnalyzeAPK` and a few small helpers, so callers don't need androguard
installed. Only `lxml` stays a dependency (the manifest and `AXMLPrinter`
trees are lxml elements, as in androguard).

| androguard 4.1.3 | drop-in |
|---|---|
| `androguard.core.apk.APK(filename, raw=False, ...)` | `androguard_rs.core.apk.APK` |
| `androguard.core.apk.FileNotPresent` / `BrokenAPKError` / `Error` | `androguard_rs.core.apk.FileNotPresent` / ... |
| `androguard.core.axml.AXMLPrinter` / `format_value` | `androguard_rs.core.axml.AXMLPrinter` / `format_value` |
| `androguard.misc.AnalyzeAPK(_file, session=None, raw=False)` | `androguard_rs.misc.AnalyzeAPK` |
| `androguard.util.set_log(level)` | `androguard_rs.util.set_log` (no-op) |
| `androguard.core.api_specific_resources.load_permission_mappings(level)` / `load_permissions(level)` | `androguard_rs.core.api_specific_resources.load_permission_mappings` / `load_permissions` (data vendored, Apache-2.0) |
| `androguard.core.androconf.load_api_specific_resource_module(name, api)` | `androguard_rs.core.androconf.load_api_specific_resource_module` |

`androguard_rs.core.apk` is the module `androguard_rs.apk` (likewise
`core.axml`/`axml`, `core.api_specific_resources`/`api_specific_resources`),
so callers rename `androguard` to `androguard_rs` in the import. `python/compat/androguard_compat.analyze_apk(path)`
now returns the native `APK` too (`native_apk=False` for androguard's), and
`APK.get_androguard_apk()` builds androguard's own object when a caller
needs something not covered here.

## How it's built

- **Zip** (`core/src/zipapk.rs`, `androguard_rs.ApkFile`): androguard 4.1.3
  reads APKs with apkInspector's `ZipEntry`, not `zipfile`, and its rules are
  kept: the EOCD is the last `PK\5\6`; the central directory is read until an
  entry lacks `PK\1\2`; names are UTF-8 with bad bytes dropped; a repeated
  name keeps its first position and last entry; local headers are read up
  front and keyed by their own name; extraction uses the local header's
  method/lengths and its sizes unless one is 0; method 8 inflates to the end
  of the stream whatever the declared size; other methods are stored or
  deflate depending on the sizes and on whether the data inflates cleanly.
  A path is read through seeks; `bytes` are used in place
  (`APK(data, raw=True)._APK__raw is data`).
- **DEX loading** (`core/src/apk.rs`, `androguard_rs.Apk`): the files and
  order of `AnalyzeAPK`'s `a.get_all_dex()`, i.e. `get_file(name)` for each
  name of `get_dex_names()`: `get_files()` (the zip reader's namelist, so
  central directory order, a repeated name at its first position) filtered
  by `re.match(r"^classes(\d*).dex$", name)`. The match is reproduced
  exactly: the `.` is unescaped (`classesXdex`, `classes3odex` match), `$`
  also matches before a final newline, and `\d` is Python's Unicode decimal
  digit (table generated from Python 3.12.8 by `scripts/gen_py_decimal.py`).
  Every DEX is read with the same zip reader, so its bytes are
  `get_file()`'s, tampered zips included; an entry whose local header is
  missing or named differently is `FileNotPresent` in androguard and an
  error here, `tolerant=True` or not.
  `Apk.dex_names()` gives that list, and `androguard_rs.misc.AnalyzeAPK`,
  `analyze_apk()` and the tolerant load all use this order. It
  decides which definition of a class defined in several DEX files wins
  (the one loaded last, as androguard's `Analysis.add()` overwrites) and
  where a class sits in `get_classes()` (its first appearance).
- **Binary XML** (`core/src/axml.rs`, `androguard_rs.AxmlParser`): a port
  of `AXMLParser` (chunk walk, "dummy data" header scan, `StringBlock` via
  `arsc::Pool`, resource-map attribute names with androguard's system table
  in `core/src/axml_attrs.rs`, and the same failures). `AXMLPrinter` itself
  is androguard's Python code over that parser, so `_fix_name`,
  `_fix_value`, `nsmap` (iterated from a Python `set`, so xmlns order is the
  same) and lxml serialization are androguard's.
- **Signing block**: `parse_v2_v3_signature()` and the v2/v3 signer parsing,
  natively, including what stays cached after an error (flags set to False
  before a failure stay False; a signer list that failed half-way is
  returned by later calls).
- **Manifest queries**: androguard's `APK` methods, copied, over the lxml
  tree.

## What's covered

| API | Notes |
|---|---|
| `AnalyzeAPK(path)` / `AnalyzeAPK(data, raw=True)` | `(APK, [androguard_rs.dex.DEX], Analysis)`; raises at load what androguard's raises (header errors, the first method `Analysis.add()` can't disassemble); `tolerant=True` (not androguard) loads anyway |
| `APK(path)` / `APK(data, raw=True)` | `_APK__raw` is the APK's bytes |
| `get_package()` | `""` without a usable manifest, as androguard |
| `get_activities/services/receivers/providers()` | package-prefixed names (`_format_value`), document order |
| `get_min_sdk_version()`, `get_target_sdk_version()` | `str` or `None` |
| `get_permissions()` | `list(set(...))`, as androguard |
| `get_android_manifest_xml()` | the same lxml element every call (`id()` stable); `None` if the manifest is missing or invalid |
| `find_tags`, `find_tags_from_xml`, `get_value_from_tag`, `get_attribute_value`, `_format_value`, `get_main_activity`, `get_string_resources(package)` | over the same lxml tree (`xpath`, `findall(..., nsmap)`, `getchildren`, `etree.tostring` work) |
| `is_signed()`, `is_signed_v1/v2/v3()`, `get_certificates_v1/v2/v3()` | see "Differences" |
| `get_files()` | central directory order, new list per call |
| `get_file(name)` | `FileNotPresent` when missing |
| `a.zip.read(name)` | the same bytes as `get_file()` |
| `get_all_dex()` | the files and order `AnalyzeAPK` loads |
| `get_android_resources()` | `androguard_rs.Resources` behind androguard's `ARSCParser` methods ([`resources-api-map.md`](resources-api-map.md)) |
| `AXMLPrinter(raw).get_xml()` / `get_xml_obj()` | byte-identical |
| `set_log(level)` | no-op |
| `load_permission_mappings(sdk)` | vendored data |

A tolerant load, `androguard_rs.Apk(path, tolerant=True)` /
`Apk.from_bytes(data, tolerant=True)`, skips a DEX androguard's `DEX()`
rejects with "Not a DEX file, Header too small." or "This is not a DEX
file! Wrong endian tag: ..." and lists it in `skipped_dex()`, for callers
that load each DEX of `get_all_dex()` themselves and skip those two
errors.

Not provided: the decompiler. `androguard_rs.decompiler` exists only for
its import side effect (`sys.setrecursionlimit(5000)`, as
`androguard.decompiler`'s import); see `docs/dex-api-map.md`.

## Differences from androguard 4.1.3

All checked by `python/tests/test_apk_parity.py` on real APKs
(`PARITY_APKS`):

- `get_certificates_v1()` returns each v1 signature's PKCS#7 file
  (`META-INF/*.RSA|DSA|EC` with a matching `.SF`), unverified. androguard
  returns the signer certificate only for a signature that verifies. Same
  count for a validly signed APK.
- `get_certificates_v2/v3()` return DER `bytes` (androguard: lazily parsed
  `asn1crypto` certificates). They raise `ValueError` exactly where
  `Certificate.load()` would (outer header checked the asn1crypto way;
  differential-tested on 200,000 mutated headers).
- `find_tags()` and what's built on it (`get_activities()`, ...,
  `get_attribute_value()` when several tags match) are in document order.
  androguard puts lxml elements in a `set`, i.e. memory-address order, which
  differs between two androguard runs.
- Exception types: parser failures are `androguard_rs.AxmlError`, zip and
  signing-block failures `androguard_rs.ApkError` (or `BrokenAPKError`
  where androguard raises that, and androguard's own `struct.error` for a
  signing block cut short), resources `ResourcesError`. Code that
  catches `Exception` behaves the same.
- Limits on hostile input, where androguard runs away: binary XML over
  64 MiB, more than 1024 open namespace mappings, or more than 256 MiB of
  strings handed out; a chunk that would make androguard loop forever (a
  scanned header whose end points back before it); a zip entry inflating
  past 256 MiB; more than 2^20 zip entries; a signer block over 16 MiB.
- `APK()` doesn't load androguard's AOSP permission lists (nothing here uses
  them) but does `int()` the SDK versions as that load does, so a
  non-numeric one still raises `ValueError`.
- Anything else on `APK` raises `NotImplementedError` (counted in
  `androguard_rs.apk.APK_GAPS`).

## Size caps and well-formed APKs

The DEX loader caps each DEX at 256 MiB and all of them at 2 GiB. A
deflated entry inflates to the end of its stream whatever it declares (as
in androguard), so the caps are enforced while inflating: a read stops at
256 MiB or at what is left of the total, whichever is smaller, and the
running total is checked after each read. Real apps' DEX files are
typically a few tens of MiB each, so the caps sit well above them. A DEX over a cap fails the APK even
with `tolerant=True` (tolerance only skips androguard's two header errors).
The zip reader's per-entry cap is the same 256 MiB, and AXML's 64 MiB is
two orders of magnitude above real manifests and layouts.

## Memory

androguard's `APK()` keeps the whole APK in memory; `androguard_rs.apk.APK`
opened from a path reads entries through seeks, so `APK()` plus
`AXMLPrinter` over every XML file stays at a few tens of MiB regardless of
the APK's size.
