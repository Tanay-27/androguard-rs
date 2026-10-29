# androguard-rs

A fast, memory-bounded drop-in replacement for the APK, DEX, `Analysis`,
binary XML (AXML) and `resources.arsc` (ARSC) APIs of
[androguard](https://github.com/androguard/androguard) **4.1.3**, written in
Rust with a Python package (`androguard_rs`, via PyO3).

**Output is byte-identical to androguard 4.1.3**: instruction text,
cross-references, class metadata, manifest/AXML output, resource queries,
and the exceptions raised (type, args and `str()`), with DEX strings decoded
as `mutf8` 1.1.0 decodes them.

## Why

androguard turns all of an APK's bytecode into Python objects up front: on
the order of 150 bytes per decoded instruction, plus a tuple or set for every
cross-reference, which adds up to tens of times the DEX size in RAM. Large
multi-DEX apps can need many GiB for `AnalyzeAPK`.

androguard-rs reads the DEX bytes in place, decodes instructions only when
asked, and stores cross-references as flat integer arrays. The Python
objects androguard callers walk (`ClassAnalysis`, `MethodAnalysis`,
`EncodedMethod`, `Instruction`, ...) are created lazily and kept in small
bounded caches, so memory stays close to the size of the DEX files
themselves. Run `spike stats <apk>` (below) to measure load time and
counts on your own APKs.

## Install

Prebuilt wheels (Linux x86_64/aarch64 manylinux, macOS arm64; abi3, Python
3.10+) and an sdist are attached to each
[GitHub release](https://github.com/Tanay-27/androguard-rs/releases), with a
`SHA256SUMS` file:

```sh
gh release download v0.1.0 -R Tanay-27/androguard-rs -p '*.whl' -p SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
pip install androguard_rs-*.whl
```

From source (Rust 1.85+ for edition 2024, and maturin):

```sh
pip install "maturin>=1.15,<2"
cd python && maturin develop --release     # into the active venv
```

The only runtime dependency is `lxml` (the manifest and `AXMLPrinter` trees
are lxml elements, as in androguard). androguard itself is not needed.

## Usage

Swap the imports:

| androguard 4.1.3 | androguard-rs |
|---|---|
| `from androguard.misc import AnalyzeAPK` | `from androguard_rs.misc import AnalyzeAPK` |
| `from androguard.core.apk import APK` | `from androguard_rs.apk import APK` |
| `from androguard.core.axml import AXMLPrinter` | `from androguard_rs.axml import AXMLPrinter` |
| `from androguard.core.dex import DEX, Instruction11n, ...` | `from androguard_rs.dex import DEX, Instruction11n, ...` |
| `from androguard.core.analysis.analysis import Analysis` | `from androguard_rs.analysis import Analysis` |
| `from androguard.util import set_log` | `from androguard_rs.util import set_log` (no-op) |
| `androguard.core.api_specific_resources.load_permission_mappings` | `androguard_rs.api_specific_resources.load_permission_mappings` |

```python
from androguard_rs.misc import AnalyzeAPK

a, d, dx = AnalyzeAPK("app.apk")          # APK, [DEX], Analysis
print(a.get_package(), a.get_permissions())
for ca in dx.find_classes(r"Lcom/example/.*"):
    for ma in ca.get_methods():
        if ma.is_external():
            continue
        for ins in ma.get_method().get_instructions():
            print(ins.get_name(), ins.get_output())
        for _cls, caller, offset in ma.get_xref_from():
            print("  called from", caller.class_name, caller.name, hex(offset))
```

Building the analysis yourself works as in androguard:

```python
from androguard_rs.apk import APK
from androguard_rs.dex import DEX
from androguard_rs.analysis import Analysis

a = APK("app.apk")
dx = Analysis()
for raw in a.get_all_dex():
    dx.add(DEX(raw))
dx.create_xref()
```

`AXMLPrinter(raw).get_xml()` / `get_xml_obj()` and
`APK.get_android_resources()` (an `ARSCParser` backed by
`androguard_rs.Resources`) behave as androguard's.

### Native API

Below the drop-ins, `androguard_rs.Apk(path)` (or `Apk.from_bytes(data)`)
builds the whole-APK index once, with the GIL released, and answers queries
as plain Python values:

- `callers(sig)`, `callees(sig)`: invoke cross-references as
  `(signature, byte offset)`;
- `bytecode(sig)`: `(offset, get_name(), get_output())` per instruction,
  as `get_instructions_idx()` gives; raises `androguard_rs.InvalidInstruction`
  exactly where androguard does; `has_code(sig)`, `instructions(sig)`;
- `class_info(descriptor)`: access flags, superclass, interfaces, methods,
  fields and `repr()` of static initial values;
- `classes()`, `class_methods(name)`, `class_fields(name)` (typed
  `init_value.value`), `xref_from(sig)` / `xref_to(sig)`, `hierarchy()`,
  `const_strings()`, and per-class lookups (`class_count()`,
  `classes_slice()`, `class_entry()`, `class_hierarchy()`): androguard's
  `dx.get_classes()` model, external classes and methods included, in the
  same order;
- `methods_using_string(needle)` (`dx.get_strings()` xrefs) and
  `search_instruction_text(needles)` (methods any one of whose lower-cased
  instruction outputs contains a needle; parallel, nothing cached);
- `stats()`, `dex_names()`, `skipped_dex()`.

Signatures look like `Lcom/foo/Bar;->baz(ILjava/lang/String;)V`.

`androguard_rs.Resources(arsc_bytes)` (or `Resources.from_apk(path)`)
provides `ARSCParser`'s `get_packages_names()`, `get_public_resources()`,
`get_resolved_strings()`, `get_resolved_res_configs()`,
`get_resource_xml_name()`, `get_string()` and `get_string_resources()`,
with androguard's results and errors (as `ResourcesError`).

One extension that androguard doesn't have:
`androguard_rs.dex.DEX.get_ssl_candidate_methods()` returns the methods that
may implement or weaken TLS validation (named `checkServerTrusted`, `verify`
or `onReceivedSslError`, or using `AllowAllHostnameVerifier`,
`ALLOW_ALL_HOSTNAME_VERIFIER` or `SSLCertificateSocketFactory.getInsecure`).
It is a cheap superset to run slower per-method checks on.

More detail:

- [`docs/apk-api-map.md`](docs/apk-api-map.md): `APK`, `AXMLPrinter`,
  `AnalyzeAPK`, the zip reader and the DEX load order;
- [`docs/instruction-api.md`](docs/instruction-api.md): the `Instruction`
  classes and their quirks;
- [`docs/resources-api-map.md`](docs/resources-api-map.md): `Resources`
  vs `ARSCParser`;
- [`docs/ci.md`](docs/ci.md): CI, tests, releases.

## Differences from androguard 4.1.3

- **Loading fails as androguard's does.** `AnalyzeAPK` raises on a DEX that
  androguard's `DEX()` header checks reject (short file, wrong or
  byte-swapped endian tag, wrong magic, bad Adler-32 checksum, wrong header
  size, too many type/proto ids) and on the first method `Analysis.add()`
  can't disassemble, in androguard's order and with its exception.
  `AnalyzeAPK(..., tolerant=True)` / `Apk(path, tolerant=True)` (not
  androguard) instead skip a DEX rejected with "Header too small" or "Wrong
  endian tag" (listed in `skipped_dex()`) and raise `InvalidInstruction`
  only when the undecodable method's code is asked for.
- **`get_certificates_v1()`** returns each v1 signature's PKCS#7 file
  unverified (androguard returns the signer certificate only for a
  signature that verifies); `get_certificates_v2/v3()` return DER `bytes`
  instead of `asn1crypto` objects.
- **Set-ordered results** (`find_tags()` and what's built on it) come in
  document order; androguard's order depends on memory addresses and isn't
  stable between runs. Xref results are sets in both.
- **Exception types**: parse failures raise `androguard_rs.AxmlError`,
  `ApkError`/`BrokenAPKError` or `ResourcesError` where androguard raises
  assorted internal errors.
- **Static values that are arrays or annotations**: androguard prints an
  object `repr` with a memory address; androguard-rs prints `at 0x0>`.
- **Not implemented**: the decompiler, sessions, and androguard APIs outside
  the ones above. An unimplemented attribute of a supported object raises
  `NotImplementedError` naming it (counted in `GAPS` / `APK_GAPS`); one
  androguard's object doesn't have either raises `AttributeError`, as in
  androguard.
- **Versions**: only 4.1.3's behaviour is implemented. 4.1.4 is equivalent
  on the DEX side (it changed only `get_information()` register mapping and
  `show()` formatting), but its resources parser differs on unusual tables
  (sparse and compact entries, unterminated strings, junk between chunks);
  the places to change are marked "4.1.4:" in `core/src/arsc.rs`.
- **String decoding follows `mutf8` 1.1.0**, the version an unpinned
  androguard 4.1.3 install resolves to; 1.0.6 decodes characters beyond
  plane 1 differently. Pin both `androguard` and `mutf8` when comparing.
- **Python-version tables**: `str.lower()`, `isprintable()` and `\d` are
  reproduced with tables generated from Python 3.12
  (`scripts/gen_py_lower.py`, `gen_py_printable.py`, `gen_py_decimal.py`).

## Limits on hostile input

APKs are untrusted input: a malformed file must produce an error, never a
panic, a hang or an unbounded allocation.

- Each DEX entry is capped at 256 MiB and all DEX entries together at
  2 GiB, enforced while inflating (a deflated entry inflates to the end of
  its stream whatever it declares, as in androguard).
- Zip: at most 2^20 entries, 256 MiB per entry; signing-block signers over
  16 MiB are rejected.
- Binary XML: 64 MiB per document, 1024 open namespace mappings, 256 MiB
  of strings handed out; chunks that would make androguard loop forever
  are rejected.
- `resources.arsc`: 256 MiB decompressed, 64 MiB per
  `get_public_resources()` document, 256 MiB of decoded strings per query.
- Class_defs sharing one `class_data` (only in crafted files) share their
  parsed data and search results, so cost doesn't grow quadratically.

These sit far above what real apps need. androguard itself has no such
limits.

## How parity is tested

- **Synthetic fixtures with goldens** (`python/tests/*_cases.py`,
  `fixture_apk.py`, `insn_apk.py`, `apkbuild.py`, `arscbuild.py`): DEX,
  APK, AXML and ARSC files built in Python to cover every instruction
  format, load error, duplicate-class layout, string-index corner and
  resource-table feature. Goldens are generated from androguard 4.1.3 +
  mutf8 1.1.0 by the `scripts/gen_*_goldens.py` scripts, so these tests run
  without androguard.
- **Live parity against androguard** (`test_*_parity.py`, `test_model.py`,
  `test_resources.py`, `test_invalid.py`, ...): with androguard installed,
  the same cases are compared live; with `PARITY_APKS` set, every class,
  method, instruction, xref, field, manifest query, zip entry, XML file and
  resource of each listed APK is compared exactly against androguard's
  `AnalyzeAPK`, `APK`, `AXMLPrinter` and `ARSCParser`.
- **Differential fuzzing** of the decoder (mutated method bytecode vs
  androguard's `LinearSweepAlgorithm`, errors included), of string decoding
  (random bytes vs the `mutf8` C extension) and of resource tables (mutants
  vs `ARSCParser`).
- **Text dumps** for large APKs: `scripts/parity.py` compares
  `spike`'s instruction, xref and class dumps with androguard's, one DEX at
  a time.

```sh
# venv with androguard 4.1.3 + mutf8 1.1.0, and this package (maturin develop)
pytest python/tests                                      # synthetic + goldens + live
PARITY_APKS=a.apk:b.apk pytest python/tests              # plus real APKs
python scripts/parity.py --spike ./target/release/spike --out /tmp/parity a.apk b.apk
```

Without androguard installed, `pytest python/tests` runs the goldens-based
tests and skips the live ones.

## Fuzzing

Coverage-guided, with `cargo-fuzz` (nightly, AddressSanitizer, overflow
checks). Targets in `fuzz/fuzz_targets/`:

| Target | Input |
|---|---|
| `dex_pipeline` | arbitrary bytes as a DEX, through every query and the per-DEX views |
| `decode` | arbitrary method code; also checks the decoders agree on validity and instruction boundaries |
| `text` | string decoding and text transforms |
| `apk` | arbitrary zips through the bounded loader, index and resources |
| `apkzip` | arbitrary bytes as an APK, read entry by entry, with the v2/v3 signing block |
| `arsc` | arbitrary bytes as `resources.arsc`, through every resources query |
| `axml` | arbitrary bytes as binary XML, through every accessor `AXMLPrinter` uses |

```sh
cargo install cargo-fuzz
python scripts/ci_fuzz_seeds.py fuzz/corpus                  # synthetic seeds
python scripts/fuzz_seeds.py fuzz/corpus <apk> [<apk> ...]   # optional: seeds from your APKs (gitignored)
cargo +nightly fuzz run -a decode fuzz/corpus/decode -- -max_len=65536 -rss_limit_mb=2048 -timeout=10
```

Mutation fuzzing on stable (`spike fuzz`, overflow checks on) mutates real
DEX files (header table sizes and offsets, random bytes, bit flips,
truncation) and runs each through parse, index, class metadata and
bytecode text:

```sh
cargo build --profile fuzz -p spike
./target/fuzz/spike fuzz <apk> classes2.dex 100000 <seed> /tmp/fuzz-out
./target/fuzz/spike replay /tmp/fuzz-out/<file>.dex
```

CI runs every coverage-guided target for a short smoke run on synthetic
seeds.

## Layout

| Path | What |
|---|---|
| `core/` | Rust library: zip reader, DEX reader, whole-APK index, AXML, ARSC, androguard-4.1.3-compatible rendering |
| `python/` | PyO3 module and the `androguard_rs` package (drop-ins, tests) |
| `python/compat/androguard_compat.py` | androguard-compatible `Analysis` objects (shipped as `androguard_rs._analysis`) |
| `spike/` | CLI: stats, parity dumps, mutation fuzzer |
| `fuzz/` | cargo-fuzz targets |
| `vendor/dex-bytecode/` | instruction decoder, vendored from androguard/dex-bytecode and modified for 4.1.3 parity (see its `VENDORED.md`) |
| `scripts/` | androguard-side dumps, golden generators, fuzz seed generators, parity driver |

```sh
cargo build --release
./target/release/spike stats app.apk      # build the index, print timings and counts
cargo test --workspace --exclude androguard-rs-py --release
```

## Known gaps

- A DEX that androguard's `DEX()` rejects past its header checks (a broken
  map list or item), or whose try/catch tables make `Analysis.add()` fail,
  isn't failed the same way.
- Id tables are read from the header and string_data offsets aren't
  checked against the map list (androguard reads both through the map);
  they agree on every valid DEX.
- Field read/write and `new-instance`/`const-class` cross-references are
  not indexed as xrefs.
- A method whose code runs past the end of the DEX is skipped; androguard
  reads what's there.

## License

Apache License 2.0, see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

androguard-rs reimplements behaviour of androguard 4.1.3 (Apache-2.0) and
includes data and Python code derived from it (see
[`python/licenses/androguard-VENDORED.md`](python/licenses/androguard-VENDORED.md)),
and a modified copy of [dex-bytecode](https://github.com/androguard/dex-bytecode)
(Apache-2.0, see [`vendor/dex-bytecode/VENDORED.md`](vendor/dex-bytecode/VENDORED.md)).
It is not affiliated with the androguard project.
