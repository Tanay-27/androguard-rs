# CI, tests and wheel builds

Three GitHub Actions workflows live in `.github/workflows/`. All of them run
with read-only `contents` permission except the job that writes the GitHub
release.

## `ci.yml`: every push and pull request

| Job | What it runs |
|---|---|
| `rust` | `cargo build --release --locked`; `cargo test --workspace --exclude androguard-rs-py --release --locked`; `cargo clippy --workspace --all-targets --locked` |
| `python` | `maturin build --release` → checks the wheel's license files → installs it into a fresh Python 3.12 venv with `androguard==4.1.3`, `mutf8==1.1.0` and pytest → `pytest python/tests`; then the same wheel in a venv without androguard → `pytest python/tests` |
| `fuzz-smoke` | nightly: `cargo +nightly fuzz build -a`, then each of `dex_pipeline`, `decode`, `text`, `apk`, `arsc`, `axml`, `apkzip` for 60 s |

Notes:

- `androguard-rs-py` is excluded from `cargo test` because the PyO3 extension
  only links under maturin. It has no Rust tests; pytest covers it.
- Clippy runs without `-D warnings`: its warnings show up in the log but
  don't fail the build. `cargo fmt --check` isn't run.
- Without APKs (`PARITY_APKS` unset), pytest runs everything synthetic, each
  against goldens generated once from androguard 4.1.3 + mutf8 1.1.0 by a
  script in `scripts/`:

  | Tests | Inputs | Goldens from |
  |---|---|---|
  | `test_mutf8`, `test_text` | string decoding and text transforms | (self-contained) |
  | `test_model_hostile` | crafted DEX files | (self-contained) |
  | `test_resources` (synthetic and mutant parts) | synthetic tables | live androguard |
  | `test_apk_native` | the native APK/AXML side on synthetic zips | `apk_goldens.py` |
  | `test_dex_order` | which DEX files `AnalyzeAPK` and the tolerant load read, in what order and with what bytes, on `dex_order_cases.py`'s tampered multi-DEX zips | `scripts/gen_dex_order_goldens.py` |
  | `test_insn` | the Instruction API on `insn_apk.py`'s every-format DEX | `scripts/gen_insn_goldens.py` |
  | `test_standalone`, `test_compat` | every native query and every Analysis-object attribute on `fixture_apk.py`'s two-DEX APK | `scripts/gen_fixture_goldens.py` |
  | `test_dup_classes` | classes defined more than once, on `dup_cases.py`'s APKs | `scripts/gen_dup_goldens.py` |
  | `test_arsc_zip` | `Resources.from_apk()` on tampered zips | `scripts/gen_arsc_zip_goldens.py` |
  | `test_strict` | load errors (`DEX()` header, map list and sections, `Analysis.add()`, `create_xref()`): `AnalyzeAPK` and a hand-written `DEX()`/`Analysis.add()` loop on `strict_cases.py` | `scripts/gen_dexobj_goldens.py` |
  | `test_sig` | signed const-string/jumbo indices, `->` in class names, on `sig_cases.py` | `scripts/gen_dexobj_goldens.py` |
  | `test_dexobj` | the per-DEX and analysis objects (`ClassDefItem`, `EncodedMethod`, `EncodedField`, `find_methods`, xrefs, `repr()`s), and a per-method instruction walk, on `dexobj_cases.py` | `scripts/gen_dexobj_goldens.py` |
  | `test_arsc_configs` | `ARSCParser.get_resolved_res_configs()`'s `ARSCResTableConfig` objects (type, `vars()`, `repr()`, `hash()`, methods) on `arsc_config_cases.py`'s tables | `scripts/gen_arsc_config_goldens.py` |
  | `test_handles` | per-query handles: every route to a method, field, class, code item or instruction gives equal, hash-equal objects; nothing kept on the Python side; on `fixture_apk.py`'s APK | (self-contained) |
  | `test_layout` | androguard 4.1.3's module paths under `androguard_rs`, the same modules as the short paths; `core.androconf` against androguard's when installed | (self-contained) |

  With androguard installed, the `*_parity` modules also check those cases
  live against it (`test_strict_parity` also finds the nesting at which
  `RecursionError` comes, for several caller stack depths). Without androguard, `python/tests/conftest.py` skips the
  modules that import it and the goldens-based tests still run. The
  real-APK tests in `test_parity`, `test_compat_parity`, `test_apk_parity`,
  `test_dex_order_parity`, `test_model`, `test_invalid`, `test_insn_parity`,
  `test_dexobj_parity` and `test_resources` skip with "set PARITY_APKS".
- Fuzz seeds come from `scripts/ci_fuzz_seeds.py`: synthetic DEX files and
  APKs from the test builders (`dexbuild.py`, `fixture_apk.py`,
  `dex_order_cases.py`, `dup_cases.py`, `arsc_zip_cases.py`, ...), a minimal
  `resources.arsc`, and MUTF-8 edge cases. They're generated in the job, so
  nothing binary is committed. If a target crashes, the job fails and
  uploads `fuzz/artifacts/` as the `fuzz-artifacts` artifact. Replay one
  with `cargo +nightly fuzz run -a <target> <file>`.

## Running the tests locally

```sh
python -m venv .venv && . .venv/bin/activate
pip install "maturin>=1.15,<2" pytest "androguard==4.1.3" "mutf8==1.1.0"
(cd python && maturin develop --release)
pytest python/tests                                        # synthetic + goldens
PARITY_APKS=a.apk:b.apk pytest python/tests                # plus live parity on your APKs
PARITY_LARGE_APKS=big.apk pytest python/tests/test_resources.py   # resources only
cargo test --workspace --exclude androguard-rs-py --release
```

The parity tests compare against androguard 4.1.3 with `mutf8` 1.1.0;
other versions give different output by design. Any APKs work; none are
committed.

## `parity.yml`: optional full parity suite

Runs every Monday and on manual dispatch, and **is skipped unless the
repository variable `PARITY_APK_URLS` is set**. It downloads the APKs,
builds and installs the wheel next to androguard 4.1.3 and mutf8 1.1.0,
and runs `pytest python/tests` with `PARITY_APKS` and `PARITY_LARGE_APKS`
set. No APK is ever committed.

Configure under **Settings → Secrets and variables → Actions → Variables**:

- `PARITY_APK_URLS` (required): https URLs of APKs, separated by spaces or
  newlines, for example publicly downloadable open-source apps.
- `PARITY_APK_SHA256` (optional, recommended): `sha256sum`-format lines,
  `<hex digest>  <file name>`, where the file name is the last path
  component of the URL. When set, every download must be listed and match.
- `PARITY_LARGE_MIN_MB` (default `100`): APKs larger than this go to
  `PARITY_LARGE_APKS`, which only the resources tests use. androguard's
  `AnalyzeAPK` needs roughly 73x the DEX size in RAM.
- `PARITY_RUNNER` (default `ubuntu-latest`): a larger runner label, if the
  corpus needs more memory or time. The job timeout is 6 h.

## `release.yml`: wheels on `v*` tags and manual dispatch

| Job | What it does |
|---|---|
| `version` | On a tag, fails unless `vX.Y.Z` matches the version in both `python/pyproject.toml` and `python/Cargo.toml` |
| `build-linux` | `PyO3/maturin-action`, `manylinux: auto`, for x86_64 and aarch64 (aarch64 is cross-compiled) |
| `build-macos` | macOS arm64 wheel |
| `sdist` | source distribution |
| `test` | installs the Linux x86_64 and macOS wheels and runs the synthetic pytest suite |
| `github-release` | tags only: creates the release (or updates an existing one) with all wheels, the sdist and `SHA256SUMS` |

The crate builds with `abi3-py310`, so each platform gets a single
`cp310-abi3` wheel that works on Python 3.10 and later.

Every wheel and the sdist carry the project's `LICENSE` (Apache-2.0) and
`NOTICE`, the vendored `dex-bytecode` Apache-2.0 `LICENSE` and its
modification notice (`VENDORED.md`), and the androguard data notice, under
`*.dist-info/licenses/`. They get there through `license-files` in
`python/pyproject.toml` and `python/licenses/`.
`scripts/check_dist_licenses.py` checks every built artifact for them.

To cut a release, bump `version` in both `python/pyproject.toml` and
`python/Cargo.toml`, commit, then `git tag vX.Y.Z && git push origin vX.Y.Z`.

## Installing a release

Install a wheel from the GitHub release, pinned alongside the androguard
and mutf8 versions output parity is defined against, and check it against
`SHA256SUMS`:

```sh
gh release download v0.1.3 --repo Tanay-27/androguard-rs --pattern '*.whl' --pattern SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
pip install ./androguard_rs-0.1.3-*.whl
python -c "import androguard_rs; print(androguard_rs.__file__)"
```

## Not automated

- The aarch64 Linux wheel is built and license-checked but not executed in
  CI (no arm64 runner assumed). If you have one, add it to the `test` matrix
  in `release.yml`.
- Real-APK fuzz seeds (`scripts/fuzz_seeds.py`) and long fuzz campaigns
  stay local. CI only runs a 60 s smoke test per target.
