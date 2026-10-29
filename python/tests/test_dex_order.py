"""Which DEX files AnalyzeAPK loads, in what order, and with what bytes, on
synthetic zips (dex_order_cases.py): central directory order (classes10
before classes2), androguard's loose `^classes(\\d*).dex$` match, repeated
names, local header vs central directory as apkInspector resolves them,
duplicate classes (the DEX loaded last wins), and the tolerant load's
per-DEX skipping. No androguard needed: the goldens (dex_order_goldens.py) were
generated once from androguard 4.1.3 by scripts/gen_dex_order_goldens.py.
test_dex_order_parity.py checks the same cases live against androguard.
"""

import sys
from pathlib import Path

import pytest

import androguard_rs
import dex_order_cases as C
from androguard_rs.misc import AnalyzeAPK
from dex_order_goldens import DUPLICATE_EXTRAS, GOLDEN, TOLERANT

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "compat"))
import androguard_compat as compat  # noqa: E402


@pytest.fixture(scope="module", params=list(C.CASES))
def case(request, tmp_path_factory):
    raw = C.CASES[request.param]()
    path = tmp_path_factory.mktemp("dex_order") / f"{request.param}.apk"
    path.write_bytes(raw)
    return request.param, raw, str(path)


def test_analyze_apk_from_bytes(case):
    name, raw, _ = case
    assert C.outcome(lambda: C.snapshot(*AnalyzeAPK(raw, raw=True))) == GOLDEN[name]


def test_analyze_apk_from_path(case):
    name, _, path = case
    assert C.outcome(lambda: C.snapshot(*AnalyzeAPK(path))) == GOLDEN[name]


def test_facade_analyze_apk(case):
    """androguard_compat.analyze_apk (its DEX list is a stub, so the
    APK's get_dex_names() stands in for it)."""
    name, _, path = case

    def run():
        a, _, dx = compat.analyze_apk(path)
        return C.snapshot(a, list(a.get_dex_names()), dx)

    assert C.outcome(run) == GOLDEN[name]


def test_native_dex_names(case):
    name, raw, path = case
    g = GOLDEN[name]
    if g == ("raises",):
        for f in (lambda: androguard_rs.Apk(path), lambda: androguard_rs.Apk.from_bytes(raw)):
            with pytest.raises(ValueError):
                f()
        return
    assert androguard_rs.Apk(path).dex_names() == g["dex_names"]
    assert androguard_rs.Apk.from_bytes(raw).dex_names() == g["dex_names"]


def test_tolerant_load(case):
    """Apk(..., tolerant=True): skipped DEX in get_all_dex() order, then the
    classes of what loaded."""
    name, raw, path = case

    def load(rs):
        return rs.skipped_dex(), [(c.name, c.is_external()) for c in compat.Analysis(rs).get_classes()]

    assert C.outcome(lambda: load(androguard_rs.Apk.from_bytes(raw, tolerant=True))) == TOLERANT[name]
    assert C.outcome(lambda: load(androguard_rs.Apk(path, tolerant=True))) == TOLERANT[name]


@pytest.mark.parametrize("name", list(DUPLICATE_EXTRAS))
def test_duplicate_class_methods(name):
    """A class every DEX defines: the winner's methods, then each earlier
    definition's calling methods with their own get_xref_to()
    (test_dup_classes.py covers the rest)."""
    _, _, dx = AnalyzeAPK(C.CASES[name](), raw=True)
    assert C.duplicate_extras(dx) == DUPLICATE_EXTRAS[name]
