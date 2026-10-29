"""strict_cases.py live against androguard 4.1.3 (test_strict.py checks the
same against stored goldens without androguard)."""

import logging

import pytest

pytest.importorskip("androguard")

from loguru import logger  # noqa: E402

logger.disable("androguard")

from androguard.core.analysis.analysis import Analysis as AgAnalysis  # noqa: E402
from androguard.core.apk import APK as AgAPK  # noqa: E402
from androguard.core.dex import DEX as AgDEX  # noqa: E402
from androguard.misc import AnalyzeAPK as AgAnalyzeAPK  # noqa: E402

import strict_cases as K  # noqa: E402
from androguard_rs.analysis import Analysis  # noqa: E402
from androguard_rs.apk import APK  # noqa: E402
from androguard_rs.dex import DEX  # noqa: E402
from androguard_rs.misc import AnalyzeAPK  # noqa: E402


@pytest.fixture(autouse=True)
def _quiet():
    logging.disable(logging.WARNING)
    yield
    logging.disable(logging.NOTSET)


@pytest.mark.parametrize("name", list(K.CASES))
def test_live(name):
    raw = K.CASES[name]()
    assert K.analyze(AnalyzeAPK, raw) == K.analyze(AgAnalyzeAPK, raw)
    assert K.manual(APK, DEX, Analysis, raw) == K.manual(AgAPK, AgDEX, AgAnalysis, raw)


def _at_depth(n, f, *args):
    return f(*args) if n == 0 else _at_depth(n - 1, f, *args)


def _deepest(load, kind, depth):
    """The deepest nesting `load` accepts without RecursionError, called
    `depth` frames down, and the outcome one level deeper."""
    section = 0x2005 if kind == "array" else 0x2004

    def mk(n):
        return K._built(patch=K._append_section(section, K._nested(n, kind)))

    lo, hi = 1, 1500
    while lo < hi:
        mid = (lo + hi + 1) // 2
        r = _at_depth(depth, K.outcome, lambda: load(mk(mid)))
        if r[0] == "raise" and r[1] == "RecursionError":
            hi = mid - 1
        else:
            lo = mid
    return lo, _at_depth(depth, K.outcome, lambda: load(mk(lo + 1)))


@pytest.mark.parametrize("kind", ["array", "annotation"])
@pytest.mark.parametrize("depth", [0, 40])
def test_recursion_depth(kind, depth):
    """RecursionError comes at the same nesting as androguard's, for the
    caller's stack depth, through DEX() and through AnalyzeAPK."""
    def dex(cls):
        return lambda raw: (cls(raw), None)[1]

    def apk(fn):
        return lambda raw: (fn(K._apk_raw(raw), raw=True), None)[1]

    assert _deepest(dex(DEX), kind, depth) == _deepest(dex(AgDEX), kind, depth)
    assert _deepest(apk(AnalyzeAPK), kind, depth) == _deepest(apk(AgAnalyzeAPK), kind, depth)
