"""DEX selection and order, live against androguard 4.1.3: on
dex_order_cases.py's synthetic zips (always, when androguard is installed),
and on every APK in $PARITY_APKS (androguard_rs.Apk's load order vs
APK.get_dex_names()). test_dex_order.py checks the synthetic cases against
stored goldens without androguard.

    PARITY_APKS=a.apk:b.apk pytest python/tests/test_dex_order_parity.py
"""

import logging
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("androguard")

from loguru import logger  # noqa: E402

logger.disable("androguard")

from androguard.core.analysis.analysis import Analysis  # noqa: E402
from androguard.core.apk import APK as AgAPK  # noqa: E402
from androguard.core.dex import DEX  # noqa: E402
from androguard.misc import AnalyzeAPK as AgAnalyzeAPK  # noqa: E402

import androguard_rs  # noqa: E402
import dex_order_cases as C  # noqa: E402
from androguard_rs.misc import AnalyzeAPK as RsAnalyzeAPK  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "compat"))
import androguard_compat as compat  # noqa: E402

APKS = [p for p in os.environ.get("PARITY_APKS", "").split(os.pathsep) if p]


@pytest.fixture(autouse=True)
def _quiet():
    # apkInspector warns on a missing local header.
    logging.disable(logging.WARNING)
    yield
    logging.disable(logging.NOTSET)


@pytest.mark.parametrize("name", list(C.CASES))
def test_synthetic_analyze_apk(name):
    raw = C.CASES[name]()
    expected = C.outcome(lambda: C.snapshot(*AgAnalyzeAPK(raw, raw=True)))
    assert C.outcome(lambda: C.snapshot(*RsAnalyzeAPK(raw, raw=True))) == expected


@pytest.mark.parametrize("name", list(C.CASES))
def test_synthetic_tolerant_load(name):
    raw = C.CASES[name]()
    expected = C.outcome(lambda: C.tolerant_load(raw, DEX, Analysis))

    def rs():
        a = androguard_rs.Apk.from_bytes(raw, tolerant=True)
        return a.skipped_dex(), [(c.name, c.is_external()) for c in compat.Analysis(a).get_classes()]

    assert C.outcome(rs) == expected


@pytest.mark.parametrize("apk", APKS or [pytest.param(None, marks=pytest.mark.skip("set PARITY_APKS"))])
def test_dex_names(apk):
    expected = list(AgAPK(apk).get_dex_names())
    assert androguard_rs.Apk(apk).dex_names() == expected
    with open(apk, "rb") as f:
        assert androguard_rs.Apk.from_bytes(f.read(), tolerant=True).dex_names() == expected
