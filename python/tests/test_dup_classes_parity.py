"""Classes defined more than once, live against androguard 4.1.3: on
dup_cases.py's synthetic APKs (test_dup_classes.py checks the same against
stored goldens without androguard), every view (dup_cases.ag_views) from
androguard's AnalyzeAPK vs androguard_rs.Apk and the facade over it.
"""

import logging
import sys
from pathlib import Path

import pytest

pytest.importorskip("androguard")

from loguru import logger  # noqa: E402

logger.disable("androguard")

from androguard.misc import AnalyzeAPK as AgAnalyzeAPK  # noqa: E402

import androguard_rs  # noqa: E402
import dup_cases as K  # noqa: E402
from androguard_rs.misc import AnalyzeAPK as RsAnalyzeAPK  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "compat"))
import androguard_compat as compat  # noqa: E402


@pytest.fixture(autouse=True)
def _quiet():
    logging.disable(logging.WARNING)
    yield
    logging.disable(logging.NOTSET)


@pytest.mark.parametrize("name", list(K.CASES))
def test_views(name):
    raw = K.CASES[name]()
    expected = K.ag_views(AgAnalyzeAPK(raw, raw=True)[2])
    apk = androguard_rs.Apk.from_bytes(raw)
    got = K.rs_views(apk, compat.Analysis(apk))
    for key in expected:
        assert got[key] == expected[key], key
    assert K.snapshot(RsAnalyzeAPK(raw, raw=True)[2]) == expected["snapshot"]
