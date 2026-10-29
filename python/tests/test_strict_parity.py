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
