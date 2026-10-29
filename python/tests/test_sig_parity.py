"""sig_cases.py live against androguard 4.1.3."""

import logging

import pytest

pytest.importorskip("androguard")

from loguru import logger  # noqa: E402

logger.disable("androguard")

from androguard.misc import AnalyzeAPK as AgAnalyzeAPK  # noqa: E402

import androguard_rs  # noqa: E402
import sig_cases as K  # noqa: E402


def test_live():
    logging.disable(logging.WARNING)
    raw = K.strings_apk()
    assert K.rs_strings(androguard_rs.Apk.from_bytes(raw)) == K.ag_strings(AgAnalyzeAPK(raw, raw=True)[2])
    raw = K.arrow_apk()
    assert K.rs_arrow(androguard_rs.Apk.from_bytes(raw)) == K.ag_arrow(AgAnalyzeAPK(raw, raw=True)[2])
    logging.disable(logging.NOTSET)
