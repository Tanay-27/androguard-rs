"""dexobj_cases.py live against androguard 4.1.3: the synthetic APK's
views from AnalyzeAPK, a manual DEX()/Analysis.add() load and the facade,
and, on each of PARITY_APKS, apk_views() (every class, method and field of
every DEX object; find_methods, xref callers, get_vm_class(), MethodAnalysis
repr()s), with get_ssl_candidate_methods() checked against the reference
definition over androguard's own objects."""

import logging
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("androguard")

from loguru import logger  # noqa: E402

logger.disable("androguard")

from androguard.core.analysis.analysis import Analysis as AgAnalysis  # noqa: E402
from androguard.core.apk import APK as AgAPK  # noqa: E402
from androguard.core.dex import DEX as AgDEX  # noqa: E402
from androguard.misc import AnalyzeAPK as AgAnalyzeAPK  # noqa: E402

import dexobj_cases as K  # noqa: E402
from androguard_rs.analysis import Analysis  # noqa: E402
from androguard_rs.apk import APK  # noqa: E402
from androguard_rs.dex import DEX  # noqa: E402
from androguard_rs.misc import AnalyzeAPK  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "compat"))
import androguard_compat as compat  # noqa: E402

APKS = [p for p in os.environ.get("PARITY_APKS", "").split(":") if p]


@pytest.fixture(autouse=True)
def _quiet():
    logging.disable(logging.WARNING)
    yield
    logging.disable(logging.NOTSET)


def manual(APK_, DEX_, Analysis_, raw):
    a = APK_(raw, raw=True)
    vmx = Analysis_()
    vms = []
    for b in a.get_all_dex():
        v = DEX_(b)
        vmx.add(v)
        vms.append(v)
        v.set_analysis(vmx)
    vmx.create_xref()
    return vms, vmx


def test_synthetic(tmp_path):
    raw = K.apk()
    expected = K.views(*AgAnalyzeAPK(raw, raw=True)[1:])
    assert K.views(*manual(AgAPK, AgDEX, AgAnalysis, raw)) == expected
    assert K.views(*AnalyzeAPK(raw, raw=True)[1:]) == expected
    assert K.views(*manual(APK, DEX, Analysis, raw)) == expected
    p = tmp_path / "a.apk"
    p.write_bytes(raw)
    assert K.views(*compat.analyze_apk(str(p))[1:]) == expected


@pytest.mark.skipif(not APKS, reason="set PARITY_APKS")
@pytest.mark.parametrize("path", APKS)
def test_apk(path):
    raw = Path(path).read_bytes()
    expected = K.apk_views(*AgAnalyzeAPK(raw, raw=True)[1:])
    got = K.apk_views(*manual(APK, DEX, Analysis, raw))
    for key in expected:
        assert got[key] == expected[key], key
    d = AnalyzeAPK(raw, raw=True)[1]
    assert K.native_tls_candidates(d) == expected["tls_candidates"]
