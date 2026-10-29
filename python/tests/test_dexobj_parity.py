"""dexobj_cases.py live against androguard 4.1.3: the synthetic APK's
views from AnalyzeAPK, a manual DEX()/Analysis.add() load and the facade,
and, on each of PARITY_APKS, apk_views() (every class, method and field of
every DEX object; find_methods, xref callers, get_vm_class(), MethodAnalysis
repr()s, and a per-method instruction walk over get_encoded_methods())."""

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


# Patterns for find_methods()/find_classes() whose class pattern has a literal
# prefix the facade narrows the class list by, or none: unescaped "$" and
# ".", a quantified last literal, alternations, lookaheads, inline flags.
TRICKY = [
    ("Landroid/app/Notification$Builder;", ".*", ".*"),
    ("Landroid/app/Notification\\$Builder;", ".*", ".*"),
    ("Landroid/app/Notification.Builder;", "<init>", ".*"),
    ("Ljava/lang/Strin?g", "valueOf", ".*"),
    ("Ljava/lang/Stringx?", "(?!value)", ".*"),
    ("Ljava/util/(Hash|Tree)Map;", "put", ".*"),
    ("Ljava/util/HashMap;|Ljava/util/TreeMap;", "get", ".*"),
    ("Landroid/(?!support)", "on", r"\(Landroid/os/Bundle;\)V"),
    ("(?i)landroid/content/intent;", "get", ".*"),
    ("Landroid/content/I(?i:NTENT);", "get", ".*"),
    ("(?x) Landroid/content/Intent; ", "get", ".*"),
    ("Landroid/content/Intent;{1,2}", ".*", ".*"),
    ("Landroid/content/Intent;{0}", ".*", ".*"),
    ("", "toString", ".*"),
    ("[L]java/lang/Object;", ".*", ".*", ".*", True),
    ("Ljava/lang/Object;", ".*", ".*", "public", True),
    # method-name patterns with and without a literal prefix
    ("^((?!LocalBroadcastManager).)*$", "registerReceiver", r"^\(Landroid/content/BroadcastReceiver; ."),
    (".*", "getStringx?", ".*"),
    ("L", "(?i)GETSTRING", ".*"),
    ("L", "get[A-Z]", r"\(\)"),
    ("L", "set|get", ".*"),
    ("Landroid/", "on(?=Create)", ".*"),
    ("L", "<clinit>", ".*", ".*", True),
    ("L", "zzzzNoSuchMethod", ".*"),
]


def _fm(dx, *pattern):
    return [(ma.class_name, ma.name, ma.descriptor, ma.access, ma.is_external()) for ma in dx.find_methods(*pattern)]


@pytest.mark.skipif(not APKS, reason="set PARITY_APKS")
@pytest.mark.parametrize("path", APKS)
def test_find_methods_permission_map(path):
    """find_methods() for every signature of androguard's permission maps
    (class, method name, re.escape()d descriptor), twice over (results
    served from the cached class list and rows must not change), and
    find_classes()/find_methods() for TRICKY, against androguard."""
    import re

    from androguard.core.api_specific_resources import load_permission_mappings

    raw = Path(path).read_bytes()
    ag = AgAnalyzeAPK(raw, raw=True)[2]
    rs = manual(APK, DEX, Analysis, raw)[1]
    sigs = []
    for level in (16, 25):
        sigs += [k.split("-") for k in load_permission_mappings(level)]
    assert len(sigs) > 1000
    expected = [_fm(ag, s[0], s[1], re.escape(s[2])) for s in sigs]
    for _ in range(2):
        assert [_fm(rs, s[0], s[1], re.escape(s[2])) for s in sigs] == expected
    for t in TRICKY:
        assert _fm(rs, *t) == _fm(ag, *t), t
        assert [c.name for c in rs.find_classes(t[0])] == [c.name for c in ag.find_classes(t[0])], t
        assert [c.name for c in rs.find_classes(t[0], True)] == [c.name for c in ag.find_classes(t[0], True)], t


# (opcode names or None, mode, text): three insecure-TLS checks, and broader ones.
REF_RULES = [
    [(("new-instance",), "endswith", "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;"),
     (("sget-object",), "contains", "Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER"),
     (("invoke-static",), "endswith", "Landroid/net/SSLCertificateSocketFactory;->getInsecure(I "
      "Landroid/net/SSLSessionCache;)Ljavax/net/ssl/SSLSocketFactory;")],
    [(("invoke-virtual", "invoke-virtual/range"), "contains", "Ljava/lang/String;->equals")],
    [(None, "contains", "http")],
    [(("const-string",), "endswith", '"')],
]
REF_NAMES = ["checkServerTrusted", "verify", "onReceivedSslError"]


def _ref_walk(vms, names, rules):
    out = []
    for vm in vms:
        for m in vm.get_encoded_methods():
            if m.get_name() in names:
                out.append(str(m))
                continue
            if m.get_code() is None:
                continue
            try:
                for i in m.get_instructions():
                    if any((ops is None or i.get_name() in ops) and (
                            i.get_output() is None or (i.get_output().endswith(t) if mode == "endswith"
                                                       else t in i.get_output())) for ops, mode, t in rules):
                        out.append(str(m))
                        break
            except Exception:  # noqa: BLE001  (unreadable code: included)
                out.append(str(m))
    return out


@pytest.mark.skipif(not APKS, reason="set PARITY_APKS")
@pytest.mark.parametrize("path", APKS)
def test_find_methods_referencing(path):
    """DEX.find_methods_referencing(): the methods (same order) a walk over
    androguard's get_encoded_methods() with the same tests finds."""
    raw = Path(path).read_bytes()
    ag_vms = AgAnalyzeAPK(raw, raw=True)[1]
    vms = manual(APK, DEX, Analysis, raw)[0]
    pool = {m for vm in vms for m in vm.get_encoded_methods()}
    cases = [(REF_RULES[0], []), (REF_RULES[0], REF_NAMES), ([], REF_NAMES)] + [(r, []) for r in REF_RULES[1:]]
    for rules, names in cases:
        want = _ref_walk(ag_vms, names, rules)
        got = [m for vm in vms for m in vm.find_methods_referencing(names, rules)]
        assert [str(m) for m in got] == want, (rules, names)
        # equal to (the same handles as) what get_encoded_methods() hands out
        assert all(m in pool for m in got)
