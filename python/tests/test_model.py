"""Whole-APK parity for the native object-model queries:
classes(), class_methods(), xref_from()/xref_to(), hierarchy() and
const_strings(), against androguard 4.1.3's AnalyzeAPK.

    PARITY_APKS=a.apk:b.apk pytest python/tests
"""

import os
import re
from collections import Counter

import pytest
from loguru import logger

logger.disable("androguard")

from androguard.misc import AnalyzeAPK  # noqa: E402

import androguard_rs  # noqa: E402

APKS = [p for p in os.environ.get("PARITY_APKS", "").split(os.pathsep) if p]


def sig(ma) -> str:
    return f"{ma.class_name}->{ma.name}{ma.descriptor.replace(' ', '')}"


@pytest.fixture(scope="module", params=APKS or [pytest.param(None, marks=pytest.mark.skip("set PARITY_APKS"))])
def pair(request):
    _, _, dx = AnalyzeAPK(request.param)
    return dx, androguard_rs.Apk(request.param)


def test_classes(pair):
    dx, apk = pair
    expected = [(ca.name, ca.is_external()) for ca in dx.get_classes()]
    assert apk.classes() == expected
    assert any(ext for _, ext in expected)


def test_find_classes(pair):
    """dx.find_classes(regex) is re.match over classes() names, in order."""
    dx, apk = pair
    names = [n for n, _ in apk.classes()]
    patterns = [".*", "Landroid/", "Ljava/lang/.*", re.escape("Landroidx/core/") + ".*", "L[a-z]{1,2}/", "La;", ".*Activity;$"]
    for pat in patterns:
        assert [n for n in names if re.match(pat, n)] == [c.name for c in dx.find_classes(pat)], pat


def test_class_methods(pair):
    dx, apk = pair
    bad = []
    for ca in dx.get_classes():
        expected = []
        for ma in ca.get_methods():
            em = ma.get_method()
            expected.append((sig(ma), em.get_name(), em.get_descriptor(), em.get_access_flags_string(), ma.is_external()))
        # A sixth element (the key of an overridden earlier definition's
        # method) only appears for classes defined more than once.
        if [r[:5] for r in apk.class_methods(ca.name)] != expected:
            bad.append(ca.name)
    assert not bad, f"{len(bad)} classes differ, e.g. {bad[:3]}"
    assert apk.class_methods("Lno/such/Class;") is None
    assert dx.get_class_analysis("Lno/such/Class;") is None


def _ends(ma, xrefs):
    return Counter(
        (sig(m), ca.name, m.get_method().get_name(), m.get_method().get_descriptor(), off) for ca, m, off in xrefs
    )


def test_xrefs(pair):
    """Each get_methods() entry's xrefs, asked by its row's key (the
    signature, or an overridden earlier definition's own key). Methods no
    class lists (an earlier definition's method that neither calls nor is
    called) have no xrefs in androguard either."""
    dx, apk = pair
    bad, n = [], 0
    for ca in dx.get_classes():
        rows = apk.class_methods(ca.name)
        for ma, row in zip(ca.get_methods(), rows):
            # Irregular classes' rows carry their MethodAnalysis's key: an
            # int, or (e,) for the class's own (completed by its name).
            key = row[0] if len(row) <= 5 else (ca.name, row[5][0]) if isinstance(row[5], tuple) else row[5]
            for got, exp in ((apk.xref_from(key), ma.get_xref_from()), (apk.xref_to(key), ma.get_xref_to())):
                n += len(exp)
                if Counter(tuple(r[:5]) for r in got) != _ends(ma, exp):
                    bad.append(sig(ma))
    assert not bad, f"{len(bad)} methods differ, e.g. {bad[:3]}"
    assert n > 0
    assert apk.xref_from("Lno/such/Class;->m()V") == []


def test_hierarchy(pair):
    dx, apk = pair
    expected = [
        (ca.name, ca.get_class().get_superclassname(), list(ca.get_class().get_interfaces()))
        for ca in dx.get_classes()
        if not ca.is_external()
    ]
    assert apk.hierarchy() == expected


@pytest.mark.parametrize("jumbo", [False, True])
def test_const_strings(pair, jumbo):
    dx, apk = pair
    wanted = ("const-string", "const-string/jumbo") if jumbo else ("const-string",)
    expected = []
    for ca in dx.get_classes():
        if ca.is_external():
            continue
        for ma in ca.get_methods():
            if ma.is_external() or ma.get_method().get_code() is None:
                continue
            em = ma.get_method()
            outs = [ins.get_output() for _, ins in em.get_instructions_idx() if ins.get_name() in wanted]
            if outs:
                expected.append((ca.name, em.get_name(), em.get_descriptor(), tuple(outs)))
    got = [(cls, *m) for cls, methods in apk.const_strings(include_jumbo=jumbo) for m in methods]
    assert got == expected
    assert expected
