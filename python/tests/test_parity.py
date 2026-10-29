"""Whole-APK parity: androguard_rs.Apk vs androguard 4.1.3's AnalyzeAPK.

For each APK in $PARITY_APKS (os.pathsep-separated), checks every method's
callers, callees and bytecode, and every class's metadata, against
androguard. Only APKs androguard can load whole fit here; per-DEX parity for
larger ones is scripts/parity.py.

    PARITY_APKS=a.apk:b.apk pytest python/tests
"""

import os
import re

import pytest
from loguru import logger

logger.disable("androguard")

from androguard.misc import AnalyzeAPK  # noqa: E402

import androguard_rs  # noqa: E402

APKS = [p for p in os.environ.get("PARITY_APKS", "").split(os.pathsep) if p]
ADDR = re.compile(r" at 0x[0-9a-f]+>")


def sig(ma) -> str:
    return f"{ma.class_name}->{ma.name}{ma.descriptor.replace(' ', '')}"


def init_text(field) -> str:
    # The field's init value as class_info() renders it: repr() of the value,
    # object addresses blanked.
    init_value = getattr(field, "init_value", None)
    if init_value is None:
        return "<no encoded init value>"
    return ADDR.sub(" at 0x0>", repr(getattr(init_value, "value", init_value)))


@pytest.fixture(scope="module", params=APKS or [pytest.param(None, marks=pytest.mark.skip("set PARITY_APKS"))])
def pair(request):
    _, _, dx = AnalyzeAPK(request.param)
    return dx, androguard_rs.Apk(request.param)


def test_xrefs(pair):
    dx, apk = pair
    # A signature defined in more than one DEX is one method in the index;
    # union androguard's per-definition xrefs to compare like with like.
    expected_to, expected_from = {}, {}
    for ma in dx.get_methods():
        s = sig(ma)
        expected_to.setdefault(s, set()).update((sig(m), off) for _, m, off in ma.get_xref_to())
        expected_from.setdefault(s, set()).update((sig(m), off) for _, m, off in ma.get_xref_from())
    bad = [s for s in expected_to if set(apk.callees(s)) != expected_to[s]]
    bad += [s for s in expected_from if set(apk.callers(s)) != expected_from[s]]
    assert not bad, f"{len(bad)} methods differ, e.g. {bad[:3]}"
    assert len(expected_to) > 0


def test_bytecode(pair):
    dx, apk = pair
    bad, checked = [], 0
    for ma in dx.get_methods():
        if ma.is_external():
            continue
        em = ma.get_method()
        if em.get_code() is None:
            assert not apk.has_code(sig(ma))
            continue
        expected = [(off, ins.get_name(), ins.get_output()) for off, ins in em.get_instructions_idx()]
        if apk.bytecode(sig(ma)) != expected:
            bad.append(sig(ma))
        checked += 1
    assert not bad, f"{len(bad)}/{checked} methods differ, e.g. {bad[:3]}"


def test_classes(pair):
    dx, apk = pair
    bad = []
    for ca in dx.get_classes():
        if ca.is_external():
            continue
        cd = ca.get_class()
        expected = {
            "name": cd.get_name(),
            "access_flags": cd.get_access_flags_string(),
            "superclass": cd.get_superclassname(),
            "interfaces": list(cd.get_interfaces()),
            "methods": [(m.get_name(), m.get_descriptor(), m.get_access_flags_string()) for m in cd.get_methods()],
            "fields": [
                (f.get_access_flags_string(), f.get_name(), f.get_descriptor(), init_text(f)) for f in cd.get_fields()
            ],
        }
        if apk.class_info(cd.get_name()) != expected:
            bad.append(cd.get_name())
    assert not bad, f"{len(bad)} classes differ, e.g. {bad[:3]}"


def test_search_instruction_text(pair):
    """search_instruction_text vs the same search done on androguard: the
    methods (defined classes, get_classes() then get_methods() order) any of
    whose lower-cased instruction outputs contains a needle."""
    dx, apk = pair
    blob = []
    for ca in dx.get_classes():
        if ca.is_external():
            continue
        for ma in ca.get_methods():
            try:
                outs = [out.lower() for _off, ins in ma.get_method().get_instructions_idx() if (out := ins.get_output())]
            except Exception:
                continue
            if outs:
                blob.append((ma, outs))

    names = sorted(ca.name for ca in dx.get_classes() if not ca.is_external())
    rng = __import__("random").Random(3)
    queries = [["cipher"], ["ljava/lang/string;"], ["http"], ["v0, v1"], ["landroid/"], ["\\"], ['"']]
    for name in rng.sample(names, min(25, len(names))):
        java = name[1:-1].replace("/", ".")
        queries.append([java.lower(), name.lower(), java.replace(".", "/").lower()])
    for needles in queries:
        expected = [sig(ma) for ma, outs in blob if any(n in out for out in outs for n in needles)]
        assert apk.search_instruction_text(needles) == expected, needles
