"""Whole-APK parity for the androguard_compat facade (and the native calls
behind it) against androguard 4.1.3's AnalyzeAPK, on every APK in
$PARITY_APKS: the facade's object model, instructions, xrefs and ARSCParser
shim.

Exact, order included, except xref sets: androguard's get_xref_from()/
get_xref_to() return sets, whose iteration order isn't defined, so those
are compared as multisets.

    PARITY_APKS=a.apk:b.apk pytest python/tests
"""

import os
import re
import sys
from collections import Counter
from pathlib import Path

import pytest
from loguru import logger

logger.disable("androguard")

from androguard.misc import AnalyzeAPK  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "compat"))
import androguard_compat as compat  # noqa: E402

from resource_refs import r_field_ids, resource_refs  # noqa: E402

APKS = [p for p in os.environ.get("PARITY_APKS", "").split(os.pathsep) if p]
ADDR = re.compile(r" at 0x[0-9a-f]+>")


@pytest.fixture(scope="module", params=APKS or [pytest.param(None, marks=pytest.mark.skip("set PARITY_APKS"))])
def pair(request):
    a, _, dx = AnalyzeAPK(request.param)
    ca, _, cdx = compat.analyze_apk(request.param)
    return (a, dx), (ca, cdx)


def typed(v):
    """A value with its exact type, objects (EncodedArray/Annotation) as
    their blanked repr, so int vs bool vs str differences show."""
    if isinstance(v, list):
        return ("list", [typed(x) for x in v])
    if v is None or isinstance(v, (bool, int, str)):
        return (type(v).__name__, v)
    return ("object", ADDR.sub(" at 0x0>", repr(v)))


def field_row(fa):
    f = fa.get_field()
    iv = f.init_value
    return (fa.name, f.get_class_name(), f.get_access_flags_string(), f.name, f.get_name(), f.get_descriptor(),
            None if iv is None else (typed(iv.value), ADDR.sub(" at 0x0>", repr(iv.value))))


def test_classes_and_lookup(pair):
    (_, dx), (_, cdx) = pair
    expected = [(c.name, c.is_external()) for c in dx.get_classes()]
    assert [(c.name, c.is_external()) for c in cdx.get_classes()] == expected
    assert len(cdx.get_classes()) == len(expected)
    for name, ext in expected:
        assert cdx.get_class_analysis(name).is_external() == ext
    assert cdx.get_class_analysis("Lno/such/Class;") is None
    for pat in [".*", "Landroid/", "Ljava/lang/.*", "L[a-z]{1,2}/", ".*Activity;$"]:
        for no_ext in (False, True):
            assert [c.name for c in cdx.find_classes(pat, no_ext)] == [c.name for c in dx.find_classes(pat, no_ext)]


def test_class_defs(pair):
    (_, dx), (_, cdx) = pair
    for ca in dx.get_classes():
        cc = cdx.get_class_analysis(ca.name).get_class()
        if ca.is_external():
            assert cc.get_name() == ca.get_class().get_name()
            continue
        cd = ca.get_class()
        assert (cc.get_name(), cc.get_superclassname(), list(cc.get_interfaces())) == (
            cd.get_name(), cd.get_superclassname(), list(cd.get_interfaces())), ca.name


def test_fields(pair):
    """get_fields(): own fields, then the foreign ones the class's code
    touches, in androguard's order, with typed init_value.value."""
    (_, dx), (_, cdx) = pair
    bad, n, foreign = [], 0, 0
    for ca in dx.get_classes():
        expected = [field_row(fa) for fa in ca.get_fields()]
        n += len(expected)
        foreign += sum(1 for r in expected if r[1] != ca.name)
        if [field_row(fa) for fa in cdx.get_class_analysis(ca.name).get_fields()] != expected:
            bad.append(ca.name)
    assert not bad, f"{len(bad)} classes differ, e.g. {bad[:3]}"
    assert n and foreign


def method_row(ma):
    em = ma.get_method()
    row = [ma.name, ma.class_name, ma.descriptor, ma.is_external(), em.get_name(), em.get_descriptor(),
           em.get_access_flags_string(), em.get_class_name()]
    if not ma.is_external():
        row.append(em.name)
    return row


def test_methods(pair):
    """get_methods() rows, EncodedMethod getters, get_code() presence, and
    instructions both ways (get_instructions_idx and get_bc())."""
    (_, dx), (_, cdx) = pair
    bad, checked = [], 0
    for ca in dx.get_classes():
        cms = cdx.get_class_analysis(ca.name).get_methods()
        ams = list(ca.get_methods())
        if [method_row(m) for m in cms] != [method_row(m) for m in ams]:
            bad.append(ca.name)
            continue
        for am, cm in zip(ams, cms):
            if am.is_external():
                with pytest.raises(AttributeError):
                    cm.get_method().get_code()
                continue
            acode, ccode = am.get_method().get_code(), cm.get_method().get_code()
            if (acode is None) != (ccode is None):
                bad.append(f"{ca.name} {am.name} code")
                continue
            if acode is None:
                assert list(cm.get_method().get_instructions_idx()) == []
                continue
            exp = [(off, i.get_name(), i.get_output()) for off, i in am.get_method().get_instructions_idx()]
            got = [(off, i.get_name(), i.get_output()) for off, i in cm.get_method().get_instructions_idx()]
            exp_bc = [(i.get_name(), i.get_output()) for i in acode.get_bc().get_instructions()]
            got_bc = [(i.get_name(), i.get_output()) for i in ccode.get_bc().get_instructions()]
            if got != exp or got_bc != exp_bc:
                bad.append(f"{ca.name} {am.name}")
            checked += 1
    assert not bad, f"{len(bad)} differ, e.g. {bad[:3]}"
    assert checked


def ends(xrefs):
    return Counter((c.name, m.class_name, m.name, m.descriptor, m.get_method().get_name(),
                    m.get_method().get_descriptor(), off) for c, m, off in xrefs)


def test_xrefs(pair):
    """Multisets: androguard's xrefs are sets (undefined order). Entry by
    entry of each class's get_methods(), so a class defined more than once
    compares each definition's methods with their own xrefs."""
    (_, dx), (_, cdx) = pair
    bad, n = [], 0
    for ca in dx.get_classes():
        for am, cm in zip(ca.get_methods(), cdx.get_class_analysis(ca.name).get_methods()):
            for exp, got in ((am.get_xref_from(), cm.get_xref_from()), (am.get_xref_to(), cm.get_xref_to())):
                exp = ends(exp)
                n += sum(exp.values())
                if ends(got) != exp:
                    bad.append((ca.name, am.name, am.descriptor))
    assert not bad, f"{len(bad)} methods differ, e.g. {bad[:3]}"
    assert n


def test_resource_refs(pair):
    """R field ids (typed ints) and the methods whose instruction literals
    use them, on both backends."""
    (_, dx), (_, cdx) = pair
    assert r_field_ids(cdx) == r_field_ids(dx)
    assert resource_refs(cdx) == resource_refs(dx)


def _legacy_resources(a):
    """analyze_apk(path, native_apk=False)'s APK: androguard's, with only
    get_android_resources() redirected (no index built)."""
    from androguard.core.apk import APK

    legacy = APK(a.filename)
    legacy.get_android_resources = compat._rs_get_android_resources.__get__(legacy, APK)
    return legacy.get_android_resources()


@pytest.mark.parametrize("which", ["native_apk", "androguard_apk"])
def test_arsc_shim(pair, which):
    from androguard_rs.apk import ARSCParser as NativeARSCParser

    (a, _), (ca, _) = pair
    ag = a.get_android_resources()
    ours = ca.get_android_resources() if which == "native_apk" else _legacy_resources(a)
    if ag is None:
        assert ours is None
        return
    assert isinstance(ours, NativeARSCParser if which == "native_apk" else compat.ARSCParser)
    pkg = a.get_package()
    assert ours.get_packages_names() == ag.get_packages_names()
    assert ours.get_public_resources(pkg) == ag.get_public_resources(pkg)
    assert ours.get_resolved_strings() == ag.get_resolved_strings()
    for rid in list(ag.resource_values)[:500]:
        assert ours.get_resource_xml_name(rid) == ag.get_resource_xml_name(rid)
        exp = [(c._get_tuple(), v) for c, v in ag.get_resolved_res_configs(rid)]
        assert ours.get_resolved_res_configs(rid) == exp
