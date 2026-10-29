"""androguard 4.1.3's per-DEX object model (dexobj_cases.py) without
androguard: per-DEX objects (DEX.get_classes/get_class/get_encoded_methods/
get_encoded_method_descriptor/get_encoded_field_descriptor/get_encoded_field,
ClassDefItem, EncodedMethod incl. get_information() and str(),
EncodedField.get_init_value().get_value()), Analysis.find_methods(),
MethodAnalysis.method/repr()/get_xref_from(), get_vm_class(), and a
per-method instruction walk, from AnalyzeAPK and from a manual
DEX()/Analysis.add() load. Goldens (dexobj_goldens.py) were generated from
androguard 4.1.3 + mutf8 1.1.0 by scripts/gen_dexobj_goldens.py;
test_dexobj_parity.py checks live.
"""

import sys
from pathlib import Path

import pytest

import dexobj_cases as K
from androguard_rs.analysis import Analysis
from androguard_rs.apk import APK
from androguard_rs.dex import DEX, EncodedMethod
from androguard_rs.misc import AnalyzeAPK
from dexobj_goldens import GOLDEN

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "compat"))
import androguard_compat as compat  # noqa: E402


def manual(raw):
    a = APK(raw, raw=True)
    vmx = Analysis()
    vms = []
    for b in a.get_all_dex():
        v = DEX(b)
        vmx.add(v)
        vms.append(v)
        v.set_analysis(vmx)
    vmx.create_xref()
    return vms, vmx


@pytest.fixture(scope="module")
def raw():
    return K.apk()


def _check(got):
    for key, expected in GOLDEN.items():
        assert got[key] == expected, key


def test_analyze_apk(raw):
    _check(K.views(*AnalyzeAPK(raw, raw=True)[1:]))


def test_manual_load(raw):
    _check(K.views(*manual(raw)))


def test_facade(raw, tmp_path):
    p = tmp_path / "a.apk"
    p.write_bytes(raw)
    _check(K.views(*compat.analyze_apk(str(p))[1:]))


def test_identity(raw):
    """Objects stand for androguard's single objects: equal and same hash when
    they are the same class_data entry (a class_def sharing another's
    class_data lists the same EncodedMethods; an Analysis method is the
    DEX's), and XREFfrom is an AttributeError, as in androguard."""
    a, d, dx = AnalyzeAPK(raw, raw=True)
    vm = d[0]
    share_a, share_b = vm.get_class(K.SHARE_A), vm.get_class(K.SHARE_B)
    assert share_a.get_methods() == share_b.get_methods()
    assert len({*share_a.get_methods(), *share_b.get_methods()}) == len(share_a.get_methods())
    ma = next(dx.find_methods(K.USE, "plain", "."))
    em = ma.get_method()
    dex_em = vm.get_encoded_method_descriptor(K.USE, "plain", "()V")
    assert em == dex_em and hash(em) == hash(dex_em) and isinstance(em, EncodedMethod)
    assert em.CM.vm is vm
    assert ma == next(dx.find_methods(K.USE, "plain", ".")) and len({ma, ma.method and ma}) == 1
    with pytest.raises(AttributeError):
        vm.get_class(K.TM).XREFfrom
    xs = ma.get_xref_from()
    assert isinstance(xs, set) and list(xs) == list(xs) and next(iter(xs)) in xs


def test_dup_class_per_dex(raw):
    """A class defined in both DEX files is in each DEX's object with that
    DEX's methods; the Analysis holds the last one."""
    _, d, dx = AnalyzeAPK(raw, raw=True)
    assert [e.get_name() for e in d[0].get_class(K.DUP).get_methods()] == ["<init>", "first"]
    assert [e.get_name() for e in d[1].get_class(K.DUP).get_methods()] == ["<init>", "second"]
    assert [e.get_name() for e in dx.get_class_analysis(K.DUP).get_vm_class().get_methods()] == ["<init>", "second"]
