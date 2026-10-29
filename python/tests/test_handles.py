"""The objects androguard_rs hands out are per-query handles (keys into the
native index, nothing kept on the Python side): the same method, field,
class or instruction reached by different routes compares and hashes
equal, so sets and dicts of them dedupe as androguard's single objects do,
though they are not the same objects (`is`). Runs on the synthetic APK
(fixture_apk.py), no androguard needed.
"""

import sys
from pathlib import Path

import pytest

import androguard_rs
import fixture_apk as fx
from androguard_rs import dex as agdex
from androguard_rs.misc import AnalyzeAPK

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "compat"))
import androguard_compat as compat  # noqa: E402


@pytest.fixture(scope="module")
def loaded(tmp_path_factory):
    path = fx.build_apk(tmp_path_factory.mktemp("fx") / "fixture.apk")
    return AnalyzeAPK(str(path))


def _key(m):
    return (m.get_class_name(), m.get_name(), m.get_descriptor())


def _same(a, b):
    return a == b and b == a and hash(a) == hash(b)


def test_method_routes_agree(loaded):
    _a, vms, dx = loaded
    seen = 0
    for vm in vms:
        listed = list(vm.get_encoded_methods())
        by_key = {_key(m): m for m in listed}
        assert len(set(listed)) == len(listed) == len(by_key)
        for c in vm.get_classes():
            assert vm.get_class(c.get_name()) == c
            for m in c.get_methods():
                k = _key(m)
                routes = [
                    by_key[k],
                    vm.get_encoded_method_descriptor(*k),
                    *[x for x in vm.find_methods_referencing(names=[k[1]]) if _key(x) == k],
                    *[x for x in vm.get_class(c.get_name()).get_methods() if _key(x) == k],
                ]
                ca = dx.get_class_analysis(k[0])
                # (a class defined twice: the ClassAnalysis holds the last)
                if ca is not None and not ca.is_external() and ca.get_vm_class() == c:
                    routes += [ma.get_method() for ma in ca.get_methods() if (ma.name, ma.descriptor) == k[1:]]
                    routes += [x for x in ca.get_vm_class().get_methods() if _key(x) == k]
                for r in routes:
                    assert _same(m, r), (k, r)
                    assert m is not r
                assert len({m, *routes}) == 1
                seen += 1
    assert seen >= 9


def test_xref_endpoints_are_the_listed_methods(loaded):
    _a, vms, dx = loaded
    listed = {m for vm in vms for m in vm.get_encoded_methods()}
    n = 0
    for ca in dx.get_classes():
        for ma in ca.get_methods():
            for c2, ma2, _off in list(ma.get_xref_to()) + list(ma.get_xref_from()):
                assert _same(c2, dx.get_class_analysis(c2.name))
                if not ma2.is_external():
                    assert ma2.get_method() in listed
                    found = [x for x in dx.find_methods(c2.name, ma2.name) if x.descriptor == ma2.descriptor]
                    assert found and all(_same(ma2, x) for x in found)
                    n += 1
    assert n > 0


def test_sets_dedupe_like_androguard(loaded):
    # e.g. a caller collecting (name, method) pairs from several queries
    _a, vms, dx = loaded
    pairs = set()
    for _ in range(3):
        for vm in vms:
            for m in vm.get_encoded_methods():
                pairs.add((m.get_name(), m))
    assert len(pairs) == sum(len(vm.get_encoded_methods()) for vm in vms)
    classes = set()
    for _ in range(2):
        classes.update(dx.get_classes())
        for vm in vms:
            classes.update(vm.get_classes())
    assert len(classes) == len(dx.get_classes()) + sum(vm.get_len_classes() for vm in vms)


def test_fields_and_classes(loaded):
    _a, vms, dx = loaded
    n_held = 0
    for vm in vms:
        fields = vm.get_encoded_fields()
        assert len(set(fields)) == len(fields)
        for f in fields:
            again = vm.get_encoded_field_descriptor(f.get_class_name(), f.get_name(), f.get_descriptor())
            assert _same(f, again) and f is not again
            assert [x for x in vm.get_class(f.get_class_name()).get_fields() if x == f] == [f]
        for c in vm.get_classes():
            ca = dx.get_class_analysis(c.get_name())
            if ca is not None and not ca.is_external():
                assert _same(ca.get_vm_class(), ca.get_vm_class())
                if ca.get_vm_class() == c:
                    assert ca.get_vm_class().get_methods() == c.get_methods()
                    n_held += 1
    assert n_held > 3


def test_code_and_instructions(loaded):
    _a, vms, dx = loaded
    for vm in vms:
        for m in vm.get_encoded_methods():
            code = m.get_code()
            if code is None:
                continue
            assert _same(code, m.get_code()) and _same(code.get_bc(), m.get_code().get_bc())
            insns = list(m.get_instructions())
            assert insns == list(code.get_bc().get_instructions())
            assert [m.get_instruction(i) for i in range(len(insns))] == insns
            assert [m.get_instruction(0, i._row) for i in insns] == insns
            assert dict(m.get_instructions_idx()) == {i._row: i for i in insns}
            ca = dx.get_class_analysis(m.get_class_name())
            mas = [ma for ma in ca.get_methods() if (ma.name, ma.descriptor) == _key(m)[1:]]
            if mas and mas[0].get_method() == m:
                assert list(mas[0].get_method().get_instructions()) == insns


def test_nothing_kept(loaded):
    # The DEX objects and the Analysis hold no member, code or instruction
    # objects between queries: once a first walk has made the kept atoms
    # (strs), walking everything again leaves nothing behind.
    import tracemalloc

    _a, vms, dx = loaded

    def walk():
        for vm in vms:
            for c in vm.get_classes():
                str(c), c.get_fields()
                for m in c.get_methods():
                    str(m), m.get_information()
                    for i in m.get_instructions():
                        i.get_output(), i.get_name()
        for ca in dx.get_classes():
            for ma in ca.get_methods():
                list(ma.get_xref_from()), list(ma.get_xref_to())
            ca.get_fields()

    walk()
    tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        walk()
        walk()
        after = tracemalloc.get_traced_memory()[0]
    finally:
        tracemalloc.stop()
    assert after - before < 4096, after - before
    for vm in vms:
        held = [getattr(vm, s, None) for s in type(vm).__slots__]
        assert not any(isinstance(v, (list, dict, tuple, set)) for v in held)
    assert set(compat.Analysis.__slots__) == {"_rs", "_apk", "_views"}


def test_cache_settings_are_reported(loaded):
    _a, vms, _dx = loaded
    info = vms[0]._native()._cache_info()
    assert set(info) >= {"atoms", "spans", "text", "lru", "span_bytes"}


def test_native_index_is_shared(loaded):
    _a, vms, dx = loaded
    assert all(vm._native() is dx._rs for vm in vms)
    assert isinstance(dx._rs, androguard_rs.Apk)
