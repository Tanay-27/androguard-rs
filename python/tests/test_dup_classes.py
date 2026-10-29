"""Irregular classes (core/src/irregular.rs): defined more than once (in
one DEX, across two or three DEX files), sharing a class_data with other
class_defs of the same or other names, listing another class's method_id
or one method twice, on dup_cases.py's synthetic APKs: every get_methods()
entry androguard 4.1.3 lists (own methods, then the MethodAnalysis objects
and ExternalMethods create_xref() appends, in its order), each with its own
code, get_class_name() and xrefs, get_fields(), find_methods(), and the
native whole-APK queries built from the same iteration (const_strings(),
search_instruction_text(), callers()/callees(), methods_using_string()).
No androguard needed: the goldens (dup_goldens.py) were generated once from
androguard 4.1.3 + mutf8 1.1.0 by scripts/gen_dup_goldens.py.
test_dup_classes_parity.py checks the same cases live.
"""

import sys
from pathlib import Path

import pytest

import androguard_rs
import dup_cases as K
from androguard_rs.misc import AnalyzeAPK
from dup_goldens import GOLDEN

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "compat"))
import androguard_compat as compat  # noqa: E402


@pytest.fixture(scope="module", params=list(K.CASES))
def case(request):
    return request.param, K.CASES[request.param]()


def test_views(case):
    name, raw = case
    apk = androguard_rs.Apk.from_bytes(raw)
    got = K.rs_views(apk, compat.Analysis(apk))
    for key, expected in GOLDEN[name].items():
        assert got[key] == expected, key


def test_misc_analyze_apk(case):
    """androguard_rs.misc.AnalyzeAPK's dx answers the same."""
    name, raw = case
    assert K.snapshot(AnalyzeAPK(raw, raw=True)[2]) == GOLDEN[name]["snapshot"]


def test_keys():
    """An irregular class's rows carry the key of their MethodAnalysis: (e,)
    for its own methods (completed by the class name), an int for the
    others; the signature names the one calls resolve to."""
    apk = androguard_rs.Apk.from_bytes(K.CASES["three_dex"]())
    rows = [r for r in apk.class_methods(K.C) if r[1] == "a"]
    assert [len(r) for r in rows] == [7, 7, 7]
    win, first, second = rows
    assert isinstance(win[5], tuple) and isinstance(first[5], int) and isinstance(second[5], int)
    win_key = (K.C, win[5][0])

    def strings(key):
        return [o for _, n, o in apk.bytecode(key) if n == "const-string"]

    assert strings(win[0]) == strings(win_key) == ['v0, "a-3"']
    assert strings(first[5]) == ['v0, "a-1"'] and strings(second[5]) == ['v0, "a-2"']
    assert apk.has_code(first[5]) and apk.xref_from(first[5]) == []
    assert apk.method_row(first[5])[:5] == first[:5]
    # a-1 calls mid at 4; mid's callers carry that key.
    mid_callers = apk.xref_from("Lp/C;->mid()V")
    assert sorted(r[4] for r in mid_callers) == [4, 10]
    assert first[5] in [r[5] for r in mid_callers]
    # Not a key: an int naming no MethodAnalysis, an unknown class.
    for bad in (2**40, 10**12, (K.X, 0), ("Lno;", 0)):
        assert apk.bytecode(bad) is None and apk.xref_to(bad) == [] and not apk.has_code(bad)
    with pytest.raises(OverflowError):
        apk.bytecode(-1)
    with pytest.raises(TypeError):
        apk.bytecode(1.5)
    # callees() by signature: every definition's calls.
    assert sorted(set(apk.callees("Lp/C;->a()V"))) == sorted(
        {(r[0], r[4]) for k in (win_key, first[5], second[5]) for r in apk.xref_to(k)})


def test_no_duplicates_unchanged():
    """Without duplicates, rows keep five elements and no key appears."""
    apk = androguard_rs.Apk.from_bytes(K.apk([K._caller((K.C, "a"))], [K.cls(K.C, virtual=[K.m("a")])]))
    for name, _ in apk.classes():
        assert all(len(r) == 5 for r in apk.class_methods(name))
    assert all(k is None for _, k, _ in apk.search_instruction_text(["l"], keys=True))
