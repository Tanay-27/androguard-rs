"""Loading fails as androguard 4.1.3's does (strict_cases.py): AnalyzeAPK
(androguard_rs.misc and the facade's analyze_apk) raises what androguard's
AnalyzeAPK raises (the same exception type, args and str()), in its order:
DEX header errors and the first method Analysis.add() can't disassemble; and
a manual DEX()/Analysis.add()/create_xref() load over
androguard_rs.dex.DEX and androguard_rs.analysis.Analysis raises (or skips)
exactly as with androguard's classes. No androguard needed: the goldens
(strict_goldens.py) were generated once from androguard 4.1.3 + mutf8 1.1.0
by scripts/gen_dexobj_goldens.py; test_strict_parity.py checks live.
"""

import sys
from pathlib import Path

import pytest

import androguard_rs
import strict_cases as K
from androguard_rs.analysis import Analysis
from androguard_rs.apk import APK
from androguard_rs.dex import DEX
from androguard_rs.misc import AnalyzeAPK
from strict_goldens import GOLDEN

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "compat"))
import androguard_compat as compat  # noqa: E402


@pytest.mark.parametrize("name", list(K.CASES))
def test_analyze_apk(name):
    assert K.analyze(AnalyzeAPK, K.CASES[name]()) == GOLDEN[name]["analyze"]


@pytest.mark.parametrize("name", list(K.CASES))
def test_facade_analyze_apk(name, tmp_path):
    p = tmp_path / "a.apk"
    p.write_bytes(K.CASES[name]())
    assert K.outcome(lambda: K.summary(*compat.analyze_apk(str(p))[1:])) == GOLDEN[name]["analyze"]


@pytest.mark.parametrize("name", list(K.CASES))
def test_manual_load(name):
    assert K.manual(APK, DEX, Analysis, K.CASES[name]()) == GOLDEN[name]["manual"]


def test_tolerant_loads_and_raises_on_use():
    """tolerant=True (not androguard): the APK loads; the method androguard
    can't disassemble raises androguard's InvalidInstruction when asked."""
    raw = K.CASES["bad"]()
    expected = GOLDEN["bad"]["analyze"]
    _, d, dx = AnalyzeAPK(raw, raw=True, tolerant=True)
    (ma,) = [m for m in dx.get_class_analysis(K.X).get_methods() if m.name == "bad"]
    got = K.outcome(lambda: list(ma.get_method().get_instructions()))
    assert got == expected
    assert K.outcome(lambda: androguard_rs.Apk.from_bytes(raw).bytecode("Lp/X;->bad()V")) == expected


def test_dex_header_errors_direct():
    """DEX(bytes) alone: the header errors, as androguard's DEX()."""
    for name, mk, exc in [("short", K.short, ValueError), ("byteswap", K.byteswap, NotImplementedError),
                          ("checksum", K.checksum, ValueError), ("magic", K.magic, ValueError)]:
        with pytest.raises(exc):
            DEX(mk())
    assert [c.get_name() for c in DEX(K.ok_dex()).get_classes()] == [K.C]


@pytest.mark.parametrize("name", list(K.HANG_CASES))
def test_androguard_never_returns(name):
    """A string_data_item running to the end of the file without a NUL:
    androguard 4.1.3's read_null_terminated_string loops forever (its list
    of empty reads grows until memory runs out). We raise MemoryError, the
    exception androguard would end with, at once."""
    raw = K.HANG_CASES[name]()
    with pytest.raises(MemoryError):
        DEX(raw)
    with pytest.raises(MemoryError):
        AnalyzeAPK(K._apk_raw(raw), raw=True)


def test_load_error_types():
    """The exception classes and enum messages are androguard's."""
    from androguard_rs.dex import HiddenApiClassDataItem, TypeMapItem

    assert repr(KeyError(TypeMapItem.CODE_ITEM)) == "KeyError(<TypeMapItem.CODE_ITEM: 8193>)"
    with pytest.raises(ValueError, match=r"^7 is not a valid HiddenApiClassDataItem.RestrictionApiFlag$"):
        HiddenApiClassDataItem.RestrictionApiFlag(7)
