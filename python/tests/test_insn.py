"""The Instruction API (androguard_rs.dex objects through the facade's
EncodedMethod / get_code().get_bc()) on insn_apk.py's synthetic DEX, with no
androguard installed: every instruction format, payload, invalid case and
lookup, against goldens from androguard 4.1.3 (insn_goldens.py, generated
once by scripts/gen_insn_goldens.py).
"""

import subprocess
import sys
from pathlib import Path

import pytest

import androguard_rs
import androguard_rs.dex as agdex
import insn_apk
from insn_goldens import G as COMPACT
from insn_goldens import T
from insn_shapes import expand, insn_shape, method_shape

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "compat"))
import androguard_compat as compat  # noqa: E402


G = {k: dict(g, insns=[expand(i, T) for i in g["insns"]]) if "insns" in g else g for k, g in COMPACT.items()}


@pytest.fixture(scope="module")
def path(tmp_path_factory):
    return insn_apk.build_apk(tmp_path_factory.mktemp("insn") / "insn.apk")


@pytest.fixture(scope="module")
def dx(path):
    return compat.Analysis(androguard_rs.Apk(path))


@pytest.fixture(scope="module")
def methods(dx):
    out = {}
    for ma in dx.get_class_analysis(insn_apk.OPS).get_methods():
        em = ma.get_method()
        out[f"{em.get_class_name()}->{em.get_name()}{em.get_descriptor()}"] = em
    return out


def test_goldens_cover_every_format():
    names = {i[0] for g in G.values() for i in g.get("insns", [])}
    expected = {e[0].__name__ for op, e in agdex.DALVIK_OPCODES_FORMAT.items() if op not in insn_apk.UNUSED}
    assert expected | {"PackedSwitch", "SparseSwitch", "FillArrayData"} == names
    ops = {dict(i[1])["get_op_value"][1] for i in G["Lcom/ex/Ops;->allops()V"]["insns"]}
    assert ops == {str(op) for op in range(256) if op not in insn_apk.UNUSED}
    assert sum(len(g.get("insns", [])) for g in G.values()) == 342
    assert sum("error" in g for g in G.values()) == 9


def test_same_methods(methods):
    assert sorted(methods) == sorted(G)


@pytest.mark.parametrize("key", sorted(G))
def test_method(methods, key):
    got = method_shape(methods[key])
    want = G[key]
    if "insns" in want:
        for n, (a, b) in enumerate(zip(got["insns"], want["insns"])):
            assert a == b, (key, n)
    assert got == want


def test_isinstance_and_literals(methods):
    """Reading a constant's literal by format: isinstance against the format
    classes, then .B / .BBBB / .BBBBBBBB."""
    seen = {}
    for ins in methods["Lcom/ex/Ops;->variants()V"].get_instructions():
        for cls, attr in ((agdex.Instruction11n, "B"), (agdex.Instruction21s, "BBBB"),
                          (agdex.Instruction21h, "BBBB"), (agdex.Instruction31i, "BBBBBBBB")):
            if isinstance(ins, cls):
                assert isinstance(ins, agdex.Instruction)
                seen.setdefault(cls.__name__, []).append(int(getattr(ins, attr)))
    assert seen["Instruction11n"] == [0, 7, -8, -1, 1]
    assert -2**31 in seen["Instruction31i"] and 2**31 - 1 in seen["Instruction31i"]
    assert -32768 << 16 in seen["Instruction21h"] and -32768 << 48 in seen["Instruction21h"]
    payload = list(methods["Lcom/ex/Ops;->payloads()V"].get_instructions())[1]
    assert isinstance(payload, agdex.PackedSwitch) and not isinstance(payload, agdex.Instruction)


def test_get_bc_and_dcode(methods):
    em = methods["Lcom/ex/Ops;->payloads()V"]
    bc = em.get_code().get_bc()
    insns = list(bc.get_instructions())
    assert [type(i).__name__ for i in insns[:3]] == ["Instruction10x", "PackedSwitch", "PackedSwitch"]
    assert bc.get_instruction(1) is insns[1] is em.get_code().get_instruction(1)
    assert bc.get_ins_off(2) is insns[1] and bc.get_ins_off(3) is None
    assert bc.off_to_pos(2) == 1 and bc.off_to_pos(3) == -1
    assert bytes(bc.get_raw()) == b"".join(i.get_raw() for i in insns)
    assert bc.get_length() == len(bc.get_raw())
    # payload notes, as androguard's
    insns[1].add_note("x")
    assert insns[1].get_notes() == ["x"]


def test_invalid_raises_lazily(methods):
    em = methods["Lcom/ex/Ops;->bad_unused()V"]
    gen = em.get_instructions()  # nothing decoded yet, as androguard's generator
    with pytest.raises(androguard_rs.InvalidInstruction) as e:
        next(gen)
    assert str(e.value) == G["Lcom/ex/Ops;->bad_unused()V"]["error"][1]
    with pytest.raises(androguard_rs.InvalidInstruction):
        em.get_instruction(0, 0)
    assert agdex.InvalidInstruction is androguard_rs.InvalidInstruction


def test_no_code(methods):
    em = methods["Lcom/ex/Ops;->abstract()V"]
    assert em.get_instructions() == [] and em.get_instruction(0) is None
    assert list(em.get_instructions_idx()) == []


def test_unsupported_is_loud(methods):
    ins = next(iter(methods["Lcom/ex/Ops;->refs()V"].get_instructions()))
    with pytest.raises(NotImplementedError):
        ins.cm
    with pytest.raises(NotImplementedError):
        ins.get_raw_string()
    assert agdex.GAPS["Instruction21c.cm"] >= 1
    with pytest.raises(AttributeError):
        ins.no_such_attribute
    assert not hasattr(ins, "no_such_attribute")


def test_lru_is_bounded(path):
    class Small(compat.Analysis):
        _LRU_SIZE = 2

    dx = Small(androguard_rs.Apk(path))
    ems = {ma.name: ma.get_method() for ma in dx.get_class_analysis(insn_apk.OPS).get_methods()}
    first = list(ems["allops"].get_instructions())
    assert list(ems["allops"].get_instructions())[0] is first[0]  # cached: the same objects
    for name in ("variants", "refs", "payloads"):
        list(ems[name].get_instructions())
    assert len(dx._lru) == 2
    again = list(ems["allops"].get_instructions())  # evicted: decoded again
    assert again[0] is not first[0] and [insn_shape(i) for i in again] == [insn_shape(i) for i in first]


def test_no_androguard_needed(path):
    code = (
        "import sys; sys.path[:0] = [%r, %r]\n"
        "import androguard_rs, androguard_compat as c, insn_shapes\n"
        "dx = c.Analysis(androguard_rs.Apk(%r))\n"
        "for ma in dx.get_class_analysis('Lcom/ex/Ops;').get_methods():\n"
        "    insn_shapes.method_shape(ma.get_method())\n"
        "assert not any(m == 'androguard' or m.startswith('androguard.') for m in sys.modules), 'androguard imported'\n"
    ) % (str(Path(__file__).resolve().parents[1] / "compat"), str(Path(__file__).resolve().parent), str(path))
    subprocess.run([sys.executable, "-c", code], check=True)
