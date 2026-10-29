"""Instruction API parity against androguard 4.1.3's AnalyzeAPK on every APK
in $PARITY_APKS: for every method of every defined class, everything
insn_shapes.method_shape() observes (per instruction: class, name, opcode,
length, raw bytes, operands, translated kind, output, literals, format
fields, show_buff, str, hex, disasm; get_instruction(idx) and
get_instruction(0, off) lookups, in range and out; object identity across
calls), exactly.

    PARITY_APKS=a.apk:b.apk pytest python/tests/test_insn_parity.py
"""

import os
import sys
from pathlib import Path

import pytest
from loguru import logger

logger.disable("androguard")

from androguard.misc import AnalyzeAPK  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "compat"))
import androguard_compat as compat  # noqa: E402

from insn_shapes import method_shape  # noqa: E402

APKS = [p for p in os.environ.get("PARITY_APKS", "").split(os.pathsep) if p]


@pytest.mark.parametrize("apk", APKS or [pytest.param(None, marks=pytest.mark.skip("set PARITY_APKS"))])
def test_every_instruction(apk):
    _, _, dx = AnalyzeAPK(apk)
    _, _, cdx = compat.analyze_apk(apk)
    methods = instructions = 0
    diffs = []
    for ca in dx.get_classes():
        if ca.is_external():
            continue
        ours = {}
        for ma in cdx.get_class_analysis(ca.name).get_methods():
            em = ma.get_method()
            ours[(em.get_name(), em.get_descriptor())] = em
        for ma in ca.get_methods():
            if ma.is_external():
                continue
            em = ma.get_method()
            want = method_shape(em)
            got = method_shape(ours[(em.get_name(), em.get_descriptor())])
            methods += 1
            instructions += len(want.get("insns", ()))
            if got != want:
                diffs.append(f"{ca.name}->{em.get_name()}{em.get_descriptor()}")
    print(f"{Path(apk).name}: {methods} methods, {instructions} instructions, {len(diffs)} differences")
    assert diffs == []
