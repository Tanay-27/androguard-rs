"""Differential fuzz of the decoder against androguard 4.1.3's
LinearSweepAlgorithm: mutated real method bytecode must give the same
instructions, or an exception with the same str().

    PARITY_APKS=a.apk:b.apk pytest python/tests/test_invalid.py
"""

import os
import random
import zipfile

import pytest
from loguru import logger

logger.disable("androguard")

from androguard.core.dex import DEX, LinearSweepAlgorithm  # noqa: E402

import androguard_rs  # noqa: E402

APKS = [p for p in os.environ.get("PARITY_APKS", "").split(os.pathsep) if p]
MUTANTS_PER_APK = int(os.environ.get("MUTANTS", "20000"))


def androguard_decode(cm, code: bytes):
    try:
        return [(off, ins.get_name(), ins.get_output()) for off, ins in _with_offsets(
            LinearSweepAlgorithm.get_instructions(cm, len(code) // 2, code, 0))]
    except Exception as e:  # noqa: BLE001 - compare whatever androguard raises
        return ("raise", str(e))


def _with_offsets(instructions):
    off = 0
    for ins in instructions:
        yield off, ins
        off += ins.get_length()


def ours(apk, code: bytes):
    try:
        return apk._decode_code(0, code)
    except androguard_rs.InvalidInstruction as e:
        return ("raise", str(e))


def mutate(code: bytes, rng: random.Random) -> bytes:
    b = bytearray(code)
    for _ in range(rng.randint(1, 4)):
        if len(b) < 2:
            break
        r = rng.random()
        i = rng.randrange(len(b))
        if r < 0.35:
            b[i] = rng.randrange(256)
        elif r < 0.6:
            b[i] ^= 1 << rng.randrange(8)
        elif r < 0.75:
            # Payload idents and the unit forms androguard treats specially.
            b[i & ~1: (i & ~1) + 2] = rng.choice([b"\x00\x01", b"\x00\x02", b"\x00\x03", b"\x00\x04", b"\xff\x01", b"\x0e\x01", b"\x3e\x00", b"\xfa\x60"])
        elif r < 0.9 and len(b) > 2:
            del b[(rng.randrange(len(b) // 2) * 2):]
        else:
            b += bytes(rng.randrange(256) for _ in range(2 * rng.randint(1, 4)))
    return bytes(b[: len(b) // 2 * 2])


@pytest.mark.parametrize("apk_path", APKS or [pytest.param(None, marks=pytest.mark.skip("set PARITY_APKS"))])
def test_mutated_bytecode(apk_path):
    with zipfile.ZipFile(apk_path) as z:
        d = DEX(z.read("classes.dex"))
    apk = androguard_rs.Apk(apk_path)
    codes = [m.get_code().get_bc().get_insn() for m in d.get_encoded_methods() if m.get_code() is not None]
    codes = [c for c in codes if len(c) >= 2]
    rng = random.Random(42)
    raised = 0
    for n in range(MUTANTS_PER_APK):
        code = mutate(rng.choice(codes), rng)
        if not code:
            continue
        expected = androguard_decode(d.CM, code)
        got = ours(apk, code)
        raised += isinstance(expected, tuple)
        assert got == expected, (n, code.hex())
    assert raised > 0  # the mutations really do produce invalid bytecode
