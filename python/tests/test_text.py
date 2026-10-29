"""Our lower-casing (used by search_instruction_text) vs Python's str.lower()."""

import random
import sys

import androguard_rs


def test_every_code_point():
    bad = [
        cp
        for cp in range(sys.maxunicode + 1)
        if not 0xD800 <= cp <= 0xDFFF and androguard_rs._py_lower(chr(cp)) != chr(cp).lower()
    ]
    assert not bad, [hex(c) for c in bad[:20]]


def test_final_sigma_contexts():
    # Final-sigma lowering depends on the neighbouring characters.
    rng = random.Random(7)
    pool = ["Σ", "A", "a", " ", "'", "́", "1", "Ω", ".", "­", "İ", "ſ", "K"]
    for _ in range(200_000):
        s = "".join(
            rng.choice(pool) if rng.random() < 0.7 else chr(rng.choice([rng.randrange(0x80, 0xD800), rng.randrange(0xE000, 0x110000)]))
            for _ in range(rng.randint(1, 8))
        )
        assert androguard_rs._py_lower(s) == s.lower(), ascii(s)
