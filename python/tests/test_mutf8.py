"""Differential fuzz: our DEX string decoding vs the `mutf8` C extension that
androguard uses. Pin the version under test with MUTF8_VERSION (default
1.1.0, what an unpinned install of androguard 4.1.3 resolves to)."""

import importlib.metadata
import os
import random

import mutf8

import androguard_rs

ALPHABET = [0x00, 0x41, 0x7F, 0x80, 0x9F, 0xA0, 0xAF, 0xB0, 0xBF, 0xC0, 0xC3, 0xDF, 0xE0, 0xE2, 0xED, 0xEF, 0xF0, 0xF4, 0xF8, 0xFF]
SAMPLES = [
    b"abc", b"\x80", b"\xf0\x9f\x98\x80", b"\xed\xa0\x80", b"\xed\xa0\x80xyz12", b"\xed\xa1\x80\xed\xb0\x80",
    b"\xed\xaf\xbf\xed\xbf\xbf", b"\xc0\x80", b"\xc3", b"\xe2\x82", b"\xed\xb8\x80", b"\xed\xa0\x80\xed\xa0\x80",
    b"\xc3(", b"\xe2(\xa1", b"\xf0\x9f\x98\x80\xc0\x80", b"\xc1\x81", b"\xf5\x80\x80\x80",
]


def expected(raw: bytes):
    try:
        return mutf8.decode_modified_utf8(raw)
    except UnicodeDecodeError:
        return None


def test_version_under_test():
    assert importlib.metadata.version("mutf8") == os.environ.get("MUTF8_VERSION", "1.1.0")


def test_samples():
    for raw in SAMPLES:
        assert androguard_rs._decode_dex_string(raw) == expected(raw), raw


def test_random():
    rng = random.Random(1234)
    for _ in range(300_000):
        n = rng.randint(1, 12)
        raw = bytes(
            rng.choice(ALPHABET) if rng.random() < 0.6 else rng.randint(1, 255) for _ in range(n)
        ).replace(b"\x00", b"\x01")  # DEX strings are NUL-terminated, so never contain 0x00
        assert androguard_rs._decode_dex_string(raw) == expected(raw), raw
