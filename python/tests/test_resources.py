"""Resource parity: androguard_rs.Resources vs androguard 4.1.3's ARSCParser.

Compares the ARSCParser query methods (get_packages_names,
get_public_resources, get_resolved_strings, get_resolved_res_configs,
get_resource_xml_name), exhaustively: every package and locale, every rid
androguard has a value for, plus rids it doesn't. Errors must match too:
where androguard raises, Resources raises, including the first-query-only
error of a failed `_analyse()`.

Inputs:
  - each APK in $PARITY_APKS and $PARITY_LARGE_APKS (os.pathsep-separated;
    the second is for APKs too big for test_parity's AnalyzeAPK);
  - synthetic tables covering what real APKs rarely have (UTF-16 pools, compact
    and 16-bit-offset entries, several packages, references and cycles,
    every value type);
  - mutants of all of the above (byte flips, header-field rewrites,
    truncation).
"""

import contextlib
import io
import os
import random
import struct
import zipfile

import pytest
from loguru import logger

logger.disable("androguard")

from androguard.core.apk import APK  # noqa: E402
from androguard.core.axml import ARSCParser, format_value  # noqa: E402

import androguard_rs  # noqa: E402
from arscbuild import synthetic_tables  # noqa: E402

APKS = [p for v in ("PARITY_APKS", "PARITY_LARGE_APKS") for p in os.environ.get(v, "").split(os.pathsep) if p]


def val(v):
    """androguard's resolved value with configs as _get_tuple(), as Resources returns it."""
    if isinstance(v, tuple):
        return (v[0]._get_tuple(), val(v[1]))
    if isinstance(v, list):
        return [val(x) for x in v]
    return v


def deep_items(d):
    """A dict tree as nested item lists, so key order is compared too."""
    return [(k, deep_items(v)) if isinstance(v, dict) else (k, v) for k, v in d.items()]


def call(f, *args):
    try:
        with contextlib.redirect_stdout(io.StringIO()):  # androguard print()s on some bad input
            return ("ok", f(*args))
    except RecursionError:
        return ("err",)
    except Exception:  # noqa: BLE001 - any androguard exception is a match for ResourcesError
        return ("err",)


def transcript(r, pkg, rids, locales, conv=lambda x: x):
    """The query methods, in a fixed order (the first query sees a failed
    analysis), as ("ok", value) / ("err",) pairs."""
    out = [("packages", call(r.get_packages_names))]
    out.append(("public", pkg, call(r.get_public_resources, pkg)))
    s = call(r.get_resolved_strings)
    out.append(("strings", ("ok", deep_items(s[1])) if s[0] == "ok" else s))
    for p, loc in locales:
        out.append(("public", p, loc, call(r.get_public_resources, p, loc)))
    for rid in rids:
        out.append(("name", rid, call(r.get_resource_xml_name, rid)))
        for p in locales_packages(locales):
            out.append(("name", rid, p, call(r.get_resource_xml_name, rid, p)))
        res = call(r.get_resolved_res_configs, rid)
        out.append(("configs", rid, ("ok", conv(res[1])) if res[0] == "ok" else res))
    return out


def locales_packages(locales):
    return list(dict.fromkeys(p for p, _ in locales))


def queries(ag: ARSCParser, pkg: str):
    """What to ask: every package/locale and rid androguard knows, plus misses."""
    locales = [("no.such.package", "\x00\x00"), (pkg, "xx")]
    try:
        for p in ag.get_packages_names():
            locales += [(p, loc) for loc in ag.get_locales(p)]
    except Exception:  # noqa: BLE001 - analysis failed; androguard_rs must fail the same way
        pass
    known = list(ag.resource_values)
    rids = known + [1, 0x7F000000, 0x7FFFFFFF, max(known, default=0) + 1]
    return rids, locales


def assert_same(raw: bytes, pkg: str, label: str, max_rids=None):
    ag = call(ARSCParser, raw)
    ours = call(androguard_rs.Resources, raw)
    assert ag[0] == ours[0], f"{label}: constructor androguard={ag[0]} ours={ours[0]}"
    if ag[0] != "ok":
        return False
    probe = call(ARSCParser, raw)[1]  # a second parser, to learn what to query
    rids, locales = queries(probe, pkg)
    if max_rids is not None:
        rids = rids[:max_rids] + rids[-4:]
    expected = transcript(ag[1], pkg, rids, locales, conv=val)
    got = transcript(ours[1], pkg, rids, locales)
    diffs = [(e, g) for e, g in zip(expected, got) if e != g]
    assert len(expected) == len(got)
    assert not diffs, f"{label}: {len(diffs)}/{len(expected)} differ, e.g. {diffs[:2]}"
    return True


# ---------------------------------------------------------------- real APKs


@pytest.fixture(scope="module", params=APKS or [pytest.param(None, marks=pytest.mark.skip("set PARITY_APKS"))])
def apk(request):
    a = APK(request.param)
    return request.param, a, a.get_android_resources()


def test_from_apk(apk):
    path, a, ag = apk
    ours = androguard_rs.Resources.from_apk(path)
    if ag is None:
        assert ours is None
        return
    raw = a.get_file("resources.arsc")
    pkg = a.get_package()
    assert ours.get_public_resources(pkg) == androguard_rs.Resources(raw).get_public_resources(pkg)


def test_public_resources(apk):
    _, a, ag = apk
    ours = androguard_rs.Resources(a.get_file("resources.arsc"))
    pkg = a.get_package()
    assert ours.get_packages_names() == ag.get_packages_names()
    assert ours.get_public_resources(pkg) == ag.get_public_resources(pkg)
    checked = 0
    for p in ag.get_packages_names():
        for loc in ag.get_locales(p):
            assert ours.get_public_resources(p, loc) == ag.get_public_resources(p, loc), (p, loc)
            checked += 1
    assert ours.get_public_resources("no.such.package") == ag.get_public_resources("no.such.package")
    assert checked > 0


def test_resolved_strings(apk):
    _, a, ag = apk
    ours = androguard_rs.Resources(a.get_file("resources.arsc"))
    expected = ag.get_resolved_strings()
    assert deep_items(ours.get_resolved_strings()) == deep_items(expected)
    assert sum(len(d) for p in expected.values() for d in p.values()) > 0


def test_resolved_res_configs_and_names(apk):
    _, a, ag = apk
    ours = androguard_rs.Resources(a.get_file("resources.arsc"))
    ag._analyse()
    rids = list(ag.resource_values)
    assert ours.rids() == sorted(rids)
    bad = []
    for rid in rids + [0x7F000000, max(rids) + 1, 0xFFFFFFFF]:
        if ours.get_resolved_res_configs(rid) != val(ag.get_resolved_res_configs(rid)):
            bad.append(("configs", hex(rid)))
        if ours.get_resource_xml_name(rid) != ag.get_resource_xml_name(rid):
            bad.append(("name", hex(rid)))
        for p in ag.get_packages_names():
            if ours.get_resource_xml_name(rid, p) != ag.get_resource_xml_name(rid, p):
                bad.append(("name", hex(rid), p))
    assert not bad, f"{len(bad)} differ, e.g. {bad[:5]}"
    with pytest.raises(ValueError):
        ours.get_resolved_res_configs(0)


def test_resolved_strings_walk(apk):
    """Walking get_resolved_strings() in iteration order and naming each rid
    with get_resource_xml_name() gives the same sequence on both: the
    nesting order (package, locale, rid) is part of the result."""
    _, a, ag = apk
    ours = androguard_rs.Resources(a.get_file("resources.arsc"))

    def walk(arsc):
        return [(pkg, locale, rid, arsc.get_resource_xml_name(rid), value)
                for pkg, locales in arsc.get_resolved_strings().items()
                for locale, strings in locales.items()
                for rid, value in strings.items()]

    assert walk(ours) == walk(ag)


# --------------------------------------------------------- synthetic tables


SYNTHETIC = synthetic_tables()


@pytest.mark.parametrize("name", sorted(SYNTHETIC))
def test_synthetic(name):
    assert_same(SYNTHETIC[name], "com.example", name)


def test_synthetic_errors_are_exercised():
    outcomes = {n: call(androguard_rs.Resources, raw)[0] for n, raw in SYNTHETIC.items()}
    assert outcomes["too-many-packages"] == "err" and outcomes["utf8"] == "ok"
    r = androguard_rs.Resources(SYNTHETIC["complex-string"])
    with pytest.raises(androguard_rs.ResourcesError):
        r.get_public_resources("com.example")
    assert b"<public" in r.get_public_resources("com.example")  # partial results afterwards, as androguard


# ------------------------------------------------------------------ mutants


def mutate(raw: bytes, rng: random.Random) -> bytes:
    b = bytearray(raw)
    kind = rng.randrange(5)
    if kind == 0:  # random bytes
        for _ in range(rng.randint(1, 8)):
            b[rng.randrange(len(b))] = rng.randrange(256)
    elif kind == 1:  # a 16/32-bit field set to an edge value
        at = rng.randrange(0, len(b) - 4) & ~1
        v = rng.choice([0, 1, 2, 3, 7, 8, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0xFFFFFFFF, len(b), len(b) - at])
        fmt, mask = rng.choice([("<I", 0xFFFFFFFF), ("<H", 0xFFFF)])
        struct.pack_into(fmt, b, at, v & mask)
    elif kind == 2:  # truncation
        del b[rng.randrange(8, len(b)) :]
    elif kind == 3:  # bit flips
        for _ in range(rng.randint(1, 4)):
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
    else:  # a byte range duplicated elsewhere
        n = rng.randint(1, 64)
        src, dst = rng.randrange(len(b) - n), rng.randrange(len(b) - n)
        b[dst : dst + n] = b[src : src + n]
    return bytes(b)


def mutant_sources():
    srcs = [(n, raw, "com.example") for n, raw in sorted(SYNTHETIC.items())]
    for p in os.environ.get("PARITY_APKS", "").split(os.pathsep):
        if p:
            with zipfile.ZipFile(p) as z:
                if "resources.arsc" in z.namelist():
                    a = APK(p)
                    srcs.append((os.path.basename(p), z.read("resources.arsc"), a.get_package()))
    return srcs


def test_mutants():
    rng = random.Random(int(os.environ.get("ARSC_MUTANT_SEED", "4131")))
    per_source = int(os.environ.get("ARSC_MUTANTS", "150"))
    parsed = failed = 0
    for name, raw, pkg in mutant_sources():
        n = per_source if len(raw) < 64 << 10 else per_source // 5
        for i in range(n):
            m = mutate(raw, rng)
            ok = assert_same(m, pkg, f"{name} mutant {i}", max_rids=None if len(raw) < 64 << 10 else 300)
            parsed += ok
            failed += not ok
    assert parsed > 0 and failed > 0, (parsed, failed)


# ------------------------------------------------------------ text helpers


def test_decode_pool_string():
    rng = random.Random(7)
    alphabet = [0x00, 0x41, 0x7F, 0x80, 0xBF, 0xC2, 0xDF, 0xE0, 0xED, 0xEF, 0xF0, 0xF4, 0xF5, 0xFF, 0xFE, 0xD8, 0xDC, 0xDB, 0xDF]
    for _ in range(200_000):
        n = rng.randint(0, 12)
        raw = bytes(rng.choice(alphabet) if rng.random() < 0.7 else rng.randrange(256) for _ in range(n))
        assert androguard_rs._decode_pool_string(raw, True) == raw.decode("utf-8", "replace"), raw
        assert androguard_rs._decode_pool_string(raw, False) == raw.decode("utf-16", "replace"), raw


def test_format_value():
    rng = random.Random(11)
    datas = [0, 1, 0xF, 0x10, 0x100, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x01000000, 0x7F800000, 0xFF800000, 0x7FC00000, 0x00000001]
    for ty in list(range(0x22)) + [0x7F, 0xFF]:
        if ty == 0x03:
            continue  # strings are looked up, covered above
        for d in datas + [rng.randrange(1 << 32) for _ in range(3000)]:
            try:
                expected = ("ok", format_value(ty, d))
            except Exception:  # noqa: BLE001
                expected = ("err",)
            assert call(androguard_rs._format_value, ty, d) == expected, (hex(ty), hex(d))
