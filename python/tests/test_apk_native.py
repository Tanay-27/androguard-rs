"""Standalone tests of the androguard drop-ins (androguard_rs.apk, .axml,
.misc, .util, .api_specific_resources) and of Apk.from_bytes / per-DEX
tolerance. They need lxml but not androguard: inputs are built here
(apkbuild.py, dexbuild.py), and expected values come from apk_goldens.py,
which androguard 4.1.3 produced once from these same inputs.
"""

import random
import struct

import pytest

from androguard_rs.dex import DEX
from lxml import etree

import androguard_rs
from androguard_rs import api_specific_resources, util
from androguard_rs.apk import APK, APK_GAPS, ARSCParser, BrokenAPKError, FileNotPresent
from androguard_rs.axml import AXMLPrinter
from androguard_rs.misc import AnalyzeAPK

import apkbuild as b
import dexbuild
from apk_goldens import GOLDEN

NS = "{http://schemas.android.com/apk/res/android}"


@pytest.fixture(scope="module")
def dex():
    return dexbuild.build(dexbuild.base_spec())[0]


def analyzable_apk():
    """synthetic_apk() of base_spec() with LB;.baz's try pointing at its
    handler: base_spec()'s points at offset 0 of the handler list (its
    count), which androguard's Analysis.add() can't match (IndexError, which
    AnalyzeAPK raises; test_strict.py's base_spec_handler)."""
    spec = dexbuild.base_spec()
    spec["codes"]["c_baz"] = dexbuild.code_item(1, 1, 0, bytes.fromhex("0e00"), tries=struct.pack("<IHH", 0, 1, 1),
                                                handlers=dexbuild.uleb(1) + dexbuild.sleb(0) + dexbuild.uleb(0), n_tries=1)
    return b.synthetic_apk(dexbuild.build(spec)[0])


@pytest.fixture(scope="module")
def apk_bytes(dex):
    return b.synthetic_apk(dex)


@pytest.fixture(scope="module", params=["path", "bytes"])
def apk(request, apk_bytes, tmp_path_factory):
    if request.param == "bytes":
        return APK(apk_bytes, raw=True)
    p = tmp_path_factory.mktemp("apk") / "synthetic.apk"
    p.write_bytes(apk_bytes)
    return APK(str(p))


# ── AXMLPrinter ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", ["manifest", "layout", "packed"])
def test_axml_printer_matches_golden(name):
    valid, packed, pretty, flat = GOLDEN["axml_" + name]
    p = AXMLPrinter(getattr(b, name)())
    assert (p.is_valid(), p.is_packed()) == (valid, packed)
    assert p.get_xml() == pretty
    assert p.get_xml(pretty=False) == flat == p.get_buff()
    assert etree.tostring(p.get_xml_obj(), encoding="utf-8") == flat


def test_axml_invalid_inputs():
    for raw in (b"", b"\x03\x00\x08\x00", b"<?xml version='1.0'?><a/>", b"\x03\x00\x08\x00\xff\xff\xff\xff" + b"\0" * 32):
        try:
            p = AXMLPrinter(raw)
        except androguard_rs.AxmlError:
            continue
        assert not p.is_valid() and p.get_xml_obj() is None
        with pytest.raises(TypeError):  # etree.tostring(None), as androguard
            p.get_xml()


def test_axml_mutations_never_crash():
    """Every outcome is a document or an Exception: no crash, no hang."""
    rng = random.Random(7)
    seeds = [b.manifest(), b.layout(), b.packed()]
    for i in range(3000):
        raw = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 6)):
            k = rng.randrange(len(raw))
            raw[k] = rng.choice([0, 0xFF, 0x7F, 0x80, rng.randrange(256)])
        if rng.random() < 0.2:
            raw = raw[: rng.randrange(len(raw))]
        try:
            p = AXMLPrinter(bytes(raw))
            if p.get_xml_obj() is not None:
                p.get_xml()
        except Exception:
            pass


def test_axml_chunk_looping_back_is_an_error():
    x = b.Axml()
    x.start("a")
    # Junk, then an element header whose header size isn't 16 and whose
    # declared end is before it: androguard 4.1.3 loops forever here.
    x.junk(b"\xaa" * 40 + struct.pack("<HHI", 0x0102, 0x20, 0x20))
    x.end("a")
    with pytest.raises(androguard_rs.AxmlError, match="loops forever"):
        AXMLPrinter(x.build())


def test_axml_too_many_namespaces():
    x = b.Axml()
    for i in range(1100):
        x.start_ns(f"p{i}", f"u{i}")
    x.start("a")
    x.end("a")
    with pytest.raises(androguard_rs.AxmlError, match="namespace"):
        AXMLPrinter(x.build())


# ── APK ───────────────────────────────────────────────────────────────────────


GOLDEN_CALLS = [
    "get_package", "get_min_sdk_version", "get_target_sdk_version", "get_max_sdk_version", "get_androidversion_code",
    "get_androidversion_name", "get_main_activity", "get_files", "get_signature_names", "is_signed", "is_signed_v1",
    "is_signed_v2", "is_signed_v3", "get_certificates_der_v2", "get_certificates_der_v3", "get_declared_permissions",
    "get_declared_permissions_details", "get_libraries", "get_effective_target_sdk_version", "get_activity_aliases",
    "is_multidex",
]


def test_apk_matches_golden(apk):
    for m in GOLDEN_CALLS:
        assert getattr(apk, m)() == GOLDEN[m], m
    for m in ["get_activities", "get_services", "get_receivers", "get_providers", "get_permissions"]:
        assert sorted(getattr(apk, m)()) == GOLDEN[m], m
    assert sorted(map(repr, apk.uses_permissions)) == GOLDEN["uses_permissions"]
    assert list(apk.get_dex_names()) == GOLDEN["get_dex_names"]
    assert etree.tostring(apk.get_android_manifest_xml()) == GOLDEN["manifest_tostring"]
    assert apk.get_android_resources().get_string_resources("com.example.app") == GOLDEN["get_string_resources"]
    assert apk._get_res_string_value("@string/xhtml") == GOLDEN["res_string_value"]
    # str, and int()-able, as in androguard
    assert int(apk.get_min_sdk_version()) == 21 and int(apk.get_target_sdk_version()) == 33


def test_apk_from_bytes_identity(apk_bytes):
    a = APK(apk_bytes, raw=True)
    assert a.filename == GOLDEN["filename"]
    assert a._APK__raw is apk_bytes and a.get_raw() is apk_bytes


def test_apk_from_path_raw(apk, apk_bytes):
    assert bytes(apk._APK__raw) == apk_bytes


def test_manifest_tree_is_lxml_and_stable(apk):
    root = apk.get_android_manifest_xml()
    assert root is apk.get_android_manifest_xml() and id(root) == id(apk.get_android_manifest_xml())
    assert isinstance(root, etree._Element) and apk.xml["AndroidManifest.xml"] is root
    assert root.tag == "manifest" and root.nsmap == {"android": NS[1:-1]}
    assert root.find("application").get(NS + "debuggable") == "true"
    assert [e.get(NS + "name") for e in root.findall(".//application/activity")] == [".MainActivity", "SettingsActivity"]
    assert len(root.xpath(".//action[@*[local-name()='name']='android.intent.action.MAIN']")) == 1
    assert [c.tag for c in root.find("application").getchildren()][:3] == ["activity", "activity", "activity-alias"]
    assert root.find(".//uses-sdk").attrib[NS + "minSdkVersion"] == "21"
    assert len(list(root.iter())) == 25


def test_manifest_queries(apk):
    acts = apk.find_tags("activity")
    assert [apk.get_value_from_tag(t, "name") for t in acts] == [".MainActivity", "SettingsActivity"]
    assert [apk._format_value(apk.get_value_from_tag(t, "name")) for t in acts] == [
        "com.example.app.MainActivity", "com.example.app.SettingsActivity"]
    assert len(apk.find_tags("activity", exported="true")) == 1
    assert len(apk.find_tags_from_xml("AndroidManifest.xml", "meta-data")) == 7
    assert apk.find_tags("manifest") == [apk.get_android_manifest_xml()]
    assert apk.get_attribute_value("application", "debuggable") == "true"
    assert apk.get_attribute_value("provider", "authorities") == "com.example.app.files"
    assert apk.get_value_from_tag(acts[0], "missing") is None
    assert apk.get_android_manifest_axml().get_xml() == GOLDEN["axml_manifest"][2]


def test_files(apk, dex):
    assert apk.get_files() == GOLDEN["get_files"]
    assert apk.get_files() is not apk.get_files()
    assert apk.get_file("assets/a.txt") == b"hello"
    assert apk.get_file("classes.dex") == dex == apk.get_dex() == next(apk.get_all_dex())
    assert apk.zip.read("assets/a.txt") == b"hello"
    with pytest.raises(FileNotPresent):
        apk.get_file("nope")
    with pytest.raises(KeyError):
        apk.zip.read("nope")


def test_signing(apk):
    assert apk.is_signed() is True
    assert len(apk.get_certificates_v1()) == 1  # CERT.RSA (ORPHAN.EC has no .SF)
    assert apk.get_certificates_v1() == [b"rsa"]
    assert apk.get_certificates_v2() == [b"\x30\x06CERT-A", b"\x30\x06CERT-B"]
    assert apk.get_certificates_v3() == [b"\x30\x06CERT-C"]


def test_signing_variants(dex):
    plain = b.synthetic_apk(dex, signing=False)
    a = APK(plain, raw=True)
    assert (a.is_signed_v2(), a.is_signed_v3(), a.get_certificates_v2(), a.get_certificates_v3()) == (False, False, [], [])
    # No EOCD-located central directory offset: androguard leaves the flags None.
    # Sizes at both ends of the block disagree: BrokenAPKError, then False.
    blk = bytearray(b.signing_block([(0x7109871A, b.signer([b"X"]))]))
    blk[0] ^= 1
    a = APK(b.zip_bytes([("AndroidManifest.xml", b.manifest(), 8)], before_cd=bytes(blk)), raw=True)
    with pytest.raises(BrokenAPKError):
        a.is_signed_v2()
    assert a.is_signed_v2() is False and a.is_signed() is False
    # Expected outcomes from androguard 4.1.3 on the same inputs.
    def truncated(cut):
        bad = b.signer([b"X"])[:-cut]
        blk = b.signing_block([(0x7109871A, struct.pack("<I", len(bad) - 4) + bad[4:])])
        return APK(b.zip_bytes([("AndroidManifest.xml", b.manifest(), 8)], before_cd=blk), raw=True)

    # Public key cut short: the signer parses, but b"X" isn't a certificate
    # asn1crypto can load: ValueError every time.
    a = truncated(6)
    assert a.is_signed_v2() is True and a.get_certificates_der_v2() == [b"X"]
    for _ in range(2):
        with pytest.raises(ValueError):
            a.get_certificates_v2()
    # Cut inside the signer: raises once, then returns what was parsed
    # (nothing), as androguard's cache does.
    a = truncated(10)
    with pytest.raises(struct.error, match="^unpack requires a buffer of 4 bytes$"):
        a.get_certificates_v2()
    assert a.get_certificates_v2() == []


def test_no_manifest_and_bad_zip():
    a = APK(b.zip_bytes([("x.txt", b"x", 0)]), raw=True)
    assert (a.get_package(), a.get_min_sdk_version(), a.get_android_manifest_xml(), a.get_activities()) == ("", None, None, [])
    assert a.get_permissions() == [] and a.get_main_activity() is None and a.get_android_resources() is None
    with pytest.raises(androguard_rs.ApkError):
        APK(b"not a zip", raw=True)
    # A non-numeric targetSdkVersion makes androguard's APK() raise ValueError.
    x = b.Axml()
    x.start("manifest", [(None, "package", b.STRING, "p")])
    x.start("uses-sdk", [(b.NS_ANDROID, "targetSdkVersion", b.STRING, "@7F010001")])
    x.end("uses-sdk")
    x.end("manifest")
    with pytest.raises(ValueError):
        APK(b.zip_bytes([("AndroidManifest.xml", x.build(), 0)]), raw=True)


def test_unknown_attributes_are_loud(apk):
    with pytest.raises(NotImplementedError):
        apk.get_app_icon()
    assert APK_GAPS["APK.get_app_icon"] >= 1
    with pytest.raises(AttributeError):
        apk.__no_such_dunder__


def test_zip_reading_rules():
    # apkInspector rules: a repeated name keeps its first position and its
    # last entry; a missing local header means the file can't be read.
    raw = bytearray(b.zip_bytes([("a", b"first", 0), ("b", b"bee", 0), ("a", b"second", 0)]))
    a = APK(bytes(raw), raw=True)
    assert a.get_files() == ["a", "b"] and a.get_file("a") == b"second"
    raw[0:4] = b"XXXX"  # break the first local header ("a", first copy)
    a = APK(bytes(raw), raw=True)
    assert a.get_file("a") == b"second"
    raw = bytearray(b.zip_bytes([("a", b"x", 0), ("b", b"y", 0)]))
    i = raw.index(b"PK\x03\x04", 4)
    raw[i:i + 4] = b"XXXX"
    a = APK(bytes(raw), raw=True)
    assert a.get_files() == ["a", "b"]
    with pytest.raises(FileNotPresent):
        a.get_file("b")


# ── Resources ─────────────────────────────────────────────────────────────────


def test_resources_strings():
    raw = b.arsc_strings("com.example.app", [("app_name", "Example"), ("html", "<b>bold</b> & co")],
                         [("app_name", "Exemple")])
    r = ARSCParser(raw)
    assert r.get_string("com.example.app", "html") == ["html", "<b>bold</b> & co"]
    assert r.get_string("com.example.app", "app_name", "fr") == ["app_name", "Exemple"]
    assert r.get_string("com.example.app", "zzz") is None and r.get_string("other", "html") is None
    assert r.get_string_resources("com.example.app", "fr") == (
        b'<?xml version="1.0" encoding="utf-8"?>\n<resources>\n<string name="app_name">Exemple</string>\n</resources>\n')
    assert r.get_string_resources("other") == b'<?xml version="1.0" encoding="utf-8"?>\n<resources>\n</resources>\n'
    assert ARSCParser.parse_id("@7F010002") == (0x7F010002, None)
    assert ARSCParser.parse_id("@android:01010000") == (0x01010000, "android")
    with pytest.raises(ValueError):
        ARSCParser.parse_id("7F010002")


# ── DEX loading: from bytes, tolerance ────────────────────────────────────────


def test_apk_index_from_bytes(apk_bytes, tmp_path):
    p = tmp_path / "a.apk"
    p.write_bytes(apk_bytes)
    by_path, by_bytes = androguard_rs.Apk(str(p)), androguard_rs.Apk.from_bytes(apk_bytes)
    assert by_path.classes() == by_bytes.classes() and len(by_bytes.classes()) > 0
    assert by_bytes.skipped_dex() == []


@pytest.mark.parametrize("bad, message", [
    (b"dex\n035\0" + b"\0" * 50, "Not a DEX file, Header too small."),
    (b"dex\n035\0" + b"\0" * 32 + struct.pack("<I", 0xCAFEBABE) + b"\0" * 68,
     "This is not a DEX file! Wrong endian tag: '0xcafebabe'"),
])
def test_dex_tolerance(dex, bad, message):
    raw = b.synthetic_apk(dex, extra=[("classes2.dex", bad, 0)])
    with pytest.raises(ValueError, match="classes2.dex"):
        androguard_rs.Apk.from_bytes(raw)
    rs = androguard_rs.Apk.from_bytes(raw, tolerant=True)
    assert rs.skipped_dex() == [("classes2.dex", message)]
    assert rs.classes() == androguard_rs.Apk.from_bytes(b.synthetic_apk(dex)).classes()


def test_byte_swapped_dex_is_not_skipped(dex):
    bad = b"dex\n035\0" + b"\0" * 32 + struct.pack("<I", 0x78563412) + b"\0" * 68
    with pytest.raises(ValueError, match="Byte swapped"):
        androguard_rs.Apk.from_bytes(b.synthetic_apk(dex, extra=[("classes2.dex", bad, 0)]), tolerant=True)


# ── Entry points ──────────────────────────────────────────────────────────────


def test_analyze_apk(tmp_path):
    apk_bytes = analyzable_apk()
    p = tmp_path / "a.apk"
    p.write_bytes(apk_bytes)
    for a, d, dx in (AnalyzeAPK(str(p)), AnalyzeAPK(apk_bytes, raw=True)):
        assert isinstance(a, APK) and a.get_package() == "com.example.app"
        assert len(d) == 1 and isinstance(d[0], DEX)
        assert len(list(dx.get_classes())) > 0
        # The DEX objects are androguard_rs.dex's, served from the same index.
        assert [c.get_name() for c in d[0].get_classes()] == [c.name for c in dx.get_classes() if not c.is_external()]


def test_util_and_permission_mappings():
    assert util.set_log("ERROR") is None
    m = api_specific_resources.load_permission_mappings(25)
    assert len(m) > 1000 and all(isinstance(v, list) for v in m.values())
    assert api_specific_resources.load_permission_mappings("25") == m
    assert api_specific_resources.load_permission_mappings(999) == {}
