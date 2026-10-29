"""The native androguard_rs.Apk / Resources API on a synthetic two-DEX APK
(fixture_apk.py), with no androguard and no PARITY_APKS needed.

Expected values are goldens from androguard 4.1.3 (mutf8 1.1.0) on the same
APK, generated once by scripts/gen_fixture_goldens.py into
fixture_goldens.py; a few key facts are also spelled out by hand below.
"""

import re
import zipfile
from collections import Counter

import pytest

import androguard_rs
import fixture_apk as fx
from fixture_goldens import G


@pytest.fixture(scope="module")
def apk_path(tmp_path_factory):
    return fx.build_apk(tmp_path_factory.mktemp("fx") / "fixture.apk")


@pytest.fixture(scope="module")
def apk(apk_path):
    return androguard_rs.Apk(apk_path)


def typed(v):
    """As the golden generator spells values: (type name, value), lists
    nested, EncodedArray/EncodedAnnotation as their repr."""
    if isinstance(v, list):
        return ("list", [typed(x) for x in v])
    if isinstance(v, androguard_rs.EncodedObject):
        return ("object", repr(v))
    return (type(v).__name__, v)


def test_classes_order(apk):
    # Defined classes in DEX order (Dup's first appearance), then externals
    # in first-reference order.
    assert apk.classes() == G["classes"]
    assert [n for n, ext in apk.classes() if ext] == [
        "Ljava/lang/Object;", "Ljava/lang/StringBuilder;", "Lcom/ext/Thing;", "Lcom/ext/Lib;"]


def test_class_methods(apk):
    for name, _ in G["classes"]:
        # A class defined twice (com/ex/Dup) is irregular: its rows also
        # carry their MethodAnalysis's key and get_class_name().
        assert [r[:5] for r in apk.class_methods(name)] == G["class_methods"][name], name
    # ExternalMethods follow the class's own, by first reference: Main's
    # inherited baseMethod() (called on Main) is one.
    assert apk.class_methods(fx.MAIN)[-1] == ("Lcom/ex/Main;->baseMethod()V", "baseMethod", "()V", "", True)
    assert apk.class_methods("Lno/such/Class;") is None


def test_class_fields(apk):
    for name, _ in G["classes"]:
        got = [(c, fl, n, t, None if i is None else (i[0], typed(i[1]))) for c, fl, n, t, i in apk.class_fields(name)]
        assert got == G["class_fields"][name], name
    assert apk.class_fields("Lno/such/Class;") is None
    assert apk.class_fields("Ljava/lang/Object;") == []
    # Own fields, then foreign ones in first-access order, once each; an
    # inherited field (Main.baseField) isn't one; a duplicate class gets
    # its earlier definition's own field and accesses too.
    assert [(c, n) for c, _, n, _, _ in apk.class_fields(fx.MAIN)] == [
        (fx.MAIN, "TAG"), (fx.MAIN, "count"), (fx.R_STRING, "title"), (fx.VALUES, "s"), (fx.BASE, "baseField")]
    assert [(c, n) for c, _, n, _, _ in apk.class_fields(fx.DUP)] == [
        (fx.DUP, "two"), (fx.DUP, "one"), (fx.R_STRING, "app_name"), (fx.SECOND, "local")]
    # A field defined in another DEX than the accessing code isn't listed.
    assert [n for _, _, n, _, _ in apk.class_fields(fx.SECOND)] == ["local", "two"]


def test_typed_init_values(apk):
    by_name = {n: i for _, _, n, _, i in apk.class_fields(fx.VALUES)}
    r = {n: i for _, _, n, _, i in apk.class_fields(fx.R_STRING)}
    assert r["app_name"] == ("2131427329", fx.APP_NAME_ID) and type(r["app_name"][1]) is int
    assert r["z_no_value"] is None
    # androguard 4.1.3: numbers are unsigned, floats/doubles their raw bits.
    assert by_name["d_int"][1] == 0xFFFFFFFF and by_name["b_short"][1] == 0xFFFE
    assert by_name["g_double"][1] == 0x3FF8000000000000
    assert by_name["p_true"][1] is True and by_name["q_false"][1] is False and by_name["o_null"] == ("None", None)
    assert by_name["k_method"][1] == ["Lcom/ex/Main;", "helper", ["(I)", "V"]]
    assert by_name["m_array"][1].kind == "EncodedArray"
    assert by_name["n_annotation"][1].kind == "EncodedAnnotation"
    # repr(value) is the repr text, which is class_info()'s.
    for name, _ in G["classes"]:
        info = apk.class_info(name)
        for _, _, _, _, init in apk.class_fields(name):
            if init is not None:
                assert repr(init[1]) == init[0]
        if info:
            own = apk.class_fields(name)[:len(info["fields"])]
            assert [f[3] for f in info["fields"]] == [i[0] if i else "<no encoded init value>" for *_, i in own]


def test_xrefs(apk):
    # androguard's xrefs are sets: compare as multisets (here, sorted).
    for s, exp in G["xref_from"].items():
        assert sorted(apk.xref_from(s)) == exp, s
        assert Counter(apk.callers(s)) == Counter((e[0], e[4]) for e in exp), s
    for s, exp in G["xref_to"].items():
        assert sorted(apk.xref_to(s)) == exp, s
        assert Counter(apk.callees(s)) == Counter((e[0], e[4]) for e in exp), s
    # Cross-DEX: Second.go (classes2.dex) calls Main.helper (classes.dex).
    assert ("Lcom/ex/Second;->go()V", "Lcom/ex/Second;", "go", "()V", 0) in apk.xref_from("Lcom/ex/Main;->helper(I)V")
    assert apk.xref_from("Lno/such/Class;->m()V") == [] and apk.callers("Lno/such/Class;->m()V") == []


def test_hierarchy(apk):
    assert apk.hierarchy() == G["hierarchy"]


def test_class_info(apk):
    for name, info in G["class_info"].items():
        assert apk.class_info(name) == info, name
    assert apk.class_info("Ljava/lang/Object;") is None
    assert apk.class_info(fx.BASE)["access_flags"] == "public abstract"


@pytest.mark.parametrize("jumbo", [False, True])
def test_const_strings(apk, jumbo):
    got = [(cls, *m) for cls, methods in apk.const_strings(include_jumbo=jumbo) for m in methods]
    assert got == G[f"const_strings_{jumbo}"]


def test_bytecode_and_has_code(apk):
    for s, exp in G["bytecode"].items():
        assert apk.has_code(s) == G["has_code"][s], s
        assert apk.bytecode(s) == exp, s
    assert apk.has_code("Lcom/ex/Main;->abstractish()V") is False
    assert apk.bytecode("Ljava/lang/Object;-><init>()V") is None


def test_search_instruction_text(apk):
    for needles, exp in G["search"]:
        assert apk.search_instruction_text(needles) == exp, needles


def test_find_classes_semantics(apk):
    """The facade's find_classes is re.match over classes() names."""
    names = apk.classes()
    for pat, no_ext, exp in G["find_classes"]:
        assert [n for n, ext in names if not (no_ext and ext) and re.match(pat, n)] == exp, pat


def test_methods_using_string(apk):
    for needle, exp in G["methods_using_string"]:
        assert sorted(apk.methods_using_string(needle)) == exp, needle


def test_invalid_bytecode(tmp_path):
    """androguard can't load this APK at all; here the rest still loads and
    bytecode() raises androguard's exception text."""
    apk = androguard_rs.Apk(fx.build_apk(tmp_path / "bad.apk", with_bad=True))
    sig = "Lcom/ex/Bad;->broken()V"
    assert apk.has_code(sig)
    with pytest.raises(androguard_rs.InvalidInstruction) as e:
        apk.bytecode(sig)
    assert (type(e.value).__name__, str(e.value)) == G["bad_bytecode_error"]
    # The rejected method contributes no xrefs or search text.
    assert apk.xref_to(sig) == []
    for needles, exp in G["search"]:
        assert apk.search_instruction_text(needles) == exp, needles
    assert apk.class_methods(fx.MAIN) == G["class_methods"][fx.MAIN]


def test_resources_from_apk(apk_path, tmp_path):
    r = androguard_rs.Resources.from_apk(apk_path)
    a = G["arsc"]
    assert r.get_packages_names() == a["packages"]
    assert r.get_public_resources("com.example") == a["public"]
    assert r.get_resolved_strings() == a["strings"]
    for rid, name in a["names"]:
        assert r.get_resource_xml_name(rid) == name
    for rid, configs in a["configs"]:
        assert r.get_resolved_res_configs(rid) == configs
    assert androguard_rs.Resources.from_apk(fx.build_apk(tmp_path / "noarsc.apk", with_arsc=False)) is None
    with zipfile.ZipFile(apk_path) as z:
        assert androguard_rs.Resources(z.read("resources.arsc")).get_packages_names() == a["packages"]
