"""Crafted DEX files vs androguard 4.1.3: offsets the map list doesn't declare.

androguard looks code_items, class_data_items, type_lists and
encoded_array_items up by exact offset among the items it parsed from the
map list's sections, instead of following the raw offset. Each case here
builds a small DEX (dexbuild.py), redirects an offset or edits the map, and
loads it with androguard's DEX() and with androguard_rs. When androguard
loads it, every class's metadata and every method's code must match. When
androguard raises (and loads nothing), the case records what it raises and
what we do instead.

    pytest python/tests/test_maplist.py
"""

import struct
import zipfile

import pytest
from loguru import logger

logger.disable("androguard")

from androguard.core.dex import DEX  # noqa: E402

import androguard_rs  # noqa: E402
import dexbuild as db  # noqa: E402

CLASSES = ["LA;", "LB;", "LI;"]
SIGS = ["LA;-><init>()V", "LA;->bar()V", "LA;->foo(I)I", "LB;->baz()V"]


def androguard_view(data: bytes):
    try:
        d = DEX(data)
    except Exception as e:  # noqa: BLE001 - recording what androguard raises
        return type(e).__name__
    classes, code = {}, {}
    for c in d.get_classes():
        classes[c.get_name()] = {
            "name": c.get_name(),
            "access_flags": c.get_access_flags_string(),
            "superclass": c.get_superclassname(),
            "interfaces": list(c.get_interfaces()),
            "methods": [(m.get_name(), m.get_descriptor(), m.get_access_flags_string()) for m in c.get_methods()],
            "fields": [(f.get_access_flags_string(), f.get_name(), f.get_descriptor(),
                        "<no encoded init value>" if f.get_init_value() is None
                        else repr(f.get_init_value().get_value())) for f in c.get_fields()],
        }
        for m in c.get_methods():
            s = f"{m.get_class_name()}->{m.get_name()}{m.get_descriptor().replace(' ', '')}"
            code[s] = None if m.get_code() is None else [
                (off, i.get_name(), i.get_output()) for off, i in m.get_instructions_idx()]
    return classes, code


def ours_view(apk, names, sigs):
    classes, code = {}, {}
    for n in names:
        try:
            classes[n] = apk.class_info(n)
        except ValueError:
            classes[n] = "raise"
    for s in sigs:
        code[s] = apk.bytecode(s) if apk.has_code(s) else None
    return classes, code


def load_ours(data: bytes, tmp_path):
    p = tmp_path / "t.apk"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("classes.dex", data)
    return androguard_rs.Apk(str(p))


def run(spec, tmp_path):
    data, labels = db.build(spec)
    return androguard_view(data), load_ours(data, tmp_path), labels


def assert_same(expected, apk):
    classes, code = expected
    assert ours_view(apk, classes, code) == (classes, code)


# --- spec edits -------------------------------------------------------------

def set_class(spec, i, **kw):
    keys = ["cls", "flags", "sup", "ifaces", "cd", "sv"]
    c = dict(zip(keys, spec["classes"][i]))
    c.update(kw)
    spec["classes"][i] = tuple(c[k] for k in keys)


def foo_code_at(spec, label, delta=0):
    """Point LA;->foo's code_off at `label` (+delta)."""
    spec["class_datas"]["cd_A"] = lambda L: db.class_data(
        static=[(1, 0x9), (2, 0x9)], instance=[(0, 0x2)], direct=[(0, 0x10001, L["c_init"])],
        virtual=[(1, 0x401, 0), (2, 0x1, L[label] + delta)])


def copy_code(spec):
    spec["extra"]["x_foo"] = spec["codes"]["c_foo"]


def map_entry(ty, size, label, delta=0, before=False):
    def hook(entries, L):
        e = [ty, size, L[label] + delta]
        if before:
            i = next(k for k, x in enumerate(entries) if x[0] == ty)
            entries.insert(i, e)
        else:
            entries.insert(len(entries) - 1, e)
    return hook


def edit_map(ty, f):
    def hook(entries, L):
        for e in entries:
            if e[0] == ty:
                f(e, L)
    return hook


def chain(*hooks):
    def hook(entries, L):
        for h in hooks:
            h(entries, L)
    return hook


# --- cases androguard loads: everything must match --------------------------

def base(spec):
    pass


def code_undeclared_copy(spec):
    copy_code(spec)
    foo_code_at(spec, "x_foo")


def code_inside_item(spec):
    foo_code_at(spec, "c_foo", 4)


def code_declared_by_larger_count(spec):
    # The copy right after the code section becomes the 4th code_item.
    copy_code(spec)
    foo_code_at(spec, "x_foo")
    spec["map_hook"] = edit_map(db.CODE, lambda e, L: e.__setitem__(1, e[1] + 1))


def code_second_entry_last(spec):
    # Two CODE_ITEM entries: only the last one's items have code.
    copy_code(spec)
    foo_code_at(spec, "x_foo")
    spec["map_hook"] = map_entry(db.CODE, 1, "x_foo")


def code_second_entry_first(spec):
    copy_code(spec)
    foo_code_at(spec, "x_foo")
    spec["map_hook"] = map_entry(db.CODE, 1, "x_foo", before=True)


def code_entry_offset_mod4_is_2(spec):
    # MapItem seeks to offset + offset % 4: 2 bytes early lands exactly.
    spec["map_hook"] = edit_map(db.CODE, lambda e, L: e.__setitem__(2, e[2] - 2))


def class_data_undeclared_copy(spec):
    spec["extra"]["x_cdA"] = lambda L: spec["class_datas"]["cd_A"](L)
    set_class(spec, 0, cd="x_cdA")


def class_data_inside_item(spec):
    spec["patch"] = lambda buf, L: db.set_class_field(buf, L, 1, 6, L["cd_B"] + 1)


def class_data_declared_by_second_entry(spec):
    spec["extra"]["x_cdA"] = lambda L: spec["class_datas"]["cd_A"](L)
    set_class(spec, 0, cd="x_cdA")
    spec["map_hook"] = map_entry(db.CLASS_DATA, 1, "x_cdA")


def class_data_count_short(spec):
    spec["map_hook"] = edit_map(db.CLASS_DATA, lambda e, L: e.__setitem__(1, 1))


def class_data_overlapping_entries(spec):
    spec["map_hook"] = chain(map_entry(db.CLASS_DATA, 1, "cd_B"), map_entry(db.CLASS_DATA, 2, "cd_A"))


def class_data_shared(spec):
    # LB; shares LA;'s class_data: androguard shows LA;'s static values on
    # both, since they share one ClassDataItem object.
    set_class(spec, 1, cd="cd_A")


def class_data_shared_values_last_writer_wins(spec):
    set_class(spec, 1, cd="cd_A", sv="ea_B")
    spec["encoded_arrays"]["ea_B"] = db.uleb(1) + bytes([0x04, 9])


def class_data_shared_values_partial_overwrite(spec):
    set_class(spec, 0, sv="ea_B")
    set_class(spec, 1, cd="cd_A", sv="ea_A")
    spec["encoded_arrays"]["ea_B"] = db.uleb(1) + bytes([0x04, 9])
    set_class(spec, 2, cd="cd_A", sv="ea_B")


def static_values_undeclared_without_class_data(spec):
    spec["extra"]["x_ea"] = spec["encoded_arrays"]["ea_A"]
    set_class(spec, 2, sv="x_ea")


def interfaces_declared_by_second_entry(spec):
    spec["extra"]["x_tl"] = struct.pack("<IH", 1, 3) + b"\0\0"
    set_class(spec, 0, ifaces="x_tl")
    spec["map_hook"] = map_entry(db.TYPE_LIST, 1, "x_tl")


def type_list_entry_offset_mod4_is_2(spec):
    spec["map_hook"] = edit_map(db.TYPE_LIST, lambda e, L: e.__setitem__(2, e[2] - 2))


def uleb_fifth_byte_continuation(spec):
    # foo's access_flags as a 5-byte uleb whose 5th byte has its high bit
    # set: androguard stops after 5 bytes anyway and keeps all 8 bits.
    spec["class_datas"]["cd_A"] = lambda L: db.class_data(
        static=[(1, 0x9), (2, 0x9)], instance=[(0, 0x2)], direct=[(0, 0x10001, L["c_init"])],
        virtual=[(1, 0x401, 0), (2, bytes([0x80, 0x80, 0x80, 0x80, 0x90]), L["c_foo"])])


def code_off_past_32_bits(spec):
    spec["class_datas"]["cd_A"] = lambda L: db.class_data(
        static=[(1, 0x9), (2, 0x9)], instance=[(0, 0x2)], direct=[(0, 0x10001, L["c_init"])],
        virtual=[(1, 0x401, 0), (2, 0x1, bytes([0x80 | (L["c_foo"] & 0x7F), 0x80 | (L["c_foo"] >> 7), 0x80, 0x80, 0x10]))])


LOADS = [
    base, code_undeclared_copy, code_inside_item, code_declared_by_larger_count, code_second_entry_last,
    code_second_entry_first, code_entry_offset_mod4_is_2, class_data_undeclared_copy, class_data_inside_item,
    class_data_declared_by_second_entry, class_data_count_short, class_data_overlapping_entries,
    class_data_shared, class_data_shared_values_last_writer_wins, class_data_shared_values_partial_overwrite,
    static_values_undeclared_without_class_data, interfaces_declared_by_second_entry,
    type_list_entry_offset_mod4_is_2, uleb_fifth_byte_continuation, code_off_past_32_bits,
]


@pytest.mark.parametrize("case", LOADS, ids=lambda f: f.__name__)
def test_loads_and_matches(case, tmp_path):
    spec = db.base_spec()
    case(spec)
    expected, apk, _ = run(spec, tmp_path)
    assert not isinstance(expected, str), f"androguard raised {expected}"
    assert_same(expected, apk)


def test_cases_change_something(tmp_path):
    """Guard against cases that silently stopped testing anything."""
    base_view, _, _ = run(db.base_spec(), tmp_path)
    same = []
    for case in LOADS[1:]:
        spec = db.base_spec()
        case(spec)
        if run(spec, tmp_path)[0] == base_view:
            same.append(case.__name__)
    # These point at a copy the map does declare, or check that a quirk of
    # the map's layout changes nothing.
    assert same == ["code_declared_by_larger_count", "code_entry_offset_mod4_is_2",
                    "class_data_declared_by_second_entry", "class_data_overlapping_entries",
                    "static_values_undeclared_without_class_data", "interfaces_declared_by_second_entry",
                    "type_list_entry_offset_mod4_is_2"]


# --- cases androguard can't load ---------------------------------------------
# androguard raises out of DEX() and loads nothing. We keep the DEX and fail
# only the affected query; everything else matches the unmodified file.

def static_values_undeclared(spec):
    spec["extra"]["x_ea"] = spec["encoded_arrays"]["ea_A"]
    set_class(spec, 0, sv="x_ea")


def static_values_in_earlier_entry(spec):
    # Only the last ENCODED_ARRAY_ITEM entry is searched.
    spec["extra"]["x_ea"] = db.uleb(0)
    spec["map_hook"] = map_entry(db.ENCODED_ARRAY, 1, "x_ea")


def static_values_without_section(spec):
    spec["map_hook"] = lambda entries, L: entries.remove(next(e for e in entries if e[0] == db.ENCODED_ARRAY))


def interfaces_undeclared(spec):
    spec["extra"]["x_tl"] = struct.pack("<IH", 1, 3) + b"\0\0"
    set_class(spec, 0, ifaces="x_tl")


def annotations_without_section(spec):
    spec["patch"] = lambda buf, L: db.set_class_field(buf, L, 0, 5, L["ea_A"])


RAISES = [
    # case, androguard's exception, the class whose class_info raises for us
    (static_values_undeclared, "AttributeError", "LA;"),
    (static_values_in_earlier_entry, "AttributeError", "LA;"),
    (static_values_without_section, "KeyError", "LA;"),
    (interfaces_undeclared, "KeyError", "LA;"),
    (annotations_without_section, "KeyError", "LA;"),
]


@pytest.mark.parametrize("case,exc,cls", RAISES, ids=lambda x: getattr(x, "__name__", None))
def test_androguard_raises_class_info_raises(case, exc, cls, tmp_path):
    expected, _, _ = run(db.base_spec(), tmp_path)
    spec = db.base_spec()
    case(spec)
    got, apk, _ = run(spec, tmp_path)
    assert got == exc
    classes, code = expected
    classes = dict(classes, **{cls: "raise"})
    assert ours_view(apk, classes, code) == (classes, code)


def test_parameters_undeclared(tmp_path):
    """foo's proto points at a type_list copy the map doesn't declare.
    androguard raises KeyError building its method table. We render the
    proto as androguard renders an invalid one, and foo can't be looked up
    by signature."""
    spec = db.base_spec()
    spec["extra"]["x_tl"] = struct.pack("<IH", 1, 0) + b"\0\0"
    spec["protos"][1] = (spec["protos"][1][0], spec["protos"][1][1], "x_tl")
    got, apk, _ = run(spec, tmp_path)
    assert got == "KeyError"
    a = apk.class_info("LA;")
    assert a["methods"][2] == ("foo", "AG:IPI:invalid_params;(AG:IPI:invalid_return_type)", "public")
    assert not apk.has_code("LA;->foo(I)I")
    assert apk.has_code("LA;-><init>()V")


def test_unknown_map_type(tmp_path):
    """androguard raises ValueError on a map item type it doesn't know; we
    ignore the entry."""
    expected, _, _ = run(db.base_spec(), tmp_path)
    spec = db.base_spec()
    spec["map_hook"] = lambda entries, L: entries.insert(1, [0x9999, 1, 0])
    got, apk, _ = run(spec, tmp_path)
    assert got == "ValueError"
    assert_same(expected, apk)


@pytest.mark.parametrize("delta", [1, 3, 5])
def test_code_count_past_section(delta, tmp_path):
    """A CODE_ITEM count larger than the section walks into the bytes after
    it. One more takes in the code_item copy that follows (it loads, and
    we match); more runs into string data and androguard raises."""
    spec = db.base_spec()
    copy_code(spec)
    spec["map_hook"] = edit_map(db.CODE, lambda e, L: e.__setitem__(1, e[1] + delta))
    got, apk, _ = run(spec, tmp_path)
    if delta == 1:
        assert_same(got, apk)
    else:
        # struct.error partway through the section; we keep what parsed.
        assert got == "error"
        assert apk.has_code("LA;->foo(I)I")


# What androguard 4.1.3 does with a CODE_ITEM / TYPE_LIST entry moved by
# `delta` bytes off its section start: it seeks to offset + offset % 4, so
# CODE at -3 still lands on the section (after aligning up); the rest raise
# struct.error mid-section, or KeyError when the shifted type_lists no
# longer include a class's interfaces_off.
MISALIGNED = [(db.CODE, -1, "error"), (db.CODE, -3, None), (db.CODE, 1, "error"), (db.CODE, 2, "error"),
              (db.CODE, 3, "error"), (db.TYPE_LIST, -1, "error"), (db.TYPE_LIST, -3, "error"),
              (db.TYPE_LIST, 1, "error"), (db.TYPE_LIST, 2, "KeyError"), (db.TYPE_LIST, 3, "error")]


@pytest.mark.parametrize("ty,delta,exc", MISALIGNED)
def test_misaligned_section_offsets(ty, delta, exc, tmp_path):
    spec = db.base_spec()
    spec["map_hook"] = edit_map(ty, lambda e, L: e.__setitem__(2, e[2] + delta))
    got, apk, _ = run(spec, tmp_path)
    if exc is None:
        assert_same(got, apk)
    else:
        assert got == exc
        apk.stats()  # loads, and every query still answers
        for c in CLASSES:
            try:
                apk.class_info(c)
            except ValueError:
                pass
