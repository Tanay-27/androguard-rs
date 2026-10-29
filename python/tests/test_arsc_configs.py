"""ARSCParser.get_resolved_res_configs() returns androguard 4.1.3's
ARSCResTableConfig objects: same values, and configs equal in type name,
every attribute (vars()), repr(), hash() and method results, the first
chunk's object kept for equal configs. Goldens from androguard 4.1.3
(scripts/gen_arsc_config_goldens.py); live against androguard too when it
is installed, on the synthetic tables and on every rid of $PARITY_APKS."""

import os
import zipfile

import pytest

import arsc_config_cases as C
from androguard_rs.apk import ARSCParser
from androguard_rs.axml import ARSCResTableConfig
from arsc_config_goldens import GOLDENS
from arsc_config_view import tree_view


@pytest.mark.parametrize("name", sorted(C.tables()))
def test_goldens(name):
    p = ARSCParser(C.tables()[name])
    assert [(rid, tree_view(p.get_resolved_res_configs(rid))) for rid in C.RIDS] == GOLDENS[name]


def test_objects_and_identity():
    p = ARSCParser(C.tables()["config-shapes"])
    res = p.get_resolved_res_configs(0x7F010000)
    assert all(isinstance(c, ARSCResTableConfig) for c, _ in res)
    # one object per type chunk, as androguard's resource_values keys
    again = p.get_resolved_res_configs(0x7F010000)
    assert [c for c, _ in res] == [c for c, _ in again]
    with pytest.raises(NotImplementedError):
        p.get_resolved_res_configs(0x7F010000, config=res[0][0])


def _androguard():
    try:
        from loguru import logger

        logger.disable("androguard")
        from androguard.core.axml import ARSCParser as AgParser
        return AgParser
    except ImportError:
        return None


@pytest.mark.parametrize("name", sorted(C.tables()))
def test_live(name):
    AgParser = _androguard()
    if AgParser is None:
        pytest.skip("androguard not installed")
    raw = C.tables()[name]
    ag, ours = AgParser(raw), ARSCParser(raw)
    for rid in C.RIDS:
        a, o = ag.get_resolved_res_configs(rid), ours.get_resolved_res_configs(rid)
        assert o == a
        assert tree_view(o) == tree_view(a)


APKS = [p for p in os.environ.get("PARITY_APKS", "").split(os.pathsep) if p]


@pytest.mark.parametrize("path", APKS)
def test_live_apk(path):
    AgParser = _androguard()
    if AgParser is None:
        pytest.skip("androguard not installed")
    with zipfile.ZipFile(path) as z:
        if "resources.arsc" not in z.namelist():
            pytest.skip("no resources.arsc")
        raw = z.read("resources.arsc")
    ag, ours = AgParser(raw), ARSCParser(raw)
    ag._analyse()
    rids = list(ag.resource_values)
    assert rids or not ag.get_packages_names()
    for rid in rids:
        a, o = ag.get_resolved_res_configs(rid), ours.get_resolved_res_configs(rid)
        assert o == a, hex(rid)
        assert tree_view(o) == tree_view(a), hex(rid)
