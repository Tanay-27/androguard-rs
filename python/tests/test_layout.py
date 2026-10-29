"""androguard 4.1.3's module paths, with ``androguard`` renamed to
``androguard_rs``, import and give the same objects as the short paths."""

import importlib
import subprocess
import sys

import pytest

# (androguard path, short path or None, names)
MIRRORED = [
    ("androguard_rs.core.apk", "androguard_rs.apk", ["APK", "FileNotPresent", "BrokenAPKError", "Error", "ARSCParser"]),
    ("androguard_rs.core.dex", "androguard_rs.dex",
     ["DEX", "EncodedMethod", "EncodedField", "ClassDefItem", "DalvikCode", "DCode", "Instruction", "Instruction35c",
      "Instruction11n", "Instruction21h", "Instruction21s", "Instruction31i", "InvalidInstruction"]),
    ("androguard_rs.core.analysis.analysis", "androguard_rs.analysis", ["Analysis", "ClassAnalysis", "MethodAnalysis"]),
    ("androguard_rs.core.axml", "androguard_rs.axml", ["AXMLPrinter", "ARSCParser", "ARSCResTableConfig"]),
    ("androguard_rs.core.api_specific_resources", "androguard_rs.api_specific_resources",
     ["load_permissions", "load_permission_mappings"]),
    ("androguard_rs.core.androconf", None, ["load_api_specific_resource_module", "InvalidResourceError"]),
    ("androguard_rs.misc", None, ["AnalyzeAPK"]),
    ("androguard_rs.util", None, ["set_log"]),
    ("androguard_rs.decompiler", None, []),
]


@pytest.mark.parametrize("path,short,names", MIRRORED, ids=[m[0] for m in MIRRORED])
def test_mirrored(path, short, names):
    mod = importlib.import_module(path)
    for name in names:
        assert getattr(mod, name) is not None
    if short is not None:
        assert mod is importlib.import_module(short)
        for name in names:
            assert getattr(mod, name) is getattr(importlib.import_module(short), name)


def test_import_forms():
    """The common androguard import forms, renamed, in a fresh
    interpreter, both import orders."""
    code = """
import sys
from androguard_rs.core import apk
from androguard_rs.core import api_specific_resources
from androguard_rs.core import androconf
from androguard_rs.core.apk import APK, FileNotPresent
from androguard_rs.core.dex import DEX, EncodedMethod, ClassDefItem, Instruction, Instruction35c, DalvikCode, DCode
from androguard_rs.core.dex import Instruction11n, Instruction21h, Instruction21s, Instruction31i
from androguard_rs.core.analysis.analysis import Analysis, ClassAnalysis, MethodAnalysis
from androguard_rs.core.axml import AXMLPrinter, ARSCParser
from androguard_rs.util import set_log
from androguard_rs.misc import AnalyzeAPK
import androguard_rs.decompiler
import androguard_rs.core.dex, androguard_rs.dex, androguard_rs.apk, androguard_rs.axml, androguard_rs.analysis
assert apk is androguard_rs.apk and apk.APK is APK
assert androguard_rs.core.dex is androguard_rs.dex and androguard_rs.dex.DEX is DEX
assert androguard_rs.analysis.Analysis is Analysis
assert androguard_rs.axml.ARSCParser is ARSCParser is androguard_rs.apk.ARSCParser
assert sys.modules["androguard_rs.core.dex"] is sys.modules["androguard_rs.dex"]
assert sys.getrecursionlimit() == 5000
assert androconf.load_api_specific_resource_module("api_permission_mappings", 16)
assert "android.permission.INTERNET" in androconf.load_api_specific_resource_module("aosp_permissions", 99)
"""
    short_first = "import androguard_rs.dex, androguard_rs.apk, androguard_rs.analysis, androguard_rs.axml\n"
    for prefix in ("", short_first):
        subprocess.run([sys.executable, "-c", prefix + code], check=True)


def test_androconf_matches_androguard():
    ag = pytest.importorskip("androguard.core.androconf")
    from androguard_rs.core import androconf

    for name in ("aosp_permissions", "api_permission_mappings"):
        for api in (None, 0, 3, 11, 16, "19", 20, 28, 34, 40):
            assert androconf.load_api_specific_resource_module(name, api) == \
                ag.load_api_specific_resource_module(name, api), (name, api)
    with pytest.raises(androconf.InvalidResourceError) as ours:
        androconf.load_api_specific_resource_module("nope")
    with pytest.raises(ag.InvalidResourceError) as theirs:
        ag.load_api_specific_resource_module("nope")
    assert str(ours.value) == str(theirs.value)
