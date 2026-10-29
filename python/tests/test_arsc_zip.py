"""Resources.from_apk() on tampered zips (arsc_zip_cases.py): the
resources.arsc bytes androguard's APK.get_android_resources() reads,
apkInspector's way, against goldens from androguard 4.1.3
(arsc_zip_goldens.py), and live against androguard when it is installed.
"""

import logging

import pytest

import androguard_rs
import arsc_zip_cases as Z
from androguard_rs.apk import APK as NativeAPK
from arsc_zip_goldens import GOLDEN


@pytest.fixture(params=list(Z.CASES))
def case(request, tmp_path):
    raw = Z.CASES[request.param]()
    path = tmp_path / f"{request.param}.apk"
    path.write_bytes(raw)
    return request.param, raw, str(path)


def ours(path):
    res = androguard_rs.Resources.from_apk(path)
    raw = None if res is None else NativeAPK(path).get_file("resources.arsc")
    return Z.view(res, raw)


def test_from_apk(case):
    name, _, path = case
    assert Z.outcome(lambda: ours(path)) == GOLDEN[name]


def test_native_apk_resources(case):
    """androguard_rs.apk.APK's get_android_resources() reads the same."""
    name, raw, _ = case

    def native():
        a = NativeAPK(raw, raw=True)
        res = a.get_android_resources()
        return Z.view(res, None if res is None else a.get_file("resources.arsc"))

    assert Z.outcome(native) == GOLDEN[name]


def test_live(case):
    pytest.importorskip("androguard")
    from androguard.core.apk import APK
    from loguru import logger

    logger.disable("androguard")
    name, raw, path = case
    logging.disable(logging.WARNING)
    try:
        def ag():
            a = APK(raw, raw=True)
            res = a.get_android_resources()
            return Z.view(res, None if res is None else a.get_file("resources.arsc"))

        assert Z.outcome(lambda: ours(path)) == Z.outcome(ag)
    finally:
        logging.disable(logging.NOTSET)
