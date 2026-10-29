"""APK-side parity: androguard_rs.apk.APK / androguard_rs.axml.AXMLPrinter vs
androguard 4.1.3's APK / AXMLPrinter, on real APKs.

For each APK in $PARITY_APKS (os.pathsep-separated): every implemented APK
method (from a path and from bytes), every zip entry's
bytes, and AXMLPrinter on every .xml entry (get_xml() pretty and not,
is_valid(), is_packed(), or both raising). Zero differences required.

Comparisons where androguard's own output isn't reproducible are made
order-free: find_tags() (androguard keeps lxml elements in a set, i.e. in
memory-address order) and everything derived from it (get_activities() & co.,
get_permissions(), which is list(set(...))).

v1 certificates are compared by count (androguard verifies and returns
asn1crypto objects; androguard_rs returns the unverified PKCS#7 files), v2/v3
certificates by their DER bytes.

    PARITY_APKS=a.apk:b.apk pytest python/tests/test_apk_parity.py
"""

import hashlib
import os

import pytest

APKS = [p for p in os.environ.get("PARITY_APKS", "").split(os.pathsep) if p]

pytestmark = pytest.mark.skipif(not APKS, reason="set PARITY_APKS")

if APKS:
    from loguru import logger

    logger.disable("androguard")
    from androguard.core.apk import APK as AgAPK
    from androguard.core.axml import AXMLPrinter as AgPrinter
    from lxml import etree

    from androguard_rs.apk import APK as RsAPK
    from androguard_rs.axml import AXMLPrinter as RsPrinter


def outcome(f, *args):
    """("ok", value) or ("raises", exception type name, str())."""
    try:
        return ("ok", f(*args))
    except Exception as e:  # noqa: BLE001
        return ("raises", type(e).__name__, str(e))


def printer_outcome(cls, raw):
    try:
        p = cls(raw)
    except Exception:
        return ("raises",)
    return (
        "ok",
        p.is_valid(),
        p.is_packed(),
        outcome(p.get_xml),
        outcome(p.get_xml, False),
        None if p.get_xml_obj() is None else etree.tostring(p.get_xml_obj()),
    )


def tags_key(elems):
    return sorted(etree.tostring(e) for e in elems)


def manifest_view(a):
    """Everything the callers use, as comparable plain data."""
    out = {}
    calls = {
        "get_package": a.get_package,
        "get_min_sdk_version": a.get_min_sdk_version,
        "get_target_sdk_version": a.get_target_sdk_version,
        "get_max_sdk_version": a.get_max_sdk_version,
        "get_effective_target_sdk_version": a.get_effective_target_sdk_version,
        "get_androidversion_code": a.get_androidversion_code,
        "get_androidversion_name": a.get_androidversion_name,
        "get_main_activity": a.get_main_activity,
        "get_main_activities": lambda: sorted(a.get_main_activities()),
        "get_activities": lambda: sorted(a.get_activities()),
        "get_services": lambda: sorted(a.get_services()),
        "get_receivers": lambda: sorted(a.get_receivers()),
        "get_providers": lambda: sorted(a.get_providers()),
        "get_permissions": lambda: sorted(a.get_permissions()),
        "get_declared_permissions_details": a.get_declared_permissions_details,
        "uses_permissions": lambda: sorted(map(repr, a.uses_permissions)),
        "get_libraries": lambda: sorted(a.get_libraries()),
        "get_features": lambda: sorted(a.get_features()),
        "get_activity_aliases": lambda: sorted(map(repr, a.get_activity_aliases())),
        "is_valid_APK": a.is_valid_APK,
        "manifest_xml": lambda: None if a.get_android_manifest_xml() is None else etree.tostring(a.get_android_manifest_xml()),
        "manifest_nsmap": lambda: None if a.get_android_manifest_xml() is None else a.get_android_manifest_xml().nsmap,
        "xml_keys": lambda: list(a.xml),
        "get_files": a.get_files,
        "get_dex_names": lambda: list(a.get_dex_names()),
        "is_multidex": a.is_multidex,
        "get_signature_names": a.get_signature_names,
        "get_signature_name": a.get_signature_name,
        "is_signed": a.is_signed,
        "is_signed_v1": a.is_signed_v1,
        "is_signed_v2": a.is_signed_v2,
        "is_signed_v3": a.is_signed_v3,
        "v1_cert_count": lambda: len(a.get_certificates_v1() or []),
        "v2_certs": lambda: [c if isinstance(c, bytes) else c.dump() for c in a.get_certificates_v2()],
        "v3_certs": lambda: [c if isinstance(c, bytes) else c.dump() for c in a.get_certificates_v3()],
        "raw_sha256": lambda: hashlib.sha256(a._APK__raw).hexdigest(),
        "has_resources": lambda: a.get_android_resources() is not None,
    }
    for tag in ("activity", "service", "receiver", "provider", "permission", "uses-permission", "meta-data",
                "intent-filter", "action", "application", "manifest", "uses-sdk"):
        calls[f"find_tags({tag})"] = lambda tag=tag: tags_key(a.find_tags(tag))
        calls[f"find_tags_from_xml({tag})"] = lambda tag=tag: tags_key(a.find_tags_from_xml("AndroidManifest.xml", tag))
        # androguard returns the first in set order; compare the candidates.
        calls[f"get_all_attribute_value({tag},name)"] = lambda tag=tag: sorted(
            a.get_all_attribute_value(tag, "name", format_value=False))
    for name, f in calls.items():
        out[name] = outcome(f)
    for tag in ("activity", "service", "uses-sdk", "application"):
        v = outcome(a.get_attribute_value, tag, "name")
        cands = out[f"get_all_attribute_value({tag},name)"]
        out[f"get_attribute_value({tag},name) in candidates"] = (
            v[0] == "ok" and cands[0] == "ok" and (v[1] in cands[1] or (v[1] is None and not cands[1])))
    # get_value_from_tag / _format_value over every manifest element.
    root = a.get_android_manifest_xml() if "AndroidManifest.xml" in a.xml else None
    if root is not None:
        vals = []
        for e in root.iter():
            for attr in ("name", "exported", "permission", "value", "launchMode", "taskAffinity"):
                v = a.get_value_from_tag(e, attr)
                vals.append((v, a._format_value(v)))
        out["get_value_from_tag"] = sorted(map(repr, vals))
    return out


@pytest.fixture(scope="module", params=APKS)
def pair(request):
    path = request.param
    return path, AgAPK(path), RsAPK(path)


def test_manifest_and_signing(pair):
    path, ag, rs = pair
    want, got = manifest_view(ag), manifest_view(rs)
    diffs = [k for k in want if want[k] != got[k]]
    assert not diffs, f"{path}: " + "; ".join(f"{k}: {want[k]!r:.300} != {got[k]!r:.300}" for k in diffs)


def test_from_bytes(pair):
    path, ag, _ = pair
    with open(path, "rb") as f:
        data = f.read()
    rs = RsAPK(data, raw=True)
    agr = AgAPK(data, raw=True)
    want, got = manifest_view(agr), manifest_view(rs)
    diffs = [k for k in want if want[k] != got[k]]
    assert not diffs, f"{path}: " + "; ".join(f"{k}: {want[k]!r:.300} != {got[k]!r:.300}" for k in diffs)
    assert rs.filename == agr.filename
    assert rs._APK__raw is data


def test_every_file(pair):
    path, ag, rs = pair
    names = ag.get_files()
    assert rs.get_files() == names
    bad = []
    for n in names + ["no/such/file"]:
        w = outcome(ag.get_file, n)
        g = outcome(rs.get_file, n)
        w = (w[0], hashlib.sha256(w[1]).hexdigest()) if w[0] == "ok" else w
        g = (g[0], hashlib.sha256(g[1]).hexdigest()) if g[0] == "ok" else g
        if w != g:
            bad.append(n)
    assert not bad, f"{path}: {len(bad)} entries differ, e.g. {bad[:5]}"


def test_every_xml(pair):
    path, ag, rs = pair
    bad = []
    n = 0
    for name in ag.get_files():
        if not name.lower().endswith(".xml"):
            continue
        try:
            raw = ag.get_file(name)
        except Exception:
            continue
        n += 1
        if printer_outcome(AgPrinter, raw) != printer_outcome(RsPrinter, raw):
            bad.append(name)
    assert not bad, f"{path}: {len(bad)} of {n} XML files differ, e.g. {bad[:5]}"


def test_resources_strings(pair):
    """_get_res_string_value, get_string_resources() and get_string()."""
    path, ag, rs = pair
    arsc_ag, arsc_rs = ag.get_android_resources(), rs.get_android_resources()
    if arsc_ag is None:
        assert arsc_rs is None
        return
    for pkg in arsc_ag.get_packages_names():
        assert outcome(arsc_ag.get_string_resources, pkg) == outcome(arsc_rs.get_string_resources, pkg)
        names = [k for k, _ in (arsc_ag.values.get(pkg, {}).get("\x00\x00", {}).get("string", []))][:200]
        for name in names + ["no_such_string"]:
            assert outcome(arsc_ag.get_string, pkg, name) == outcome(arsc_rs.get_string, pkg, name), name
            assert outcome(ag._get_res_string_value, "@string/" + name) == outcome(rs._get_res_string_value, "@string/" + name)
