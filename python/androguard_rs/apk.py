"""``androguard.core.apk`` drop-in: ``APK``, ``FileNotPresent``.

``APK(filename)`` / ``APK(data, raw=True)`` with androguard 4.1.3's results
for the methods implemented, without androguard:

- the zip is read natively the way apkInspector reads it (same names, same
  order, same extraction rules; ``androguard_rs.ApkFile``), from the file
  through seeks or from the caller's ``bytes`` in place, so the APK's bytes
  are held at most once;
- ``AndroidManifest.xml`` goes through ``androguard_rs.axml.AXMLPrinter``
  (androguard's printer over the native parser), and the manifest queries
  below are androguard 4.1.3's code (Apache-2.0) on that lxml tree;
- the v2/v3 signing block is located and its signers parsed natively, with
  androguard's quirks (what raises, what stays cached after an error);
- ``get_android_resources()`` is ``androguard_rs.Resources``.

Deliberate differences:

- ``get_certificates_v1()`` returns the raw PKCS#7 signature file of each v1
  signature (``META-INF/*.RSA|DSA|EC`` with a matching ``.SF``), unverified.
  androguard returns the signer certificate (an asn1crypto object) only for
  signatures that verify against their ``.SF``. Same count for a validly
  signed APK.
- ``get_certificates_v2()/_v3()`` return DER ``bytes`` per certificate
  (androguard: lazily parsed ``asn1crypto.x509.Certificate``). Same list.
- ``find_tags()`` (and so ``get_activities()`` & co.) list elements in
  document order; androguard collects them in a ``set`` of lxml elements,
  i.e. in memory-address order, which isn't reproducible even between two
  androguard runs. ``get_permissions()`` is ``list(set(...))`` as in
  androguard.
- Exceptions from a broken zip or signing block are ``androguard_rs.ApkError``
  (or ``BrokenAPKError`` where androguard raises that, and ``struct.error``
  for a signing block cut short, as androguard's unpack raises); a missing file is
  ``FileNotPresent``. A zip entry over 256 MiB, more than 2^20 zip entries,
  or a signer block over 16 MiB raise instead of being processed.
- Anything else androguard's ``APK`` has raises ``NotImplementedError``
  (counted in ``APK_GAPS``). ``get_androguard_apk()`` builds the real one
  when a caller needs it.
"""

from __future__ import annotations

import struct

import hashlib
import io
import os
import re
from collections import Counter
from typing import Iterator, Union

from . import _arscconfig, _native
from .axml import AXMLPrinter

__all__ = ["APK", "Error", "FileNotPresent", "BrokenAPKError", "ARSCParser", "APK_GAPS", "NS_ANDROID", "NS_ANDROID_URI"]

NS_ANDROID_URI = 'http://schemas.android.com/apk/res/android'
NS_ANDROID = '{{{}}}'.format(NS_ANDROID_URI)

#: attribute -> number of NotImplementedError raised for it.
APK_GAPS: Counter = Counter()


def _asn1_parse(data: bytes, pointer: int = 0, lengths_only: bool = False, depth: int = 0):
    """asn1crypto's ``parser._parse()`` header walk: (class, constructed,
    tag, end), or ValueError where asn1crypto raises it."""
    if depth > 10:
        raise ValueError('Indefinite-length recursion limit exceeded')
    n = len(data)
    if n < pointer + 1:
        raise ValueError("Insufficient data")
    first = data[pointer]
    pointer += 1
    tag = first & 31
    constructed = (first >> 5) & 1
    if tag == 31:
        tag = 0
        while True:
            if n < pointer + 1:
                raise ValueError("Insufficient data")
            num = data[pointer]
            pointer += 1
            if num == 0x80 and tag == 0:
                raise ValueError('Non-minimal tag encoding')
            tag = tag * 128 + (num & 127)
            if num >> 7 == 0:
                break
        if tag < 31:
            raise ValueError('Non-minimal tag encoding')
    if n < pointer + 1:
        raise ValueError("Insufficient data")
    length_octet = data[pointer]
    pointer += 1
    if length_octet >> 7 == 0:
        end = pointer + (length_octet & 127)
    else:
        k = length_octet & 127
        if k:
            if n < pointer + k:
                raise ValueError("Insufficient data")
            pointer += k
            end = pointer + int.from_bytes(data[pointer - k:pointer], "big")
        else:
            if not constructed:
                raise ValueError('Indefinite-length element must be constructed')
            end = pointer
            while n < end + 2 or data[end:end + 2] != b'\x00\x00':
                _, end = _asn1_parse(data, end, True, depth + 1)
            end += 2
    if end > n:
        raise ValueError("Insufficient data")
    if lengths_only:
        return pointer, end
    return first >> 6, constructed, tag, end


def _certificate_load(der: bytes) -> bytes:
    """What ``asn1crypto.x509.Certificate.load(der)`` checks up front (the
    rest is parsed lazily): a universal, constructed SEQUENCE header whose
    length fits. Raises ValueError where it does; returns ``der``."""
    class_, constructed, tag, _ = _asn1_parse(der)
    if class_ != 0 or constructed != 1 or tag != 16:
        raise ValueError("Error parsing asn1crypto.x509.Certificate")
    return der


class Error(Exception):
    """Base class for exceptions in this module."""


class FileNotPresent(Error):
    pass


class BrokenAPKError(Error):
    pass


def _gap(owner: str, attr: str):
    key = f"{owner}.{attr}"
    APK_GAPS[key] += 1
    raise NotImplementedError(f"androguard_rs: {key} is not implemented")


def _sig_error(error: str) -> Exception:
    """The exception for a signing-block parse error: androguard's own
    ``struct.error`` for a short read, else ``ApkError``."""
    if error.startswith("unpack requires a buffer of "):
        return struct.error(error)
    return _native.ApkError(error)


class ARSCParser:
    """``ARSCParser`` methods over ``androguard_rs.Resources`` (same results;
    errors are ``ResourcesError``). ``get_resolved_res_configs`` returns
    androguard's ``ARSCResTableConfig`` objects (``androguard_rs.axml``),
    built from the bytes androguard reads them from, one per type chunk as
    in androguard."""

    __slots__ = ("_r",)

    def __init__(self, raw_buff: bytes) -> None:
        self._r = _native.Resources(raw_buff)

    def get_packages_names(self):
        return self._r.get_packages_names()

    def get_public_resources(self, package_name, locale="\x00\x00"):
        return self._r.get_public_resources(package_name, locale)

    def get_resolved_strings(self):
        return self._r.get_resolved_strings()

    def get_resolved_res_configs(self, rid, config=None):
        if config is not None:
            _gap("ARSCParser", "get_resolved_res_configs(config=...)")
        return self._r.get_resolved_res_configs(rid, _arscconfig.from_bytes)

    def get_resource_xml_name(self, r_id, package=None):
        return self._r.get_resource_xml_name(r_id, package)

    def get_string(self, package_name, name, locale="\x00\x00"):
        return self._r.get_string(package_name, name, locale)

    def get_string_resources(self, package_name, locale="\x00\x00"):
        return self._r.get_string_resources(package_name, locale)

    @staticmethod
    def parse_id(name: str) -> tuple:
        if not name.startswith('@'):
            raise ValueError("Not a valid resource ID, must start with @: '{}'".format(name))
        name = name[1:]
        package = None
        if ':' in name:
            package, res_id = name.split(':', 1)
        else:
            res_id = name
        if len(res_id) != 8:
            raise ValueError("Numerical ID is not 8 characters long: '{}'".format(res_id))
        try:
            return int(res_id, 16), package
        except ValueError:
            raise ValueError("ID is not a hex ID: '{}'".format(res_id))

    def __getattr__(self, attr):
        if attr.startswith("__") and attr.endswith("__"):
            raise AttributeError(attr)
        _gap("ARSCParser", attr)


class _Zip:
    """``APK.zip`` (apkInspector's ``ZipEntry``): ``read``, ``namelist``."""

    __slots__ = ("_f",)

    def __init__(self, f) -> None:
        self._f = f

    def read(self, name: str) -> bytes:
        return self._f.read(name)

    def namelist(self) -> list:
        return self._f.namelist()

    def __getattr__(self, attr):
        if attr.startswith("__") and attr.endswith("__"):
            raise AttributeError(attr)
        _gap("ZipEntry", attr)


class APK:
    """androguard 4.1.3's ``APK``; see the module docstring."""

    def __init__(
        self,
        filename,
        raw: bool = False,
        magic_file=None,
        skip_analysis: bool = False,
        testzip: bool = False,
    ) -> None:
        self.filename = filename
        self.xml = {}
        self.axml = {}
        self.arsc = {}
        self.package = ""
        self.androidversion = {}
        self.permissions = []
        self.uses_permissions = []
        self.declared_permissions = {}
        self.valid_apk = False
        self._is_signed_v2 = None
        self._is_signed_v3 = None
        self._v2_signing_data = None
        self._v3_signing_data = None
        self._androguard_apk = None

        if raw is True:
            self._file = _native.ApkFile.from_bytes(filename)
            self._sha256 = hashlib.sha256(filename).hexdigest()
            self.filename = "raw_apk_sha256:{}".format(self._sha256)
        else:
            self._file = _native.ApkFile(filename)
        self.zip = _Zip(self._file)

        if testzip:
            import zipfile

            ret = zipfile.ZipFile(io.BytesIO(self.get_raw()), mode="r").testzip()
            if ret is not None:
                raise BrokenAPKError("The APK is probably broken: testzip returned an error.")

        if not skip_analysis:
            self._apk_analysis()

    def __getattr__(self, attr):
        if attr.startswith("__") and attr.endswith("__"):
            raise AttributeError(attr)
        _gap("APK", attr)

    @staticmethod
    def _ns(name):
        return NS_ANDROID + name

    def _apk_analysis(self):
        i = "AndroidManifest.xml"
        try:
            manifest_data = self.zip.read(i)
        except KeyError:
            pass
        else:
            ap = AXMLPrinter(manifest_data)
            if not ap.is_valid():
                return
            self.axml[i] = ap
            self.xml[i] = self.axml[i].get_xml_obj()

            if self.xml[i] is not None:
                if self.xml[i].tag != "manifest":
                    return

                self.package = self.get_attribute_value("manifest", "package")
                self.androidversion["Code"] = self.get_attribute_value("manifest", "versionCode")
                self.androidversion["Name"] = self.get_attribute_value("manifest", "versionName")
                permission = list(self.get_all_attribute_value("uses-permission", "name"))
                self.permissions = list(set(self.permissions + permission))

                for uses_permission in self.find_tags("uses-permission"):
                    self.uses_permissions.append(
                        [self.get_value_from_tag(uses_permission, "name"), self._get_permission_maxsdk(uses_permission)]
                    )

                for d_perm_item in self.find_tags('permission'):
                    d_perm_name = self._get_res_string_value(str(self.get_value_from_tag(d_perm_item, "name")))
                    d_perm_label = self._get_res_string_value(str(self.get_value_from_tag(d_perm_item, "label")))
                    d_perm_description = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "description"))
                    )
                    d_perm_permissionGroup = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "permissionGroup"))
                    )
                    d_perm_protectionLevel = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "protectionLevel"))
                    )
                    self.declared_permissions[d_perm_name] = {
                        "label": d_perm_label,
                        "description": d_perm_description,
                        "permissionGroup": d_perm_permissionGroup,
                        "protectionLevel": d_perm_protectionLevel,
                    }

                self.valid_apk = True

        # androguard loads its AOSP permission lists for the target and min
        # SDK here; that int()s a non-empty value, so a non-numeric one makes
        # APK() raise ValueError. The lists themselves aren't used.
        for level in (self.get_target_sdk_version(), self.get_min_sdk_version()):
            if level:
                int(level)

    def _get_res_string_value(self, string):
        if not string.startswith('@string/'):
            return string
        string_key = string[9:]

        res_parser = self.get_android_resources()
        if not res_parser:
            return ''
        string_value = ''
        for package_name in res_parser.get_packages_names():
            extracted_values = res_parser.get_string(package_name, string_key)
            if extracted_values:
                string_value = extracted_values[1]
                break
        return string_value

    def _get_permission_maxsdk(self, item):
        maxSdkVersion = None
        try:
            maxSdkVersion = int(self.get_value_from_tag(item, "maxSdkVersion"))
        except ValueError:
            pass
        except TypeError:
            pass
        return maxSdkVersion

    # ── androguard escape hatch ─────────────────────────────────────────────

    def get_androguard_apk(self):
        """androguard's own ``APK`` for this file (built on first call; needs
        androguard installed)."""
        if self._androguard_apk is None:
            from androguard.core.apk import APK as _AgAPK

            if self.filename.startswith("raw_apk_sha256:") and not os.path.exists(self.filename):
                self._androguard_apk = _AgAPK(self.get_raw(), raw=True)
            else:
                self._androguard_apk = _AgAPK(self.filename)
        return self._androguard_apk

    # ── Files ───────────────────────────────────────────────────────────────

    def is_valid_APK(self) -> bool:
        return self.valid_apk

    def get_filename(self) -> str:
        return self.filename

    def get_package(self) -> str:
        return self.package

    def get_androidversion_code(self) -> str:
        return self.androidversion["Code"]

    def get_androidversion_name(self) -> str:
        return self.androidversion["Name"]

    def get_files(self) -> list:
        return self.zip.namelist()

    @property
    def _APK__raw(self):
        """androguard's private ``__raw`` (the APK's bytes), as ``apk._APK__raw``."""
        return self._file.raw()

    def get_raw(self) -> bytes:
        return self._file.raw()

    def get_file(self, filename: str) -> bytes:
        try:
            return self.zip.read(filename)
        except KeyError:
            raise FileNotPresent(filename)

    def get_dex(self) -> bytes:
        try:
            return self.get_file("classes.dex")
        except FileNotPresent:
            return b""

    def get_dex_names(self):
        dexre = re.compile(r"^classes(\d*).dex$")
        return filter(lambda x: dexre.match(x), self.get_files())

    def get_all_dex(self) -> Iterator[bytes]:
        for dex_name in self.get_dex_names():
            yield self.get_file(dex_name)

    def is_multidex(self) -> bool:
        dexre = re.compile(r"^classes(\d+)?.dex$")
        return len([instance for instance in self.get_files() if dexre.search(instance)]) > 1

    # ── Manifest ────────────────────────────────────────────────────────────

    def _format_value(self, value):
        if value and self.package:
            v_dot = value.find(".")
            if v_dot == 0:
                value = self.package + value
            elif v_dot == -1:
                value = self.package + "." + value
        return value

    def get_all_attribute_value(self, tag_name: str, attribute: str, format_value: bool = True, **attribute_filter):
        tags = self.find_tags(tag_name, **attribute_filter)
        for tag in tags:
            value = tag.get(self._ns(attribute)) or tag.get(attribute)
            if value is not None:
                if format_value:
                    yield self._format_value(value)
                else:
                    yield value

    def get_attribute_value(self, tag_name: str, attribute: str, format_value: bool = False, **attribute_filter):
        for value in self.get_all_attribute_value(tag_name, attribute, format_value, **attribute_filter):
            if value is not None:
                return value

    def get_value_from_tag(self, tag, attribute: str):
        value = tag.get(self._ns(attribute))
        if value is None:
            value = tag.get(attribute)
        return value

    def find_tags(self, tag_name: str, **attribute_filter) -> list:
        all_tags = [self.find_tags_from_xml(i, tag_name, **attribute_filter) for i in self.xml]
        return [tag for tag_list in all_tags for tag in tag_list]

    def find_tags_from_xml(self, xml_name: str, tag_name: str, **attribute_filter) -> list:
        xml = self.xml[xml_name]
        if xml is None:
            return []
        if xml.tag == tag_name:
            if self.is_tag_matched(xml.tag, **attribute_filter):
                return [xml]
            return []
        # androguard: set(findall(".//" + tag) + findall(".//" + NS_ANDROID + tag)),
        # in set order; here in document order.
        ns_tag = NS_ANDROID + tag_name
        tags = [e for e in xml.iter(tag_name, ns_tag) if e is not xml]
        return [tag for tag in tags if self.is_tag_matched(tag, **attribute_filter)]

    def is_tag_matched(self, tag, **attribute_filter) -> bool:
        if len(attribute_filter) <= 0:
            return True
        for attr, value in attribute_filter.items():
            _value = self.get_value_from_tag(tag, attr)
            if _value != value:
                return False
        return True

    def get_main_activities(self) -> set:
        x = set()
        y = set()

        for i in self.xml:
            if self.xml[i] is None:
                continue
            activities_and_aliases = self.xml[i].findall(".//activity") + self.xml[i].findall(".//activity-alias")

            for item in activities_and_aliases:
                activityEnabled = item.get(self._ns("enabled"))
                if activityEnabled == "false":
                    continue

                for sitem in item.findall(".//action"):
                    val = sitem.get(self._ns("name"))
                    if val == "android.intent.action.MAIN":
                        activity = item.get(self._ns("name")) or item.get("name")
                        if activity is not None:
                            x.add(activity)

                for sitem in item.findall(".//category"):
                    val = sitem.get(self._ns("name"))
                    if val == "android.intent.category.LAUNCHER":
                        activity = item.get(self._ns("name")) or item.get("name")
                        if activity is not None:
                            y.add(activity)

        return x.intersection(y)

    def get_main_activity(self) -> Union[str, None]:
        activities = self.get_main_activities()
        if len(activities) == 1:
            return self._format_value(activities.pop())
        elif len(activities) > 1:
            main_activities = {self._format_value(ma) for ma in activities}
            good_main_activities = sorted(main_activities.intersection(self.get_activities()))
            if good_main_activities:
                return good_main_activities[0]
            return sorted(main_activities)[0]
        return None

    def get_activities(self) -> list:
        return list(self.get_all_attribute_value("activity", "name"))

    def get_activity_aliases(self) -> list:
        ali = []
        for alias in self.find_tags('activity-alias'):
            activity_alias = {}
            for attribute in ['name', 'targetActivity']:
                value = alias.get(attribute) or alias.get(self._ns(attribute))
                if not value:
                    continue
                activity_alias[attribute] = self._format_value(value)
            if activity_alias:
                ali.append(activity_alias)
        return ali

    def get_services(self) -> list:
        return list(self.get_all_attribute_value("service", "name"))

    def get_receivers(self) -> list:
        return list(self.get_all_attribute_value("receiver", "name"))

    def get_providers(self) -> list:
        return list(self.get_all_attribute_value("provider", "name"))

    def get_permissions(self) -> list:
        return self.permissions

    def get_uses_permissions(self) -> list:
        return self.uses_permissions

    def get_declared_permissions(self) -> list:
        return list(self.declared_permissions.keys())

    def get_declared_permissions_details(self) -> dict:
        return self.declared_permissions

    def get_max_sdk_version(self) -> str:
        return self.get_attribute_value("uses-sdk", "maxSdkVersion")

    def get_min_sdk_version(self) -> str:
        return self.get_attribute_value("uses-sdk", "minSdkVersion")

    def get_target_sdk_version(self) -> str:
        return self.get_attribute_value("uses-sdk", "targetSdkVersion")

    def get_effective_target_sdk_version(self) -> int:
        target_sdk_version = self.get_target_sdk_version()
        if not target_sdk_version:
            target_sdk_version = self.get_min_sdk_version()
        try:
            return int(target_sdk_version)
        except (ValueError, TypeError):
            return 1

    def get_libraries(self) -> list:
        return list(self.get_all_attribute_value("uses-library", "name"))

    def get_features(self) -> list:
        return list(self.get_all_attribute_value("uses-feature", "name"))

    def get_android_manifest_axml(self):
        try:
            return self.axml["AndroidManifest.xml"]
        except KeyError:
            return None

    def get_android_manifest_xml(self):
        try:
            return self.xml["AndroidManifest.xml"]
        except KeyError:
            return None

    def get_android_resources(self):
        try:
            return self.arsc["resources.arsc"]
        except KeyError:
            if "resources.arsc" not in self.zip.namelist():
                return None
            self.arsc["resources.arsc"] = ARSCParser(self.zip.read("resources.arsc"))
            return self.arsc["resources.arsc"]

    # ── Signatures ──────────────────────────────────────────────────────────

    def is_signed(self) -> bool:
        return self.is_signed_v1() or self.is_signed_v2() or self.is_signed_v3()

    def is_signed_v1(self) -> bool:
        return self.get_signature_name() is not None

    def is_signed_v2(self) -> bool:
        if self._is_signed_v2 is None:
            self.parse_v2_v3_signature()
        return self._is_signed_v2

    def is_signed_v3(self) -> bool:
        if self._is_signed_v3 is None:
            self.parse_v2_v3_signature()
        return self._is_signed_v3

    def parse_v2_v3_signature(self) -> None:
        flags_set, v2, v3, error = self._file.signing_block()
        if flags_set:
            self._is_signed_v2 = v2
            self._is_signed_v3 = v3
        if error is not None:
            if error.startswith(("No Central Dir", "Sizes at beginning")):
                raise BrokenAPKError(error)
            raise _sig_error(error)

    def _signer_certs(self, v3: bool) -> list:
        attr = "_v3_signing_data" if v3 else "_v2_signing_data"
        if getattr(self, attr) is None:
            # androguard sets the list before parsing, so after an error a
            # later call returns what was parsed instead of raising again.
            object.__setattr__(self, attr, [])
            if not (self.is_signed_v3() if v3 else self.is_signed_v2()):
                return []
            certs, error = self._file.signer_certificates(v3)
            object.__setattr__(self, attr, list(certs))
            if error is not None:
                if "does not match" in error:
                    raise BrokenAPKError(error)
                raise _sig_error(error)
        return list(getattr(self, attr))

    def get_certificates_der_v2(self) -> list:
        return self._signer_certs(False)

    def get_certificates_der_v3(self) -> list:
        return self._signer_certs(True)

    def get_certificates_v2(self) -> list:
        """DER bytes per certificate (androguard: asn1crypto certificates).
        Raises ValueError where ``Certificate.load()`` would."""
        return [_certificate_load(c) for c in self.get_certificates_der_v2()]

    def get_certificates_v3(self) -> list:
        """DER bytes per certificate (androguard: asn1crypto certificates).
        Raises ValueError where ``Certificate.load()`` would."""
        return [_certificate_load(c) for c in self.get_certificates_der_v3()]

    def get_certificates_v1(self) -> list:
        """The PKCS#7 signature file of each v1 signature, unverified (see
        the module docstring)."""
        return [self.get_file(x) for x in self.get_signature_names()]

    def get_signature_name(self) -> Union[str, None]:
        if self.get_signature_names():
            return self.get_signature_names()[0]
        return None

    def get_signature_names(self) -> list:
        signature_expr = re.compile(r'\AMETA-INF/(?s:.)*\.(DSA|EC|RSA)\Z')
        signatures = []
        files = self.get_files()
        present = set(files)
        for i in files:
            if signature_expr.search(i):
                if "{}.SF".format(i.rsplit(".", 1)[0]) in present:
                    signatures.append(i)
        return signatures

    def get_signature(self) -> Union[bytes, None]:
        if self.get_signatures():
            return self.get_signatures()[0]
        return None

    def get_signatures(self) -> list:
        signature_expr = re.compile(r'\AMETA-INF/(?s:.)*\.(DSA|EC|RSA)\Z')
        return [self.get_file(i) for i in self.get_files() if signature_expr.search(i)]
