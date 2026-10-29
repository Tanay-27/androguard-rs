"""``androguard.core.axml`` drop-ins: ``AXMLPrinter`` and ``format_value``.

The binary XML is parsed natively (``androguard_rs.AxmlParser``, a port of
androguard 4.1.3's ``AXMLParser``: same chunk walk, string pool, attribute
naming and failures). The tree is built here by androguard 4.1.3's own
``AXMLPrinter`` code (Apache-2.0), unchanged except that logging is gone, so
names, namespace maps, values and lxml serialization come out identical.

Differences from androguard, all on hostile input only:

- exceptions androguard raises from the parser (``struct.error``,
  ``ResParserError``, ``AssertionError``, ``UnboundLocalError``...) are
  ``androguard_rs.AxmlError`` (``Exception`` subclasses either way);
- inputs over 64 MiB, more than 1024 open namespace mappings, more than
  256 MiB of string data handed out, or a chunk that would make androguard
  loop forever raise ``AxmlError`` instead of running away.
"""

from __future__ import annotations

import re
from struct import pack, unpack
from typing import Union

from lxml import etree

from . import _native
from ._arscconfig import ARSCResTableConfig  # noqa: F401

__all__ = ["ARSCResTableConfig", "AXMLPrinter", "AXMLParser", "format_value", "AxmlError", "START_TAG", "END_TAG", "TEXT", "END_DOCUMENT"]

AxmlError = _native.AxmlError

START_DOCUMENT = 0
END_DOCUMENT = 1
START_TAG = 2
END_TAG = 3
TEXT = 4

TYPE_ATTRIBUTE = 2
TYPE_DIMENSION = 5
TYPE_FIRST_COLOR_INT = 28
TYPE_FIRST_INT = 16
TYPE_FLOAT = 4
TYPE_FRACTION = 6
TYPE_INT_BOOLEAN = 18
TYPE_INT_HEX = 17
TYPE_LAST_COLOR_INT = 31
TYPE_LAST_INT = 31
TYPE_REFERENCE = 1
TYPE_STRING = 3

RADIX_MULTS = [0.00390625, 3.051758e-005, 1.192093e-007, 4.656613e-010]
DIMENSION_UNITS = ["px", "dip", "sp", "pt", "in", "mm"]
FRACTION_UNITS = ["%", "%p"]
COMPLEX_UNIT_MASK = 0x0F


def complexToFloat(xcomplex) -> float:
    return float(xcomplex & 0xFFFFFF00) * RADIX_MULTS[(xcomplex >> 4) & 3]


def format_value(_type: int, _data: int, lookup_string=lambda ix: "<string>") -> str:
    """androguard's ``format_value``, verbatim."""
    fmt_package = lambda x: "android:" if x >> 24 == 1 else ""
    fmt_int = lambda x: (0x7FFFFFFF & x) - 0x80000000 if x > 0x7FFFFFFF else x

    if _type == TYPE_STRING:
        return lookup_string(_data)
    elif _type == TYPE_ATTRIBUTE:
        return "?{}{:08X}".format(fmt_package(_data), _data)
    elif _type == TYPE_REFERENCE:
        return "@{}{:08X}".format(fmt_package(_data), _data)
    elif _type == TYPE_FLOAT:
        return "%f" % unpack("=f", pack("=L", _data))[0]
    elif _type == TYPE_INT_HEX:
        return "0x%08X" % _data
    elif _type == TYPE_INT_BOOLEAN:
        if _data == 0:
            return "false"
        return "true"
    elif _type == TYPE_DIMENSION:
        return "{:f}{}".format(complexToFloat(_data), DIMENSION_UNITS[_data & COMPLEX_UNIT_MASK])
    elif _type == TYPE_FRACTION:
        return "{:f}{}".format(complexToFloat(_data) * 100, FRACTION_UNITS[_data & COMPLEX_UNIT_MASK])
    elif TYPE_FIRST_COLOR_INT <= _type <= TYPE_LAST_COLOR_INT:
        return "#%08X" % _data
    elif TYPE_FIRST_INT <= _type <= TYPE_LAST_INT:
        return "%d" % fmt_int(_data)
    return "<0x{:X}, type 0x{:02X}>".format(_data, _type)


class AXMLParser:
    """androguard's ``AXMLParser`` API over the native parser."""

    __slots__ = ("_p", "_nsmap_key", "_nsmap")

    def __init__(self, raw_buff: bytes) -> None:
        self._p = _native.AxmlParser(raw_buff)
        self._nsmap_key = None
        self._nsmap = None

    def is_valid(self) -> bool:
        return self._p.is_valid()

    def __next__(self):
        return self._p.next()

    @property
    def m_event(self):
        return self._p.m_event

    @property
    def m_lineNumber(self):
        return self._p.m_lineNumber

    @property
    def packerwarning(self) -> bool:
        return self._p.packerwarning

    @property
    def axml_tampered(self) -> bool:
        return self._p.axml_tampered

    @property
    def name(self) -> str:
        return self._p.name

    @property
    def comment(self) -> Union[str, None]:
        return self._p.comment

    @property
    def namespace(self) -> str:
        return self._p.namespace

    @property
    def namespaces(self) -> list:
        return self._p.namespaces

    @property
    def nsmap(self) -> dict[str, str]:
        # androguard's nsmap, computed the same way (a Python set of the
        # (prefix, uri) index pairs, so the same iteration order); cached
        # until the namespace list changes.
        key = self._p.namespaces_version()
        if self._nsmap_key != key:
            sb = self._p.string
            NSMAP = dict()
            for k, v in set(self._p.namespaces):
                s_prefix = sb(k)
                s_uri = sb(v)
                if s_uri != "" and s_prefix != "":
                    NSMAP[s_prefix] = s_uri.strip()
            self._nsmap = NSMAP
            self._nsmap_key = key
        return dict(self._nsmap)

    @property
    def text(self) -> str:
        return self._p.text

    def getName(self) -> str:
        return self.name

    def getText(self) -> str:
        return self.text

    def getPrefix(self) -> str:
        return self.namespace

    def getAttributeCount(self) -> int:
        return self._p.getAttributeCount()

    def getAttributeNamespace(self, index: int) -> str:
        return self._p.getAttributeNamespace(index)

    def getAttributeName(self, index: int) -> str:
        return self._p.getAttributeName(index)

    def getAttributeValueType(self, index: int):
        return self._p.getAttributeValueType(index)

    def getAttributeValueData(self, index: int):
        return self._p.getAttributeValueData(index)

    def getAttributeValue(self, index: int) -> str:
        return self._p.getAttributeValue(index)


class AXMLPrinter:
    """androguard 4.1.3's ``AXMLPrinter`` (logging removed)."""

    __charrange = None
    __replacement = None

    def __init__(self, raw_buff: bytes) -> None:
        self.axml = AXMLParser(raw_buff)

        self.root = None
        self.packerwarning = False
        cur = []

        while self.axml.is_valid():
            _type = next(self.axml)

            if _type == START_TAG:
                if not self.axml.name:
                    continue
                uri = self._print_namespace(self.axml.namespace)
                uri, name = self._fix_name(uri, self.axml.name)
                tag = "{}{}".format(uri, name)

                comment = self.axml.comment
                if comment:
                    if self.root is not None:
                        cur[-1].append(etree.Comment(comment))

                try:
                    elem = etree.Element(tag, nsmap=self.axml.nsmap)
                except ValueError as e:
                    if 'Invalid namespace prefix' in str(e):
                        corrected_nsmap = self.clean_and_replace_nsmap(self.axml.nsmap, str(e).split("'")[1])
                        elem = etree.Element(tag, nsmap=corrected_nsmap)
                    else:
                        raise

                for i in range(self.axml.getAttributeCount()):
                    uri = self._print_namespace(self.axml.getAttributeNamespace(i))
                    uri, name = self._fix_name(uri, self.axml.getAttributeName(i))
                    value = self._fix_value(self._get_attribute_value(i))
                    # androguard formats this for a debug log, and checks
                    # for a duplicate (only to warn), eagerly.
                    value.encode("utf-8")
                    "{}{}".format(uri, name) in elem.attrib
                    elem.set("{}{}".format(uri, name), value)

                if self.root is None:
                    self.root = elem
                else:
                    if not cur:
                        break
                    cur[-1].append(elem)
                cur.append(elem)

            if _type == END_TAG:
                if cur:
                    if not self.axml.name:
                        continue

                name = self.axml.name
                uri = self._print_namespace(self.axml.namespace)
                tag = "{}{}".format(uri, name)
                if cur[-1].tag != tag:
                    pass
                cur.pop()
            if _type == TEXT:
                # androguard formats cur[-1] for a debug log first.
                cur[-1]
                cur[-1].text = self.axml.text
            if _type == END_DOCUMENT:
                break

    def clean_and_replace_nsmap(self, nsmap, invalid_prefix):
        correct_prefix = 'android'
        corrected_nsmap = {}
        for prefix, uri in nsmap.items():
            if prefix.startswith(invalid_prefix):
                corrected_nsmap[correct_prefix] = uri
            else:
                corrected_nsmap[prefix] = uri
        return corrected_nsmap

    def get_buff(self) -> bytes:
        return self.get_xml(pretty=False)

    def get_xml(self, pretty: bool = True) -> bytes:
        return etree.tostring(self.root, encoding="utf-8", pretty_print=pretty)

    def get_xml_obj(self):
        return self.root

    def is_valid(self) -> bool:
        return self.axml.is_valid()

    def is_packed(self) -> bool:
        return self.packerwarning or self.axml.packerwarning

    def _get_attribute_value(self, index: int):
        _type = self.axml.getAttributeValueType(index)
        _data = self.axml.getAttributeValueData(index)
        return format_value(_type, _data, lambda _: self.axml.getAttributeValue(index))

    def _fix_name(self, prefix, name) -> tuple[str, str]:
        if not name[0].isalpha() and name[0] != "_":
            self.packerwarning = True
            name = "_{}".format(name)
        if name.startswith("android:") and prefix == '' and 'android' in self.axml.nsmap:
            prefix = self._print_namespace(self.axml.nsmap['android'])
            name = name[len("android:"):]
            self.packerwarning = True
        elif ":" in name and prefix == '':
            self.packerwarning = True
            embedded_prefix, new_name = name.split(":", 1)
            if embedded_prefix in self.axml.nsmap:
                prefix = self._print_namespace(self.axml.nsmap[embedded_prefix])
                name = new_name
        if not re.match(r"^[a-zA-Z0-9._-]*$", name):
            self.packerwarning = True
            name = re.sub(r"[^a-zA-Z0-9._-]", "_", name)

        return prefix, name

    def _fix_value(self, value):
        if not self.__charrange or not self.__replacement:
            self.__charrange = re.compile('^[ -퟿\u0009\u000A\u000D-�\U00010000-\U0010FFFF]*$')
            self.__replacement = re.compile('[^ -퟿\u0009\u000A\u000D-�\U00010000-\U0010FFFF]')

        if "\x00" in value:
            self.packerwarning = True
            value = value[: value.find("\x00")]

        if not self.__charrange.match(value):
            self.packerwarning = True
            value = self.__replacement.sub('_', value)
        return value

    def _print_namespace(self, uri):
        if uri != "":
            uri = "{{{}}}".format(uri)
        return uri


def __getattr__(name):
    # androguard 4.1.3 has ARSCParser in androguard.core.axml; here it lives in
    # .apk, which imports this module.
    if name == "ARSCParser":
        from .apk import ARSCParser

        return ARSCParser
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
