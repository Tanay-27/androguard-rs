"""Hand-built binary XML (AXML), zip APKs and APK Signing Blocks for the
standalone APK tests. No androguard needed.

`Axml` writes the chunks aapt2 writes (string pool, resource map, namespace,
element, CDATA) and lets a test add the oddities packers use: junk between
chunks, an unusual first chunk type, trailing data, names only in the
resource map.
"""

import struct
import zlib

NS_ANDROID = "http://schemas.android.com/apk/res/android"

# Res_value types
REF, ATTR, STRING, FLOAT, DIMEN, FRACTION = 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
INT_DEC, INT_HEX, BOOL, COLOR_ARGB8 = 0x10, 0x11, 0x12, 0x1C


def chunk(ty: int, header_size: int, header_rest: bytes, body: bytes = b"", size=None) -> bytes:
    total = 8 + len(header_rest) + len(body) if size is None else size
    return struct.pack("<HHI", ty, header_size, total) + header_rest + body


def string_pool(strings, utf8=False) -> bytes:
    data = bytearray()
    offsets = []
    for s in strings:
        offsets.append(len(data))
        if utf8:
            b = s.encode("utf-8")
            n16 = len(s.encode("utf-16-le")) // 2
            for n in (n16, len(b)):
                data += bytes([n]) if n < 0x80 else bytes([0x80 | (n >> 8), n & 0xFF])
            data += b + b"\x00"
        else:
            u = s.encode("utf-16-le")
            n = len(u) // 2
            data += struct.pack("<H", n) if n < 0x8000 else struct.pack("<HH", 0x8000 | (n >> 16), n & 0xFFFF)
            data += u + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"
    strings_start = 28 + 4 * len(strings)
    hdr = struct.pack("<IIIII", len(strings), 0, 0x100 if utf8 else 0, strings_start, 0)
    body = b"".join(struct.pack("<I", o) for o in offsets) + bytes(data)
    return chunk(0x0001, 0x1C, hdr, body)


class Axml:
    """Collects strings and chunks; `build()` returns the file."""

    def __init__(self, utf8=False):
        self.strings = []
        self.index = {}
        self.res_ids = []  # resource ids for the first len(res_ids) strings
        self.nodes = []
        self.utf8 = utf8
        self.first_type = 0x0003

    def s(self, text):
        if text is None:
            return 0xFFFFFFFF
        if text not in self.index:
            self.index[text] = len(self.strings)
            self.strings.append(text)
        return self.index[text]

    def attr_name(self, name, res_id):
        """A string slot named through the resource map (slot < len(res_ids))."""
        # Attribute names with ids go first, as aapt does.
        i = len(self.res_ids)
        self.strings.insert(i, name)
        self.index = {t: k for k, t in enumerate(self.strings)}
        self.res_ids.append(res_id)
        return i

    def _node(self, ty, fields, line=1, comment=None):
        rest = struct.pack("<II", line, 0xFFFFFFFF if comment is None else comment)
        self.nodes.append((ty, rest, fields))

    def start_ns(self, prefix, uri):
        self._node(0x0100, ("ns", prefix, uri))

    def end_ns(self, prefix, uri):
        self._node(0x0101, ("ns", prefix, uri))

    def start(self, name, attrs=(), ns=None, comment=None):
        """attrs: (ns_uri or None, name, type, data) with data a str for STRING."""
        self._node(0x0102, ("start", ns, name, list(attrs)), comment=comment)

    def end(self, name, ns=None):
        self._node(0x0103, ("end", ns, name))

    def text(self, t):
        self._node(0x0104, ("text", t))

    def junk(self, raw: bytes):
        self.nodes.append(("raw", raw, None))

    def build(self, trailing=b"") -> bytes:
        # Resolve every string first, so the pool is final.
        resolved = []
        for ty, rest, f in self.nodes:
            if ty == "raw":
                resolved.append(rest)
                continue
            kind = f[0]
            if kind == "ns":
                body = struct.pack("<II", self.s(f[1]), self.s(f[2]))
            elif kind == "start":
                _, ns, name, attrs = f
                ab = b""
                for a_ns, a_name, a_type, a_data in attrs:
                    a_name_i = a_name if isinstance(a_name, int) else self.s(a_name)
                    raw_i = self.s(a_data) if a_type == STRING else 0xFFFFFFFF
                    data = self.s(a_data) if a_type == STRING else a_data
                    ab += struct.pack("<IIIHBBI", self.s(a_ns), a_name_i, raw_i, 8, 0, a_type, data & 0xFFFFFFFF)
                body = struct.pack("<IIHHHHHH", self.s(ns), self.s(name), 0x14, 0x14, len(attrs), 0, 0, 0) + ab
            elif kind == "end":
                body = struct.pack("<II", self.s(f[1]), self.s(f[2]))
            else:
                body = struct.pack("<I", self.s(f[1])) + struct.pack("<HBBI", 8, 0, 0, 0)
            resolved.append(chunk(ty, 0x10, rest, body))
        out = string_pool(self.strings, self.utf8)
        if self.res_ids:
            out += chunk(0x0180, 8, b"", b"".join(struct.pack("<I", r) for r in self.res_ids))
        out += b"".join(resolved)
        return struct.pack("<HHI", self.first_type, 8, 8 + len(out)) + out + trailing


def manifest(package="com.example.app", extra_activity_attrs=()):
    """A typical compiled AndroidManifest.xml."""
    x = Axml()
    a = NS_ANDROID
    names = {}
    for n, rid in [("versionCode", 0x0101021B), ("versionName", 0x0101021C), ("minSdkVersion", 0x0101020C),
                   ("targetSdkVersion", 0x01010270), ("name", 0x01010003), ("label", 0x01010001),
                   ("icon", 0x01010002), ("debuggable", 0x0101000F), ("allowBackup", 0x01010280),
                   ("exported", 0x01010010), ("theme", 0x01010000), ("authorities", 0x01010018),
                   ("value", 0x01010024), ("protectionLevel", 0x01010009), ("enabled", 0x0101000E),
                   ("targetActivity", 0x01010202), ("maxSdkVersion", 0x01010271)]:
        names[n] = x.attr_name(n, rid)
    x.start_ns("android", a)
    x.start("manifest", [(a, names["versionCode"], INT_DEC, 42), (a, names["versionName"], STRING, "4.2.0"),
                         (None, "package", STRING, package),
                         (None, "platformBuildVersionCode", INT_DEC, 33)])
    x.start("uses-sdk", [(a, names["minSdkVersion"], INT_DEC, 21), (a, names["targetSdkVersion"], INT_DEC, 33)])
    x.end("uses-sdk")
    for p in ["android.permission.INTERNET", "android.permission.CAMERA", "LOCAL_PERM", "android.permission.INTERNET"]:
        x.start("uses-permission", [(a, names["name"], STRING, p)])
        x.end("uses-permission")
    x.start("uses-permission", [(a, names["name"], STRING, "android.permission.READ_CONTACTS"),
                                (a, names["maxSdkVersion"], INT_DEC, 22)])
    x.end("uses-permission")
    x.start("permission", [(a, names["name"], STRING, "com.example.app.PERM"),
                           (a, names["label"], STRING, "@string/xapp_name"),
                           (a, names["protectionLevel"], INT_HEX, 2)])
    x.end("permission")
    x.start("application", [(a, names["label"], REF, 0x7F0F0001), (a, names["icon"], REF, 0x7F080001),
                            (a, names["debuggable"], BOOL, 0xFFFFFFFF), (a, names["allowBackup"], BOOL, 0),
                            (a, names["theme"], REF, 0x01030237), (a, names["name"], STRING, ".App")])
    x.start("activity", [(a, names["name"], STRING, ".MainActivity"), (a, names["exported"], BOOL, 0xFFFFFFFF),
                         (a, names["theme"], ATTR, 0x7F040123)] + list(extra_activity_attrs))
    x.start("intent-filter")
    x.start("action", [(a, names["name"], STRING, "android.intent.action.MAIN")])
    x.end("action")
    x.start("category", [(a, names["name"], STRING, "android.intent.category.LAUNCHER")])
    x.end("category")
    x.end("intent-filter")
    x.end("activity")
    x.start("activity", [(a, names["name"], STRING, "SettingsActivity")])
    x.end("activity")
    x.start("activity-alias", [(a, names["name"], STRING, ".Alias"),
                               (a, names["targetActivity"], STRING, ".MainActivity")])
    x.end("activity-alias")
    x.start("service", [(a, names["name"], STRING, "com.example.app.SyncService"),
                        (a, names["exported"], BOOL, 0)])
    x.end("service")
    x.start("receiver", [(a, names["name"], STRING, ".BootReceiver")])
    x.end("receiver")
    x.start("provider", [(a, names["name"], STRING, "androidx.core.content.FileProvider"),
                         (a, names["authorities"], STRING, "com.example.app.files")])
    x.end("provider")
    for key, ty, data in [("f", FLOAT, 0x3FC00000), ("d", DIMEN, (16 << 8) | 1), ("fr", FRACTION, (1 << 23) | 0),
                          ("c", COLOR_ARGB8, 0xFF00FF00), ("h", INT_HEX, 0xDEADBEEF), ("n", INT_DEC, -5),
                          ("unk", 0x07, 1234)]:
        x.start("meta-data", [(a, names["name"], STRING, "k." + key), (a, names["value"], ty, data)])
        x.end("meta-data")
    x.end("application")
    x.end("manifest")
    x.end_ns("android", a)
    return x.build()


def layout():
    """A layout with three namespaces, a comment, text and odd names."""
    x = Axml()
    a, app, tools = NS_ANDROID, "http://schemas.android.com/apk/res-auto", "http://schemas.android.com/tools"
    lw = x.attr_name("", 0x010100F4)  # layout_width, name only in the resource map
    lh = x.attr_name("layout_height", 0x010100F5)
    unk = x.attr_name("", 0x0101FFFF)  # not a known system attribute
    x.start_ns("android", a)
    x.start_ns("app", app)
    x.start_ns("tools", tools)
    x.start("androidx.constraintlayout.widget.ConstraintLayout",
            [(a, lw, INT_DEC, -1), (a, lh, DIMEN, (48 << 8) | 1), (a, unk, INT_DEC, 3),
             (app, "layout_constraintTop_toTopOf", REF, 0), (tools, "context", STRING, ".MainActivity")])
    x.start("TextView", [(a, "text", STRING, "Hello <world> & \"friends\""), (None, "android:hint", STRING, "packed"),
                         (None, "1bad name!", STRING, "v\x01al\x00ue")], comment=x.s("a comment"))
    x.text("some text")
    x.end("TextView")
    x.end("androidx.constraintlayout.widget.ConstraintLayout")
    x.end_ns("tools", tools)
    x.end_ns("app", app)
    x.end_ns("android", a)
    return x.build()


def packed():
    """Packer tricks: odd first chunk type, junk between chunks, trailing data, UTF-8 pool."""
    x = Axml(utf8=True)
    x.first_type = 0x0000
    a = NS_ANDROID
    x.start_ns("android", a)
    x.junk(b"\xde\xad\xbe")
    x.start("network-security-config")
    x.start("domain-config", [(None, "cleartextTrafficPermitted", BOOL, 1)])
    x.start("domain", [(None, "includeSubdomains", BOOL, 0xFFFFFFFF)])
    x.text("example.com é中")
    x.end("domain")
    x.end("domain-config")
    x.end("network-security-config")
    x.end_ns("android", a)
    return x.build(trailing=b"\x00" * 8)


# ── Zip and signing ──────────────────────────────────────────────────────────


def zip_bytes(entries, before_cd=b"", comment=b""):
    """entries: (name, data, method) with method 0 (stored) or 8 (deflate)."""
    out = bytearray()
    cd = bytearray()
    for name, data, method in entries:
        nb = name.encode()
        off = len(out)
        if method == 8:
            c = zlib.compressobj(9, zlib.DEFLATED, -15)
            payload = c.compress(data) + c.flush()
        else:
            payload = data
        crc = zlib.crc32(data)
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, method, 0, 0x21, crc, len(payload), len(data), len(nb), 0)
        out += nb + payload
        cd += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, method, 0, 0x21, crc, len(payload), len(data),
                          len(nb), 0, 0, 0, 0, 0, off)
        cd += nb
    out += before_cd
    cd_off = len(out)
    out += cd
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(cd), cd_off, len(comment))
    out += comment
    return bytes(out)


def _lp(b: bytes) -> bytes:
    return struct.pack("<I", len(b)) + b


def signer(certs, v3=False) -> bytes:
    digests = _lp(_lp(struct.pack("<I", 0x0103) + _lp(b"\x11" * 32)))
    signed = digests + _lp(b"".join(_lp(c) for c in certs))
    if v3:
        signed += struct.pack("<II", 24, 0x7FFFFFFF)
    signed += _lp(b"")
    body = _lp(signed)
    if v3:
        body += struct.pack("<II", 24, 0x7FFFFFFF)
    body += _lp(_lp(struct.pack("<I", 0x0103) + _lp(b"\x22" * 64))) + _lp(b"PUBKEY")
    return _lp(_lp(body))


def signing_block(pairs) -> bytes:
    body = b"".join(struct.pack("<QI", len(v) + 4, k) + v for k, v in pairs)
    size = len(body) + 8 + 16
    return struct.pack("<Q", size) + body + struct.pack("<Q", size) + b"APK Sig Block 42"


# ── A minimal resources.arsc (one package, string resources) ─────────────────


def _arsc_pool(strings):
    data, offsets = b"", []
    for s in strings:
        offsets.append(len(data))
        b = s.encode("utf-8")
        n = len(s)
        for v in (n, len(b)):
            data += bytes([v]) if v < 0x80 else bytes([0x80 | (v >> 8), v & 0xFF])
        data += b + b"\0"
    data += b"\0" * (-len(data) % 4)
    start = 28 + 4 * len(strings)
    head = struct.pack("<HHIIIIII", 1, 28, start + len(data), len(strings), 0, 0x100, start, 0)
    return head + b"".join(struct.pack("<I", o) for o in offsets) + data


def arsc_strings(package_name, pairs, fr_pairs=()):
    """resources.arsc with string resources `pairs` ((key, value), default
    locale) and `fr_pairs` (same keys' French values)."""
    keys = [k for k, _ in pairs]
    values = [v for _, v in pairs] + [v for _, v in fr_pairs]

    def cfg(locale):
        body = struct.pack("<I", 0) + locale + struct.pack("<I", 0) + struct.pack("<III", 0, 0, 0) + b"\0" * 36
        return struct.pack("<I", 4 + len(body)) + body

    def type_chunk(entries, c):
        offs, data = [], b""
        for key, vi in entries:
            offs.append(len(data))
            data += struct.pack("<HHI", 8, 0, key) + struct.pack("<HBBI", 8, 0, 0x03, vi)
        head_size = 20 + len(c)
        start = head_size + 4 * len(offs)
        head = struct.pack("<HHIBBHII", 0x201, head_size, start + len(data), 1, 0, 0, len(offs), start)
        return head + c + b"".join(struct.pack("<I", o) for o in offs) + data

    chunks = [struct.pack("<HHIBBHI", 0x202, 16, 16 + 4 * len(keys), 1, 0, 0, len(keys)) + b"\0" * (4 * len(keys)),
              type_chunk([(i, i) for i in range(len(pairs))], cfg(b"\0\0\0\0"))]
    if fr_pairs:
        chunks.append(type_chunk([(keys.index(k), len(pairs) + j) for j, (k, _) in enumerate(fr_pairs)], cfg(b"fr\0\0")))
    tp, kp = _arsc_pool(["string"]), _arsc_pool(keys)
    name_b = package_name.encode("utf-16-le")[:256].ljust(256, b"\0")
    body = struct.pack("<I", 0x7F) + name_b + struct.pack("<IIIII", 288, 1, 288 + len(tp), len(keys), 0)
    rest = tp + kp + b"".join(chunks)
    pkg = struct.pack("<HHI", 0x200, 288, 288 + len(rest)) + body + rest
    tbody = _arsc_pool(values) + pkg
    return struct.pack("<HHII", 2, 12, 12 + len(tbody), 1) + tbody


def synthetic_apk(dex: bytes, extra=(), signing=True) -> bytes:
    """The standalone tests' APK: manifest, a DEX, two XML resources, a
    resources.arsc, a v1 signature (and an orphan .EC without .SF) and a
    v2 + v3 signing block."""
    blk = b""
    if signing:
        blk = signing_block([(0x42726577, b"\0" * 8), (0x7109871A, signer([b"\x30\x06CERT-A", b"\x30\x06CERT-B"])),
                             (0xF05368C0, signer([b"\x30\x06CERT-C"], v3=True))])
    arsc = arsc_strings("com.example.app", [("app_name", "Example"), ("html", "<b>bold</b> & co")])
    entries = [("AndroidManifest.xml", manifest(), 8), ("classes.dex", dex, 8), ("res/layout/main.xml", layout(), 8),
               ("res/xml/network_security_config.xml", packed(), 0), ("resources.arsc", arsc, 0),
               ("META-INF/CERT.SF", b"sf", 8), ("META-INF/CERT.RSA", b"rsa", 8), ("META-INF/ORPHAN.EC", b"ec", 0),
               ("assets/a.txt", b"hello", 0)] + list(extra)
    return zip_bytes(entries, before_cd=blk)
