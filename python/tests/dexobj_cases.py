"""androguard 4.1.3's per-DEX object model (DEX, ClassDefItem, EncodedMethod,
EncodedField, Analysis.find_methods(), MethodAnalysis, xrefs) on a synthetic
two-DEX APK, shared by test_dexobj.py (standalone, goldens),
test_dexobj_parity.py (live against androguard, also on PARITY_APKS) and
scripts/gen_dexobj_goldens.py (which wrote dexobj_goldens.py from
androguard 4.1.3 + mutf8 1.1.0).

The APK covers TLS-related shapes (a TrustManager whose checkServerTrusted
is empty, HostnameVerifiers that return true, one through a superclass, a
WebViewClient whose onReceivedSslError proceeds, AllowAllHostnameVerifier /
ALLOW_ALL_HOSTNAME_VERIFIER / getInsecure(...) uses), Intent sources and
sinks, Math.random and Random.<init> calls, registerReceiver calls, static
fields with typed initial values, a <clinit> that sput-objects one, a class
defined in both DEX files and two class_defs sharing a class_data.

`views(d, dx)` is what the tests compare; `tls_candidates()` is a
per-method walk over every DEX object's get_encoded_methods() and
get_instructions(), as a caller scanning for TLS-related code makes it.
"""

import re
import struct
import zlib

import fixture_apk as F
from dup_cases import _apk_raw, call
from fixture_apk import RETURN_VOID, cls, const4, invoke, meth, new_instance, sget
from fixture_apk import ev_array, ev_bool, ev_int, ev_long, ev_null, ev_string

STR = "Ljava/lang/String;"
OBJ = "Ljava/lang/Object;"
TM, HV, HV2, WVC, USE, APP, CONSTS, DUP, SHARE_A, SHARE_B = (
    "Lcom/app/TM;", "Lcom/app/HV;", "Lcom/app/HV2;", "Lcom/app/WVC;", "Lcom/app/Use;", "Lcom/app/MainActivity;",
    "Lcom/app/Consts;", "Lcom/app/Dup;", "Lcom/app/ShareA;", "Lcom/app/ShareB;")
CORDOVA = "Lorg/apache/cordova/CordovaWebView;"
DEVICE = "Lorg/apache/cordova/Device;"
INTENT = "Landroid/content/Intent;"


def code(*parts):
    return lambda c: b"".join(p(c) for p in parts)


def raw(b):
    return lambda c: b


def ret_true(c):
    return const4(0, 1) + bytes([0x0F, 0x00])


def init(sup=OBJ):
    return meth("<init>", flags=0x10001, code=code(call(0x70, sup, "<init>"), raw(RETURN_VOID)), regs=1, ins=1, outs=1)


def m(name, *parts, ret="V", params=(), flags=0x1, regs=6):
    c = code(*parts, raw(RETURN_VOID)) if parts else None
    return meth(name, ret=ret, params=params, flags=flags, code=c, regs=regs, ins=1 + len(params), outs=4)


def get_obj(owner, name, ty):
    return lambda c: sget(0x62, 0, c.f(owner, name, ty))


def put_obj(owner, name, ty):
    return lambda c: sget(0x69, 0, c.f(owner, name, ty))


def new(ty):
    return lambda c: new_instance(0, c.t(ty))


def static_call(owner, name, ret, params, *regs):
    return lambda c: invoke(0x71, c.m(owner, name, ret, params), *regs)


def virt(owner, name, ret="V", params=(), *regs):
    return lambda c: invoke(0x6E, c.m(owner, name, ret, params), *(regs or range(1 + len(params))))


def const_str(text, reg=0):
    return lambda c: F.const_string(reg, c.s(text))


X509 = ("[Ljava/security/cert/X509Certificate;", STR)
SSL_ERR = ("Landroid/webkit/WebView;", "Landroid/webkit/SslErrorHandler;", "Landroid/net/http/SslError;")


def dex1():
    return [
        cls(TM, ifaces=["Ljavax/net/ssl/X509TrustManager;"], direct=[init()], virtual=[
            m("checkClientTrusted", params=X509),
            m("checkServerTrusted", raw(b""), params=X509),
            meth("getAcceptedIssuers", ret="[Ljava/security/cert/X509Certificate;", flags=0x1,
                 code=lambda c: const4(0, 0) + bytes([0x11, 0x00]), regs=1, ins=1, outs=0)]),
        cls(HV, ifaces=["Ljavax/net/ssl/HostnameVerifier;"], direct=[init()], virtual=[
            meth("verify", ret="Z", params=(STR, "Ljavax/net/ssl/SSLSession;"), code=ret_true, regs=3, ins=3, outs=0)]),
        # Not a verifier (no interface, no known superclass): skipped by the checks.
        cls(HV2, direct=[init()], virtual=[
            meth("verify", ret="Z", params=(STR, "Ljavax/net/ssl/SSLSession;"), code=ret_true, regs=3, ins=3, outs=0),
            m("verify", raw(b""), params=(STR, "[Ljava/lang/String;", "[Ljava/lang/String;"))]),
        cls(WVC, sup="Landroid/webkit/WebViewClient;", direct=[init("Landroid/webkit/WebViewClient;")], virtual=[
            m("onReceivedSslError", virt("Landroid/webkit/SslErrorHandler;", "proceed", "V", (), 2), params=SSL_ERR)]),
        cls(USE, direct=[init()], virtual=[
            m("allowAll", new("Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;")),
            m("allowAllField", get_obj("Lorg/apache/http/conn/ssl/SSLSocketFactory;", "ALLOW_ALL_HOSTNAME_VERIFIER",
                                       "Lorg/apache/http/conn/ssl/X509HostnameVerifier;")),
            m("insecure", static_call("Landroid/net/SSLCertificateSocketFactory;", "getInsecure",
                                      "Ljavax/net/ssl/SSLSocketFactory;", ("I", "Landroid/net/SSLSessionCache;"), 0, 1)),
            m("plain", const_str("nothing here")),
            m("random", static_call("Ljava/lang/Math;", "random", "D", (),),
              call(0x70, "Ljava/util/Random;", "<init>")),
            m("abstractish", flags=0x401)]),
        cls(APP, sup="Landroid/app/Activity;", direct=[init("Landroid/app/Activity;")], virtual=[
            m("onCreate", virt(INTENT, "getParcelableExtra", "Landroid/os/Parcelable;", (STR,), 1, 2),
              raw(bytes([0x0C, 0x00])),  # move-result-object v0
              virt(APP, "startActivity", "V", (INTENT,), 3, 0), params=("Landroid/os/Bundle;",)),
            m("sel", virt(INTENT, "getSelector", INTENT, (), 1), raw(bytes([0x0C, 0x00])),
              virt(APP, "startService", "Landroid/content/ComponentName;", (INTENT,), 3, 0)),
            m("recv", virt(APP, "registerReceiver", INTENT,
                           ("Landroid/content/BroadcastReceiver;", "Landroid/content/IntentFilter;"), 3, 1, 2)),
            m("wide", raw(b""), params=("J", "D", "[[I", "Z"), ret="[Ljava/lang/String;", regs=8),
            m("noparams", raw(b""), ret="I", regs=0)]),
        cls(CONSTS, static=[
            ("API_KEY", STR, 0x19, lambda c: ev_string(c.s("AIzaSyFakeKey"))),
            ("COUNT", "I", 0x19, lambda c: ev_int(42)),
            ("BIG", "J", 0x19, lambda c: ev_long(1 << 40)),
            ("ON", "Z", 0x19, lambda c: ev_bool(True)),
            ("NOTHING", OBJ, 0x19, lambda c: ev_null()),
            ("ARR", "[I", 0x19, lambda c: ev_array(ev_int(1), ev_int(2))),
            ("LATE", STR, 0x9, None)], instance=[("inst", STR, 0x2)], direct=[init()]),
        cls(CORDOVA, static=[("CORDOVA_VERSION", STR, 0x19, lambda c: ev_string(c.s("9.1.0")))], direct=[init()]),
        cls(DEVICE, static=[("cordovaVersion", STR, 0x9, None)], direct=[
            meth("<clinit>", flags=0x10008, code=code(const_str("2.9.0"), put_obj(DEVICE, "cordovaVersion", STR),
                                                      raw(RETURN_VOID)), regs=1, ins=0, outs=0)]),
        cls(DUP, direct=[init()], virtual=[m("first", const_str("dup-1"))]),
        cls(SHARE_A, direct=[init()], virtual=[m("shared", const_str("share-a"), virt(USE, "plain"))]),
        cls(SHARE_B, direct=[init()], virtual=[m("unused", const_str("share-b"))]),
    ]


def dex2():
    return [
        cls(DUP, direct=[init()], virtual=[m("second", const_str("dup-2"), virt(APP, "startActivity", "V", (INTENT,), 0, 0))]),
        cls("Lcom/app/Other;", sup=TM, direct=[init(TM)], virtual=[
            m("checkServerTrusted", virt(TM, "checkServerTrusted", "V", X509, 0, 1, 2), params=X509)]),
    ]


def _share(dex: bytes, src: str, dst: str) -> bytes:
    """class `dst`'s class_def pointed at class `src`'s class_data (class_defs
    are in dex1() order)."""
    buf = bytearray(dex)
    _size, off = struct.unpack_from("<II", buf, 0x60)
    order = [c["name"] for c in dex1()]
    s, d = order.index(src), order.index(dst)
    data_off = struct.unpack_from("<I", buf, off + 32 * s + 24)[0]
    struct.pack_into("<I", buf, off + 32 * d + 24, data_off)
    struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:])))
    return bytes(buf)


def apk() -> bytes:
    return _apk_raw(_share(F.dex(dex1()), SHARE_A, SHARE_B), F.dex(dex2()))


# ── what the tests compare ───────────────────────────────────────────────────

_ADDR = re.compile(r" at 0x[0-9a-f]+>")


def _norm(s: str) -> str:
    return _ADDR.sub(" at 0x0>", s)


def _value(v):
    t = type(v).__name__
    return (t if t in ("int", "str", "bool", "NoneType", "list") else "object", _norm(str(v)))


def em_view(em):
    code = em.get_code()
    return (str(em), em.get_class_name(), em.class_name, em.get_name(), em.get_descriptor(),
            em.get_access_flags_string(), em.get_code_off(), em.get_information(), code is None,
            None if code is None else code.get_registers_size(),
            [(i.get_name(), i.get_output()) for i in em.get_instructions()])


def field_view(f):
    iv = f.get_init_value()
    return (str(f), f.get_class_name(), f.get_name(), f.get_descriptor(), f.get_access_flags_string(),
            None if iv is None else _value(iv.get_value()))


def class_view(c):
    return (str(c), repr(c), c.get_name(), c.get_superclassname(), list(c.get_interfaces()),
            c.get_access_flags_string(), [em_view(e) for e in c.get_methods()], [field_view(f) for f in c.get_fields()])


FIND = [
    ("Landroid/content/Intent", "getParcelableExtra", "."),
    ("Landroid/content/Intent", "getSelector", "."),
    ("Lcom/app/MainActivity", "startActivity", "."),
    ("Lcom/app/MainActivity", "startService", "."),
    ("^((?!LocalBroadcastManager).)*$", "registerReceiver",
     r"^\(Landroid/content/BroadcastReceiver; Landroid/content/IntentFilter;\)."),
    ("Ljava/lang/Math", "random", "."),
    ("Ljava/util/Random", "<init>", "."),
    ("Ljavax/net/ssl/X509TrustManager", "checkServerTrusted", "."),
    ("Lcom/app/TM;", ".*", ".*", "public"),
    ("Lcom/app/", "<init>", r"\(\)V", "public constructor", True),
    ("Lcom/app/Dup", ".", "."),
    ("Lorg/apache/cordova/", ".", "."),
    ("Lorg/apache/cordova/CordovaWebViewImpl;", ".", "."),
    (".*", ".*", ".*", ".*", True),
    ("L", "verify", r"\(Ljava/lang/String; Ljavax/net/ssl/SSLSession;\)Z", "public"),
]

DESCRIPTORS = [
    (CORDOVA, "CORDOVA_VERSION", STR), (CONSTS, "API_KEY", STR), (CONSTS, "LATE", STR), (CONSTS, "COUNT", "I"),
    (CONSTS, "inst", STR), (CONSTS, "nope", STR),
]
METHOD_DESCRIPTORS = [
    (DEVICE, "<clinit>", "()V"), (TM, "checkServerTrusted", "([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V"),
    (TM, "checkServerTrusted", "([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V"), (DUP, "first", "()V"),
    (DUP, "second", "()V"), (SHARE_B, "shared", "()V"), (SHARE_A, "shared", "()V"), ("Lcom/app/Nope;", "a", "()V"),
]
FIELD_REGEX = ["CORDOVA_VERSION", "C", ".*", "cordova", "NO_SUCH"]


def _xrefs(xs):
    return sorted((repr(ca), repr(ma), off) for ca, ma, off in xs)


def _ma(ma):
    return (repr(ma), str(ma.method), ma.class_name, ma.name, ma.descriptor, ma.is_external(),
            _xrefs(ma.get_xref_from()), _xrefs(ma.get_xref_to()))


def taint(dx, *pattern):
    """For every find_methods() match, each caller in get_xref_from():
    (klass.name, str(method), index) (a set: sorted), plus the instruction
    at that offset through get_instruction(0, index)."""
    out = []
    for ma in dx.find_methods(*pattern):
        for klass, xm, idx in ma.get_xref_from():
            i = xm.get_method().get_instruction(0, idx)
            out.append((klass.name, str(xm.method), idx, repr(xm), str(klass.get_vm_class()),
                        i.get_name(), i.get_op_value(), i.get_output()))
    return sorted(out)


def views(d, dx):
    out = {}
    per_dex = []
    for vm in d:
        classes = vm.get_classes()
        methods = list(vm.get_encoded_methods())
        per_dex.append({
            "classes": [class_view(c) for c in classes],
            "names": vm.get_classes_names(),
            "encoded_methods": [str(e) for e in methods],
            "distinct_methods": len(set(methods)),
            "get_class": [None if (c := vm.get_class(n)) is None else str(c) for n in (TM, DUP, "Lcom/app/Nope;")],
            "method_descriptor": [None if (e := vm.get_encoded_method_descriptor(*k)) is None else em_view(e)
                                  for k in METHOD_DESCRIPTORS],
            "field_descriptor": [None if (f := vm.get_encoded_field_descriptor(*k)) is None else field_view(f)
                                 for k in DESCRIPTORS],
            "encoded_field": [[str(f) for f in vm.get_encoded_field(r)] for r in FIELD_REGEX],
        })
    out["dex"] = per_dex
    out["find_methods"] = [[_ma(ma) for ma in dx.find_methods(*f)] for f in FIND]
    out["taint"] = [taint(dx, *f) for f in FIND[:8]]
    vm_classes = {}
    for ca in dx.get_classes():
        vc = ca.get_vm_class()
        if ca.is_external():
            vm_classes[ca.name] = (repr(ca), str(vc))
        else:
            vm_classes[ca.name] = (repr(ca), class_view(vc), [_ma(ma) for ma in ca.get_methods()],
                                   [(repr(fa), field_view(fa.get_field())) for fa in ca.get_fields()])
    out["classes"] = vm_classes
    out["tls_candidates"] = tls_candidates(d)
    return out


# ── a per-method walk: TLS-related methods ───────────────────────────────
#
# The EncodedMethods of get_encoded_methods(), in that order, that could
# implement or weaken TLS certificate/hostname checks, selected by name and
# by each instruction's get_name()/get_output(): a whole walk over the
# per-DEX objects, compared between androguard and androguard_rs.

TLS_METHOD_NAMES = frozenset({"checkServerTrusted", "verify", "onReceivedSslError"})
# (instruction name, how its get_output() must contain the marker, marker)
TLS_INSN_MARKERS = (
    ("new-instance", str.endswith, "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;"),
    ("sget-object", str.__contains__, "Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER"),
    ("invoke-static", str.endswith,
     "Landroid/net/SSLCertificateSocketFactory;->getInsecure(I Landroid/net/SSLSessionCache;)"
     "Ljavax/net/ssl/SSLSocketFactory;"),
)


def is_tls_candidate(em) -> bool:
    if em.get_name() in TLS_METHOD_NAMES:
        return True
    try:
        decoded = [(i.get_name(), i.get_output()) for i in em.get_instructions()]
    except Exception:  # noqa: BLE001 - undecodable code is always a candidate
        return True
    return any(name == op and test(out, marker)
               for name, out in decoded for op, test, marker in TLS_INSN_MARKERS)


def tls_candidates(vms) -> list:
    """Per DEX object, str() of every method is_tls_candidate() selects."""
    return [[str(em) for em in vm.get_encoded_methods() if is_tls_candidate(em)] for vm in vms]


# ── the same on real APKs (PARITY_APKS), without per-instruction detail ──────


def _em_light(em):
    code = em.get_code()
    return (str(em), em.class_name, em.get_information(), None if code is None else code.get_registers_size())


def apk_views(d, dx, sample=300):
    out = {}
    per_dex = []
    for vm in d:
        classes = vm.get_classes()
        methods = list(vm.get_encoded_methods())
        fields = vm.get_encoded_fields()
        per_dex.append({
            "classes": [(str(c), repr(c), list(c.get_interfaces()), c.get_access_flags_string(),
                         [_em_light(e) for e in c.get_methods()], [field_view(f) for f in c.get_fields()])
                        for c in classes],
            "n_methods": len(methods),
            "distinct_methods": len(set(methods)),
            "method_descriptor": [str(vm.get_encoded_method_descriptor(e.get_class_name(), e.get_name(),
                                                                       e.get_descriptor())) for e in methods[:sample]],
            "field_descriptor": [str(vm.get_encoded_field_descriptor(f.get_class_name(), f.get_name(),
                                                                     f.get_descriptor())) for f in fields[:sample]],
            "encoded_field": [str(f) for f in vm.get_encoded_field(".*VERSION")],
            "get_class": [str(vm.get_class(c.get_name())) for c in classes[:sample]],
        })
    out["dex"] = per_dex
    out["find_methods"] = [[_ma(ma) for ma in dx.find_methods(*f)] for f in FIND if f[0] != ".*"]
    out["taint"] = [taint(dx, *f) for f in FIND[:8]]
    vm_classes = []
    for ca in dx.get_classes():
        vc = ca.get_vm_class()
        if ca.is_external():
            vm_classes.append((repr(ca), str(vc)))
        else:
            vm_classes.append((repr(ca), str(vc), [repr(ma) for ma in ca.get_methods()],
                               [str(e) for e in vc.get_methods()], [field_view(f) for f in vc.get_fields()],
                               [repr(fa) for fa in ca.get_fields()]))
    out["classes"] = vm_classes
    out["tls_candidates"] = tls_candidates(d)
    return out
