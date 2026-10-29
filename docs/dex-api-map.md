# DEX, `Analysis` and the per-DEX objects vs androguard 4.1.3

What `androguard_rs.core.dex` (`DEX`, `ClassDefItem`, `EncodedMethod`,
`EncodedField`, ...), `androguard_rs.core.analysis.analysis` (`Analysis`,
`ClassAnalysis`, `MethodAnalysis`) and `androguard_rs.misc.AnalyzeAPK`
do where androguard 4.1.3's do, including how loading fails.

## Module layout

`androguard_rs` has androguard 4.1.3's module layout, so code switches by
renaming `androguard` to `androguard_rs` in its imports, same paths
(`androguard_rs.core.dex` is the module `androguard_rs.dex`, the same
classes; `python/tests/test_layout.py`):

| androguard 4.1.3 | `androguard_rs` (same module as) |
|---|---|
| `androguard.core.apk` (`APK`, `FileNotPresent`; `from androguard.core import apk`) | `androguard_rs.core.apk` (`androguard_rs.apk`) |
| `androguard.core.axml` (`AXMLPrinter`, `ARSCParser`, `ARSCResTableConfig`) | `androguard_rs.core.axml` (`androguard_rs.axml`; `ARSCParser` is `androguard_rs.apk.ARSCParser`) |
| `androguard.core.dex` (`DEX`, `ClassDefItem`, `EncodedMethod`, `DalvikCode`, `DCode`, `Instruction*`) | `androguard_rs.core.dex` (`androguard_rs.dex`) |
| `androguard.core.analysis.analysis` (`Analysis`, `ClassAnalysis`, `MethodAnalysis`) | `androguard_rs.core.analysis.analysis` (`androguard_rs.analysis`) |
| `androguard.core.api_specific_resources` (`load_permissions`, `load_permission_mappings`) | `androguard_rs.core.api_specific_resources` (`androguard_rs.api_specific_resources`) |
| `androguard.core.androconf.load_api_specific_resource_module` | `androguard_rs.core.androconf` |
| `androguard.util.set_log` | `androguard_rs.util.set_log` (no-op) |
| `androguard.misc.AnalyzeAPK` | `androguard_rs.misc.AnalyzeAPK` |
| `androguard.decompiler` | `androguard_rs.decompiler`: import only, the decompiler is not provided (see RecursionError below) |

## Construction and load errors

The usual manual load runs unchanged on the drop-ins:

```python
from androguard_rs.core.apk import APK
from androguard_rs.core.dex import DEX
from androguard_rs.core.analysis.analysis import Analysis

a = APK(raw, raw=True)
vmx = Analysis()
for b in a.get_all_dex():
    vm = DEX(b)
    vmx.add(vm)
    vm.set_analysis(vmx)
vmx.create_xref()
```

- `DEX(bytes)`: raises what androguard's `DEX()` raises, at the same
  point (`core/src/agload.rs` steps through its parse over the raw bytes):
  every `HeaderItem` check (`ValueError("Not a DEX file, Header too
  small.")`, `ValueError("This is not a DEX file! Wrong endian tag:
  '0x…'")`, `NotImplementedError("Byte swapped endian tag
  encountered!")`, wrong magic, Adler-32 checksum, header size, too many
  type or proto ids), then the map list and every section it declares, in
  androguard's load order: `struct.error` for a short read,
  `ValueError('N is not a valid TypeMapItem')`, `KeyError(<TypeMapItem.…>)`
  for a missing section something resolves through, `KeyError(off)` for an
  undeclared type_list, `AttributeError` for a method_id whose proto is out
  of range ("'ProtoIdItemInvalid' object has no attribute …") or a class
  whose static values aren't there ("'NoneType' object has no attribute
  'get_value'"), a moved HEADER_ITEM's header checks, hidden-API flag enum
  errors, `RecursionError` for nested encoded values (see below). The
  exception is built so that type, `args` and `str()` are androguard's
  (`androguard_rs._agerr`; `TypeMapItem` and
  `HiddenApiClassDataItem.RestrictionApiFlag`/`DomapiApiFlag` are in
  `androguard_rs.dex`). The bytes are kept.
- `Analysis()` / `add(vm)`: as androguard's `add()`, appends the DEX and
  raises what it raises for it: `AttributeError("'DEX' object has no
  attribute 'classes'")` without a map list, `IndexError` for a class with
  no hidden-API flags, `KeyError(<TypeMapItem.METHOD_ID_ITEM: 5>)` without
  method_ids, `InvalidInstruction` (same args and `str()`) for the first
  method it can't disassemble, `struct.error` for code cut to an odd length
  by the end of the file, `IndexError` for a try whose handler offset
  matches no handler (`determineException`), in androguard's order.
- `create_xref()`: raises what androguard's raises walking the
  instructions (`IndexError('string index out of range')` for a
  const-class/new-instance of, or an invoke on, a type whose name is empty
  once `[` are stripped; `KeyError` for a field/string reference without
  that section), then builds one native index (`androguard_rs.Apk`) over
  every added DEX, in order, binds each DEX object to it and drops the
  bytes. A second call returns, as androguard's does.
- `vm.set_analysis(vmx)`: kept, unused.

`androguard_rs.misc.AnalyzeAPK` gives the same kinds of objects (`d` is the list of
`DEX`, bound to the index) and raises at load what androguard's raises, in
its order: `DEX()` then `add()` for each DEX file in turn, `create_xref()`
last (`python/tests/test_strict.py`; `tolerant=True` loads anyway).

The id tables are read from the map list's sections, and a string_id whose
data the map doesn't declare is `AG:IS: invalid string`, as in androguard;
code cut short by the end of the file is read as far as it goes.

### RecursionError

androguard parses nested encoded values (arrays in arrays, annotations in
annotations) recursively, so a deep enough nesting raises
`RecursionError('maximum recursion depth exceeded')` from Python's
recursion limit, or, when that is high, from CPython 3.12's separate C
recursion limit (each nested instantiation counts). Where depends on the
caller's stack: `DEX()` and `AnalyzeAPK` measure what is left (Python
frames above the caller, and C units by nesting instantiations until
RecursionError, which takes about 2 ms) and the native walk counts each
frame and unit androguard's code would use, so the error comes at the same
nesting (`test_strict_parity.py::test_recursion_depth`: several caller
depths, both paths, arrays and annotations; the one assumption is that
loguru has no handler on that path, as androguard's own `set_log` above
DEBUG leaves it).

Importing `androguard.misc` or `androguard.decompiler` raises the recursion
limit to 5000 (`sys.setrecursionlimit` in
`androguard/decompiler/__init__.py`), and so does importing
`androguard_rs.misc` or `androguard_rs.decompiler` (which provides nothing
else; any other name from it raises `NotImplementedError`). Code that
drops its decompiler use should keep `import androguard_rs.decompiler` to
keep that limit.

### An intentional difference in loading

A string_data_item running to the end of the file without a NUL makes
androguard's `read_null_terminated_string` loop forever (its list of empty
reads grows until memory runs out). androguard-rs raises `MemoryError()` at
once.

## Per-DEX objects

| androguard API | here (`androguard_rs.dex`) |
|---|---|
| `DEX.get_classes()` | a list of `ClassDefItem`: `get_name()`, `get_superclassname()`, `get_interfaces()`, `get_access_flags_string()`, `get_methods()`, `get_fields()`, `str()`/`repr()` (`<dvm.ClassDefItem super->name>`); unknown attributes are `AttributeError` |
| `DEX.get_class(name)` | the first class_def of that name in this DEX, or None |
| `DEX.get_encoded_methods()` | every class_def's methods in order; a class_data shared by several class_defs is listed once per class_def (equal handles) |
| `DEX.find_methods_referencing(names, rules, include_unreadable=True)` | androguard_rs extension, not androguard API (see below) |
| `get_encoded_method_descriptor(cls, name, desc)`, `get_encoded_field_descriptor(cls, name, desc)` | androguard's lookup: `class + name + descriptor` concatenated (descriptor with spaces), last match in class_def order; done natively, nothing cached |
| `get_encoded_field(regex)` | `re.match` on every field's name, in `get_encoded_fields()` order |
| `EncodedMethod.get_information()`, `get_access_flags_string()` | androguard 4.1.3's results, computed natively (its `get_type()` ported; the module-level `androguard_rs.dex.get_type()` is androguard's code verbatim), with `registers_size` read natively: `{}` without code, `"registers"` `(0, nb - len(params) - 1)`, `"params"` only with parameters (registers can be negative, as in androguard) |
| `EncodedMethod` attributes | `class_name` (its method_id's class), `name`, `proto`, `access_flags`, `code_off`, `method_idx`, `code`, `CM` (`CM.vm` is the method's DEX object) |
| `str(EncodedMethod)` | `cls->name(desc) [access_flags=…] @ 0x<code_off>` |
| `EncodedField.get_init_value().get_value()` | typed as androguard's (int, str, bool, None, lists for field/method references; arrays and annotations are objects whose `str()` is androguard's with the address as `0x0`); `None` without a value |

A class defined in two DEX files is in each DEX object with that DEX's
class_data (`test_dexobj.py::test_dup_class_per_dex`).

### `find_methods_referencing()` (androguard_rs extension)

`DEX.find_methods_referencing(names=(), rules=(), include_unreadable=True)`
is not androguard API. It answers in one native pass, classes in parallel,
what callers otherwise ask with a full walk over `get_encoded_methods()`
and every method's `get_instructions()`: the EncodedMethods, in
`get_encoded_methods()` order, whose `get_name()` is in `names`, or one of
whose instructions passes a rule `(opcode names or None, "endswith" |
"contains", text)` on its `get_output()` (an instruction whose output is
None passes), or, with `include_unreadable`, whose code can't be
disassembled. The methods returned are equal to (the same handles as) what
`get_encoded_methods()` hands out, so a caller narrows its walk to them and
runs its own checks on them only. It raises `ValueError` for an unknown
opcode name or mode. Feature-detect it, so the same code runs on
androguard:

```python
a, d, dx = AnalyzeAPK("app.apk")
rules = [(("new-instance",), "endswith", "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;")]
for vm in d:
    if hasattr(vm, "find_methods_referencing"):
        candidates = vm.find_methods_referencing(["checkServerTrusted"], rules)
    else:
        candidates = vm.get_encoded_methods()
    for m in candidates:
        ...                     # the caller's own checks
```

`test_dexobj_parity.py::test_find_methods_referencing` compares it with
that walk over androguard's objects on each of `PARITY_APKS`.

## `Analysis.find_methods`, `MethodAnalysis`

- `find_methods(classname, methodname, descriptor, accessflags,
  no_external)`: every class in `dx.classes` order (external ones too), its
  `get_methods()`, matched with Python's `re.match` on the native rows'
  name, descriptor (with spaces) and flags (`""` for an ExternalMethod,
  which `no_external` drops), as androguard; unescaped class names,
  lookaheads and space-separated descriptors work as there.
- `MethodAnalysis.method`; `repr()`/`str()` is androguard's
  `<analysis.MethodAnalysis {method}>`; `get_method().get_instruction(idx,
  off)` as androguard's; `get_vm_class()` gives `super->name` (internal) or
  `<analysis.ExternalClass name>` (external) as `str()`.
- `get_xref_from()`/`get_xref_to()` return a `set` of `(ClassAnalysis,
  MethodAnalysis, offset)`.

Order: androguard returns a `set` of tuples hashed by object identity, so
its iteration order is the memory-address order of that run: arbitrary
and different from run to run. Here it is a `set` subclass (set
operations, `in`, `len`) that iterates in a fixed order, the index's (one
of androguard's possible orders, the same every run). Whatever a caller
derives from iteration order (`next(iter(...))`, last-wins dicts) is
deterministic here and run-dependent in androguard; every such result is
one androguard can produce. The tests compare these as sorted lists.

Unknown attributes: an attribute androguard's object doesn't have either
raises `AttributeError` with androguard's message; one it has that isn't
implemented raises `NotImplementedError` and is counted in `GAPS`.

## Rust owns the data; Python gets per-query handles

The native index (Rust) owns everything: the DEX bytes, the id tables, the
class list, method rows, cross-references and the decoder. Nothing is
materialized per APK in Python, up front or later. Every object a query
returns (`ClassDefItem`, `EncodedMethod`, `EncodedField`, `DalvikCode`,
`DCode`, `Instruction` and payloads, `ClassAnalysis`, `MethodAnalysis`,
`ExternalClass`) is a handle made for that query: the native index plus
integer keys (DEX number, class_def index, class_data offset and position,
method_idx/field_idx, access flags, code_off; an instruction is its
method's code and its offset), and every method asks the index. Only the
APK, the DEX list and the Analysis live on. `get_encoded_methods()` is a
lazy view (iterable, `len()`, indexable, `+`) made as it is walked.

What the index keeps natively, besides the bytes and tables: one `str` per
distinct DEX string, type name, descriptor, flags string and resolved
reference handed out (as androguard's objects share the DEX's string
table), and the instruction boundaries of the last 32 methods asked for
(so `get_instruction(idx)` stepping through a method decodes it once).

### Intentional differences

These follow from handing out handles instead of androguard's single
long-lived objects, and keep memory bounded:

- **`is`-identity across queries.** An object from a second query is a new
  object: `dx.get_classes()` walked twice, `get_instructions()` asked
  twice, `get_vm_class()` / `get_code()` / `get_bc()` called twice give
  equal objects (`==`, same `hash()`), not the same ones (`is`). Equality is
  by what they stand for (a ClassDefItem by DEX and class_def; an
  instruction by its method's code and offset; a ClassAnalysis by Analysis
  and name; a MethodAnalysis by its method; an ExternalMethod by
  class/name/descriptor), so the same method reached through
  `get_methods()`, `get_encoded_methods()`,
  `get_encoded_method_descriptor()`, `find_methods()`,
  `find_methods_referencing()` or an xref compares and hashes equal, and
  sets and dicts of them dedupe as androguard's do
  (`python/tests/test_handles.py`).
- **`EncodedMethod` / `EncodedField` equality** is by (DEX, class_data
  offset, position in the class_data). That matches androguard, which
  builds one object per class_data entry and shares it among the
  class_defs pointing at that class_data (only in crafted files): such
  class_defs list equal methods here and the same objects there.
- **`add_note()`** notes on a payload stay on the one object they were
  added to; asking for the method's instructions again gives payloads
  without them (androguard's cached payload keeps them).
- **`get_information()` on deep array types.** androguard's `get_type()`
  recurses once per array dimension, so a parameter or return type with
  more dimensions than the caller's remaining recursion depth (just under
  1,000 at Python's default limit, just under 5,000 once `androguard.misc`
  or `androguard_rs.misc` has raised it) raises `RecursionError` there; the
  native port returns the type. DEX caps array dimensions at 255, so only a malformed
  file can tell the difference.

The other intentional difference is in loading (`MemoryError` for an
unterminated string, above).

### Tuning: `ANDROGUARD_RS_CACHE`

The default is recommended. `ANDROGUARD_RS_CACHE`, read when the index is
built (comma-separated words), trades memory for speed on unusual access
patterns:

- `noatoms`: make a new `str` for every DEX string, type name,
  descriptor, flags string and resolved reference asked for, instead of
  one per distinct value (less memory kept, more allocation);
- `spans`: keep every method's instruction boundaries once decoded (6
  bytes per instruction), instead of the last `lru` methods' only;
- `text`: keep every instruction's rendered text once asked for;
- `lru=N`: how many methods' boundaries the default keeps (32).

`Apk._cache_info()` (a diagnostic, underscore-named and not stable API)
returns the settings in use and how much is kept.

## Tests

- `test_dexobj.py` (no androguard; goldens `dexobj_goldens.py` from
  `scripts/gen_dexobj_goldens.py`): every view above from `AnalyzeAPK`,
  from the manual load and from the facade, on `dexobj_cases.apk()`
  (TLS-related classes, Intent sources and sinks, typed static values, a
  class in both DEX files, two class_defs sharing a class_data, a
  per-method instruction walk); identity and AttributeError semantics.
- `test_handles.py` (no androguard): the handles above, on the synthetic
  APK: every route to a method, field, class, code item or instruction
  gives equal, hash-equal objects, sets dedupe, and walking everything
  again keeps nothing on the Python side.
- `test_dexobj_parity.py`: the same live, and `apk_views()` (every class,
  method and field of every DEX object, find_methods, xref callers,
  get_vm_class(), MethodAnalysis repr()s, the per-method walk),
  `find_methods()`/`find_classes()` for every permission-map signature and
  tricky patterns, and `find_methods_referencing()` against the equivalent
  walk, on each of `PARITY_APKS`.
- `test_strict.py` / `test_strict_parity.py`: load errors, `AnalyzeAPK`
  and the manual load (the header checks, the map list and its sections,
  add() and create_xref() failures, orders across DEX files; goldens from
  androguard 4.1.3 by `scripts/gen_dexobj_goldens.py`), the RecursionError
  depths live, and the case androguard never returns from.
- `test_layout.py`: the module paths above, and `core.androconf` against
  androguard's.
- `scripts/load_difffuzz.py`: mutates real DEX files and compares
  accept/reject and the exception (stage, type, `args`, `str()`) with
  androguard 4.1.3, one DEX or two per case; `--deep` also compares what
  the objects show for mutants both load.

## Gaps

- **Decompiler**: not provided (`androguard_rs.decompiler` is import-only).
- **Orders androguard derives from sets** (above): deterministic here.
- **Handles** (above): `is`-identity across queries, `add_note()`, deep
  array types in `get_information()`.
- `str()` of an EncodedArray/EncodedAnnotation value: androguard prints a
  memory address; here `0x0`.
- `Instruction.cm` and `get_raw_string()` (`docs/instruction-api.md`).
- `ARSCParser.get_resolved_res_configs(rid, config=...)` with a config
  filter (`NotImplementedError`); without one, the result is androguard's,
  `ARSCResTableConfig` objects included (`docs/resources-api-map.md`).
- Crafted DEX files androguard loads but whose members can't be named
  (out-of-range method/type/string indices in class_data or ids,
  undecodable names, several classes with the same unresolvable name):
  androguard keeps one object per item, with placeholder names
  (`AG:IS: invalid string`, ...); the index keys methods and classes by
  name, so some of those members' xrefs and facade lookups differ (a
  facade lookup can raise NotImplementedError). Load errors are not
  affected. `scripts/load_difffuzz.py --deep` measures it; real APKs
  don't have such members.
- APK side (`APK`, `AXMLPrinter`, signing): `docs/apk-api-map.md`.
