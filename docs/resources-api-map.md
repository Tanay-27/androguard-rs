# Resources: `androguard_rs.Resources` vs androguard 4.1.3's `ARSCParser`

`androguard_rs.Resources` parses `resources.arsc` natively and answers the
`ARSCParser` queries below with androguard 4.1.3's results and failures.
androguard's parser holds the whole table as Python objects (hundreds of
MiB for a large table); `Resources` keeps the bytes and compact indexes.

## Construction

androguard gets the parser through `APK.get_android_resources()`, which
caches it in `a.arsc` and parses on first call: a constructor error is
raised from every call, and `None` means the APK has no `resources.arsc`.

- `Resources(a.get_file("resources.arsc"))` parses exactly the bytes
  androguard parses.
- `Resources.from_apk(path)` returns `None` without a `resources.arsc`. It
  reads the zip the way apkInspector does (`core/src/zipapk.rs`, as
  `androguard_rs.apk.APK` does), so a tampered entry (local header vs
  central directory, a repeated name, a later local header named
  `resources.arsc`) gives the same bytes, and an entry listed without a
  readable local header fails as androguard's `KeyError` does.
  `python/tests/test_arsc_zip.py` checks such zips against goldens from
  androguard 4.1.3 (`scripts/gen_arsc_zip_goldens.py`).
- `androguard_rs.apk.APK.get_android_resources()` returns an
  `ARSCParser`-shaped object over `Resources`.

## Queries

| androguard API | `androguard_rs` |
|---|---|
| `get_packages_names()` | identical |
| `get_public_resources(package_name, locale="\x00\x00")` | byte-identical XML: every entry of every config of that locale, duplicates included; a package missing from the table gives an empty `<resources>`; names aren't escaped |
| `get_resolved_strings()` | `{package: {locale or "DEFAULT": {rid: str or None}}}`: equal dicts, same key order at every level |
| `get_resolved_res_configs(rid)` | the same values, nesting and order, references followed; the config comes back as `ARSCResTableConfig._get_tuple()` (a 9-tuple) instead of the object; `rid == 0` raises `ValueError`, as androguard does |
| `get_resource_xml_name(rid, package=None)` | `"@package:type/name"` from the first package whose default-locale public list has `rid`, else `None` (also `None` for a match in a package with an empty name); O(1), where androguard scans linearly |

## androguard behaviour preserved, quirks included

- A failed `_analyse()` raises from the first query that runs it. Later
  queries see the partial `values`/`resource_values`, and
  `get_resolved_strings()` then raises `KeyError` for any package the analysis
  never reached.
- In `get_public_resources()` and `get_resolved_strings()`, "public" means
  every entry (`get_index() != -1` is always true). Its strings come from the
  value pool regardless of the value's type.
- `get_resolved_res_configs()` skips a reference to the entry itself. Any
  longer reference cycle recurses until `RecursionError`, so we raise there
  too. Configs that differ only in script/variant collapse, because
  `_get_tuple()` omits them.
- Compact entries keep 4.1.3's mixed-up key and value fields. `stringCount` is
  recomputed from `stringsOffset`. A package name without a NUL loses its last
  character. Errors come from short reads (`struct.error`), unterminated
  strings, a missing main pool, and the eagerly formatted debug `repr()`s that
  decode a type's name or read a weak entry's value. Each of these is an
  exception, in the same place.

## Differences

- Exception types: everything androguard raises from the parser
  (`ResParserError`, `struct.error`, `AttributeError`, `IndexError`, `KeyError`,
  `RecursionError`) is `androguard_rs.ResourcesError`.
- Limits on hostile input, where androguard would run on or blow up: the
  public XML is capped at 64 MiB, a query decodes at most 256 MiB of strings,
  and one `get_resolved_res_configs()` does at most 2^20 steps and follows at
  most 300 references deep. androguard's own depth limit is Python's recursion
  limit, which depends on the caller's stack (about 330 references from a
  shallow one). Real tables stay far below each budget.
- Only androguard 4.1.3's behaviour is implemented. 4.1.4 changed resource
  parsing (sparse entries, compact entries' names and values, unterminated
  UTF-8 strings, a non-zero reserved field, junk between chunks); the places
  to change are marked "4.1.4:" in `core/src/arsc.rs`.

## Tests

`python/tests/test_resources.py` compares every query above, exhaustively
(every package and locale, every rid androguard has a value for, plus rids
it doesn't, errors included) on:

- each APK in `$PARITY_APKS` and `$PARITY_LARGE_APKS` (the second for APKs
  too big for `AnalyzeAPK`);
- synthetic tables covering UTF-16 pools, compact and 16-bit-offset entries,
  several packages, references and cycles, and every value type;
- mutants of all of the above (byte flips, header-field rewrites,
  truncation), where errors must match too.

The `arsc` fuzz target runs arbitrary bytes through every query.
