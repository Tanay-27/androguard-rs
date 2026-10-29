# Vendored: dex-bytecode

| | |
|---|---|
| Upstream | https://github.com/androguard/dex-bytecode |
| Path | `dex-bytecode/` (library crate only; the CLI, examples and Python bindings were not copied) |
| Commit | `7d40b753480131bff4d5c1786b5f698b630f2bac` (2026-10-25) |
| License | Apache-2.0, see `LICENSE` (upstream ships no NOTICE file) |
| Upstream README | `UPSTREAM_README.md` |

## Why vendored

We need instruction text that is byte-identical to **androguard 4.1.3**'s
`Instruction.get_name()` / `get_output()`: callers' text output and
substring searches depend on it. Upstream targets androguard's newer code and
differs from 4.1.3 in several places. Vendoring lets us pin that behaviour
without following upstream's changes.

## Modifications

The first commit adding this directory is upstream's code unchanged. Every
later change is a separate commit touching `vendor/dex-bytecode/`; use
`git log -p -- vendor/dex-bytecode` to review them. Each modified source file
carries a header comment saying it was changed. Changes are listed below.

1. **Operand text matches androguard 4.1.3** (`src/decoder.rs`):
   - Branch offsets use Python's `{:+0Nx}h`, where the sign counts toward
     the width (`+007h`, not `+0007h`).
   - `const-string` (21c) wraps its string in `"…"`; `const-string/jumbo`
     (31c) doesn't.
   - Payloads print androguard's `get_output()`: switch keys as `%x`, and
     fill-array-data as `repr(bytes) | \xNN…`.
   - `invoke-polymorphic(/range)` print raw method/proto indices. When the
     register count is 0, androguard's `get_output()` returns `None`:
     `Instruction::output_is_none` flags that case (`src/instruction.rs`),
     and the operands hold `"None"`.
   - 35c with a register count over 5 prints nothing. Register ranges use
     signed arithmetic, so an empty range prints `vC ... v(C-1)`.
2. **Same invalid-bytecode behaviour as androguard 4.1.3's
   `LinearSweepAlgorithm`** (`src/decoder.rs`, `src/error.rs`):
   - These reject the method:
     - any unit above 0xFF whose low byte is 0x00/0xFF and isn't a known
       payload;
     - an unused opcode;
     - a nonzero padding byte in 10x/20t/30t/32x;
     - a 45cc register count over 5;
     - any short read.
   - `DexError::message()` is androguard's inner `InvalidInstruction`
     message verbatim. A short read reports `repr()` of every byte left in
     the method, as androguard's struct.error path does.
   - `DexError::offset` is the byte offset the sweep stopped at.
   - Payloads parse exactly as androguard parses them:
     - fill-array-data silently truncates its data;
     - packed-switch reads fewer targets when its size overruns the buffer;
     - a payload whose length runs past the method ends the sweep without
       an error.
3. **Removed the text assembler** (`src/encode.rs`, `src/test/encode_roundtrip.rs`).
   It parsed upstream's operand text, which this decoder no longer emits, and
   we never assemble bytecode. The byte-level patch helpers (`src/patch.rs`)
   are kept.
4. **No preallocation from untrusted lengths** (`src/decoder.rs`):
   `decode_all_with_resolver` no longer reserves `code_len / 2` instructions
   up front. A crafted method could otherwise force a multi-GiB allocation.
5. **Tests updated** to androguard 4.1.3 output (`src/test/mod.rs`,
   `src/test/instructions/format_f21c.rs`, `src/test/instructions/format_f45cc.rs`).

Verified against androguard 4.1.3 on every instruction of real APKs and on
synthetic DEX files covering every format; see the top-level README.
