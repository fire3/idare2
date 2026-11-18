# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `--reimport` rebuilds the database from the input file. A `.i64` that a
  crash (or a worker killed mid-save) left truncated cannot be opened by IDA
  at all: every later command used to fail with `ERROR: WorkerStartError:
  idat worker N exited with status 4` plus IDA's b-tree banner. The flag is
  opt-in because rebuilding discards the database's analysis, names and
  comments.

### Fixed

- `f` now seeds flags with the symbol-table size, so `f~func_a` prints the
  same width as r2 instead of 1.
- `pd N` on a raw blob is now a linear decode like r2: it continues past a
  `return`, and decodes bytes IDA had not marked as code (the item is created
  only for the render pass and removed afterwards). Previously `pd 6` on
  ARM/MIPS/PPC/6502/AVR raw targets stopped after one or two instructions.
- `-b 8` is accepted for the byte-wide processors (6502/8051/AVR). IDA models
  them as 16-bit, so the hint is translated instead of rejected; r2 scripts
  that pass `-b 8` now work unchanged.
- A bare `-a ppc` now defaults to little-endian, matching r2's
  `cfg.bigendian=false`; IDA's PowerPC processor defaults to big-endian, which
  made little-endian raw PPC targets produce no disassembly.
- A database IDA cannot open is now reported as one actionable line naming the
  `.i64` and the IDA diagnosis (`Database initialization failed with error 4`),
  with a pointer at `--reimport`, and exits 3 (no database) instead of 4
  (transport). When no IDB existed before the attempt the message says so
  instead of pointing at `--reimport`: IDA has no loader or processor for the
  file (an sBPF ELF, for example), and `-a/-b` forces a raw import. Other
  worker-start failures keep their original error.

## [0.2.1] - 2026-11-16

### Fixed

- `ii` now resolves the vaddr of function imports from their PLT stub (IDA
  names the stub `.puts` while the import is `puts`), so the column matches r2
  instead of `----------`. The table also uses r2's fixed 37-character rule,
  even when a long symbol name overflows it.
- `iIj` is now a real token (`iI` as JSON), and `-j` maps `iI` onto it. The
  JSON bundle workflows that call `iIj` no longer fail with "unsupported
  information command 'Ij'".
- Unmapped reads (`px`/`p8` past EOF) now return `ff` bytes instead of failing
  the command, matching r2; a partially mapped read keeps its readable prefix.
- The numeric repeat prefix now repeats the command's output too:
  `3?e x` prints `x` three times instead of only the last iteration.
- Backtick and `$(...)` substitution run before parsing, so
  `?e v-`?e sub`` prints `v-sub` like r2 (nested substitution is bounded).
- `u`/`U` (undo/redo) now work in a read-only session. They only replay IDA's
  undo/redo history, so reverting a patch that an earlier `-w` session wrote
  succeeds instead of failing with "could modify the database".
- A quiet batch invocation with no `-c`/`-i` now reads commands from stdin
  like r2: `printf 'ie\nq\n' | idare2 -q file` prints the entry table and
  exits.  Piped commands used to be ignored entirely, leaving stdout empty.
- `s entry0` (and any `@ entry0`) now resolves to the program entry point.
  radare2 synthesises an `entry0` flag, while IDA keeps the loader's own
  spelling (`_start`, `start`, ...), so the r2 name used to fail with
  `ERROR: cannot resolve name 'entry0'` and made a batch run exit non-zero.

- `-a` now accepts radare2 architecture names (`x86`, `arm`, `mips`, `ppc`,
  `riscv`, `m68k`, `sparc`, `sh`, `s390`, ...) and maps them to the IDA
  processor module they select. `-a x86` used to be passed to IDA verbatim,
  which failed with "The processor type 'x86' is not included" because IDA
  calls that module `metapc`. IDA processor names (`metapc`, `mipsb`,
  `sparcb`, `arm:ARMv7`, ...) still work unchanged.
- Removed the idare2-only `--color` and `--endian` long options. Their
  radare2 spellings work instead: `-e scr.color=0` and
  `-e cfg.bigendian=true|false` (the latter is applied as a raw-import hint
  before the database is opened).

## [0.2.0] - 2026-11-14

Output-format alignment with radare2 6.2.6, from the CLI-difference
re-evaluation of 2026-11-14 (`docs/r2-parity-report.md` §15), continued by
the 0.2 roadmap (`docs/roadmap-0.2.md`, local notes).

### Added

- `Cf [sz] [fmt]` materialises a pf format as IDA data items (`Cf 16 [4]d`
  defines four dwords) and stores the format string as a repeatable comment;
  `Cf-` undefines the span and drops the comment. Scalar and array formats
  map to `create_byte/word/dword/qword/float/double/oword_at`; unions, nested
  braces and NUL-terminated string fields are rejected explicitly. A failing
  item keeps the earlier ones (IDA has no rollback) and the command warns
  `applied N of M`.
- `pFa/pFo/pFp/pFx` decode ASN.1/DER, OIDs, PKCS#7 and X.509 — pure
  client-side DER parsing (`idare2.asn1`), so every backend behaves the same
  and the worker does no work. Strict DER (BER indefinite lengths, non-minimal
  encodings and multi-byte tags are rejected with the offset); r2-shaped
  indented tree with absolute offsets, `key: value` certificate fields and
  `j` JSON forms. Tested against a real system certificate.
- `$w`, `$M` and `$S` join `?$`: word size, lowest map address and the
  offset of the segment holding the seek (r2 6.2.6's spellings; the older
  `$x`/`$X`/`$I` trio is not in 6.2.6, so it stays out).
- `iSS` names the program-header types r2 does (`NOTE`, `TLS`,
  `GNU_RELRO`, `GNU_PROPERTY` …, previously the raw `PT_4`) and dedups
  repeated segment names with r2's `_N` suffix (`NOTE`, `NOTE_1`).
- `pd -N`/`pd--` walk back through undefined items: the backward walk used
  IDA's defined-instruction navigation and stopped at the first gap, so a
  function start preceded by a literal pool or padding returned nothing
  where r2 decodes straight through. Each step now falls back to decoding
  raw bytes (the instruction must end exactly at the seek, like r2's
  contiguous linear walk).
- Decimal value dumps (`pxd`/`pxu`) label the header with the low byte of
  each value's address, right-aligned to two characters — the old single
  nibble labels only matched r2 when all labels were below `0x10`. Verified
  against r2 6.2.6 at `0x10000` and `0xc8c48`; the rendering at aligned
  addresses is byte-identical to before.
- `aflj`/`afij` now carry r2's graph statistics `C`/`CC.` read only the REGULAR
  kind, so `CCr` notes (and `Cf`'s stored format) were set-but-invisible;
  both reads now use `CommentKind.ALL`.
- `aflj`/`afij` now carry r2's graph statistics — `edges`, `cc`,
  `maxbbins`, `midbbins`, `ratbbins`, `is-lineal` — computed in a single
  walk per function (the flow chart and the instruction enumeration used to
  be two separate traversals). `cc` is `edges − nbbs + 2` with a floor of 1,
  verified against r2 6.2.6 per-function on the parity fixture. The `nlocals`
  key stays out of `aflj` rows on purpose: a Hex-Rays query per function
  tripled the run on a 2435-function binary, so the local count only appears
  in `afij` (one function at a time), which keeps the ≤1.5× `afl` perf bound.

### Added

- `tools/cmdsurface.py`: the command-surface probe from the 2026-11-14
  re-evaluation — harvests r2's help tree, probes idare2 with one batch
  session and reports supported / excluded / missing per command token
  (`--json` for archives).
- `e asm.syntax` selects the immediate style of the disassembly: `intel`
  (the default) rewrites IDA's MASM-style `11h` to r2's `0x11`; `masm` keeps
  IDA's text. `pa`/`wa`/`/a` accept either spelling — the user's r2-style
  text is converted to what IDA's assembler wants, and the rasm2 fallback
  receives r2 syntax and runs with `-S intel`.
- `CCa [addr] [base64:..|text]` and `CCa- [addr]`, r2's comment-at-address
  forms.
- `e scr.nkey` selects what `sn`/`sp` walk (`flag`, the r2 default, `func` or
  `instr`); they used to always walk instructions.

### Fixed

- `ie`/`iej` now report the loader entry point in r2's table shape
  (`paddr vaddr phaddr vhaddr type`, read from the ELF header) instead of
  dumping the export table; `ies` and `iE` keep the symbol forms.
- `sn`/`sp` walk the nearest flag like r2's default `scr.nkey=flag`.
- Table header rules now span the whole header row (gaps included), as r2's
  do, instead of stopping short with trailing spaces.

### Fixed

- Addresses now render the way radare2 6.x does: zero-padded to 8 hex digits
  at any bitness, and never truncated — `pd`/`afl`/`px`/`axt` and the prompt
  used to pad 64-bit addresses to 16 digits, and `fmt_addr` masked values
  above `2**32` when the width was 8.
- `px`'s header labels each offset with its low byte right-aligned to two
  characters without zero padding (`- offset -   0 1  2 3 ...` at `0x4000`,
  `1011 1213 ...` at `0x8d10`), matching r2 6.2.6 byte-for-byte; the table
  header rule is ASCII `-` again (r2 6.x stopped using U+2015).
- `iz` now reports only data strings like r2: ELF sections whose type is
  SYMTAB/STRTAB/RELA/DYNAMIC/NOTE/REL/DYNSYM, plus `.interp`-style metadata
  sections, are excluded; the `type` column maps IDA's `StringType` enum to
  `ascii`/`utf16le`/`utf32le` instead of printing the raw enum number (`0`).
- `?` prints r2 6.2.6's full block: `int32`/`uint32` (or `int64`/`uint64`
  past 32 bits), plus the `string`, `fvalue`, `float`, `double`, `base36` and
  `ternary` rows. `?j` returns r2's object shape. Empty value forms print
  zero (`?v` → `0`, `?b` → `0b`, `?o` → `00`).
- `?b` suffixes the digits with `b` (`10100b`) and `?o` keeps octal's leading
  zero (`024`), as r2 does.
- Bare `s` prints the address unpadded (`0x1140`); the zero-padded form stays
  `s:`. `b` prints the block size in hex (`0x100`).
- `aa`/`aaa` are silent on success like r2.
- Bare `pr` writes the bytes untouched instead of decoding them as UTF-8
  (which replaced non-UTF-8 bytes with U+FFFD and split lines); with `~`, `|`,
  `>` or repeats it degrades to latin-1 text lines.
- The rasm2 fallback passes the address as `-s` again: rasm2 6.2.6 treats
  `-o` as the *output file*, so the 0.1.1 change made it read stdin and print
  nothing.
- `?`'s command index no longer claims a bare `p` command, and `i?` lists
  `ic`.

### Changed

- Tests: the parity helper drops header rules by character set, the parity
  and integration expectations follow the new address/number renderings, and
  new unit tests pin the `px` header, `?` block, `iz` filtering, `pr` raw
  path and address widths.

## [0.1.3] - 2026-11-14

Fixes from the agent-driven live-test campaign of 2026-11-14 (416 recorded
probes over 20 ELF/PE/Mach-O binaries, 13 raw slices and an IDB).

### Fixed

- `--no-save-on-close` (and a writable batch without an explicit `w`) is now
  honoured: the worker shutdown ran `handle.take_snapshot()`, which does not
  exist in ida-nexus 0.14.2, so the shutdown request never reached Nexus and
  the worker saved on its own exit. Saving at close now requires
  `--save-on-close`; an explicit `w`/`wq` still saves.
- Text output no longer truncates 64-bit addresses above 4 GiB: the client
  read the key `bits` while `open_summary` reports `bitness`, so every address
  on PE64/MIPS64/Mach-O databases rendered as its low 32 bits.
- `iI` now reports `stripped`/`lsyms` from the input file's symbol table (the
  same source `is` uses) instead of IDA's synthesised name table, and shapes
  `arch`/`bintype`/`os` the way r2 does (`x86`/`elf`/`linux`, `pe`/`windows`,
  `mach0`/`darwin`).
- `-j` no longer turns commands without a JSON form into usage errors
  (`iI`, `iM`, `ig`, `af`, `pD`); the substitution is token-level.
- `--backend idalib` now selects the backend for path opens; `--backend gui`
  on a path fails with a clear message instead of silently spawning a worker.
- `f` lists names written into the IDB by an earlier session (flags, `afn`
  renames); it previously seeded only from the original ELF symbol table.
- A command-line `-e` overrides rc files and projects, as r2's does.
- Opening a directory or passing a non-positive `--timeout`/`--idle`/
  `--startup-timeout` now fails with a one-line usage error instead of an
  opaque `WorkerStartError`.

### Changed

- README: the memory row lists `p=d` (the only `p=` form implemented) instead
  of `p=`.

## [0.1.2] - 2026-11-13

### Changed

- Documented how to configure the IDA install path (`IDADIR`, the per-user
  `ida-config.json`, and `py-activate-idalib.py`), the WSL platform caveat, the
  `-V` verification output, and the writable-directory requirement for the
  first database.
- Clarified that the client process does not load IDA for database work, and
  removed `po*`/`pp*` from the command overview because they are not
  implemented.

### Fixed

- `idare2 -V` reported a configured IDA installation as "not importable": it
  imported `ida_kernwin` before `idapro` had initialised idalib. It now loads
  `idapro` first and prints the underlying import error when IDA really is
  unavailable.

## [0.1.1] - 2026-11-13

### Changed

- Clarified the minimum IDA version and documented the IDA Nexus plugin and
  idalib installation paths, including when idalib is actually required.
- Documented that `pip install ida-nexus` installs the Python library, while
  the IDA GUI plugin is registered through `ida-hcli`.
- Added minimum setup combinations for plugin-only, idalib-only, and both.
- Verified the minimal installation: `pip install idare2` plus a configured IDA
  install path is enough for headless idalib use. The PyPI `idapro` package is
  the real IDA Library module; the IDA-shipped wheel is optional.
- Documented IDA license acceptance and the install-path requirements for both
  `idat` and `idalib` workers.
- Added a troubleshooting section for the common IDA path, license, worker, and
  database-busy errors.
- Redrew the README badges as self-hosted SVGs and added
  `tools/update_badges.py`.

### Fixed

- Fixed the optional `rasm2` fallback using `-s` (syntax) instead of `-o`
  (address), which broke `pa`/`wa` on processors without an IDA assembler.

## [0.1.0] - 2026-11-13

### Added

- Initial public release.
- radare2-style interactive and batch CLI over IDA Pro databases through
  `ida-nexus`.
- Disassembly, memory, information, analysis, search, write, metadata, type,
  flag, and session commands, including radare2 operators such as `@`, `~`, `|`,
  `>`, and `@@`.
- JSON output via `-j` and command-level `j` suffixes.
- Raw-binary import hints for architecture, bitness, byte order, and load base.
- Attach/detach support for running IDA GUI sessions and managed idalib workers.
- Startup rc files, persistent command history, and tab completion.
- Optional `rasm2` fallback for processors without an IDA assembler.

### Packaging

- PEP 639 license metadata, a single-sourced version, and validated sdist/wheel
  builds.
- GitHub Actions CI across Python 3.11-3.14 and PyPI/TestPyPI Trusted
  Publishing workflows.

[Unreleased]: https://github.com/fire3/idare2/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/fire3/idare2/compare/v0.1.3...v0.2.0
[0.1.2]: https://github.com/fire3/idare2/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/fire3/idare2/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/fire3/idare2/releases/tag/v0.1.0
