# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Output-format alignment with radare2 6.2.6, from the CLI-difference
re-evaluation of 2026-11-14 (`docs/r2-parity-report.md` §15).

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

[Unreleased]: https://github.com/fire3/idare2/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/fire3/idare2/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/fire3/idare2/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/fire3/idare2/releases/tag/v0.1.0
