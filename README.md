# idare2

[![PyPI](https://raw.githubusercontent.com/fire3/idare2/main/assets/badges/pypi.svg)](https://pypi.org/project/idare2/)
[![Python versions](https://raw.githubusercontent.com/fire3/idare2/main/assets/badges/python.svg)](https://pypi.org/project/idare2/)
[![CI](https://github.com/fire3/idare2/actions/workflows/ci.yml/badge.svg)](https://github.com/fire3/idare2/actions/workflows/ci.yml)
[![License: MIT](https://raw.githubusercontent.com/fire3/idare2/main/assets/badges/license.svg)](https://github.com/fire3/idare2/blob/main/LICENSE)

`idare2` brings a radare2-style command line and output model to IDA Pro.
It drives an IDA database through [IDA Nexus](https://github.com/HexRaysSA/ida-nexus),
so analysis, disassembly, cross-references, types, strings, and decompilation come
directly from IDA and Hex-Rays.

Use it interactively or from scripts. When attached to a running IDA instance,
both clients share the same database.

> **Status:** alpha. The command surface is broad, but interfaces may change
> before 1.0.

## Requirements

- **IDA Pro 9.4 or newer**, with a valid IDA license. IDA is commercial software
  and is not bundled with idare2. The current `ida-nexus` runtime rejects older
  kernels.
- **Python 3.11 or newer.**
- **A way for IDA Nexus to reach an IDA database:** either the IDA Nexus plugin
  (recommended) or IDA's idalib bindings.

`idare2` is a pure-Python CLI. It depends on `ida-nexus` and does not import
`ida_*` modules itself. `pip install idare2` does not install IDA, the IDA Nexus
plugin, or idalib; those come from your IDA installation.

`pip install ida-nexus` installs the Python library and its `ida-nexus` command,
but it does **not** register the IDA GUI plugin. The plugin needs the
`ida-hcli` installer described below. `idare2` already depends on `ida-nexus`,
so `pip install idare2` pulls the library in automatically.

### Does idare2 require idalib?

Not necessarily. IDA Nexus can use three backends:

| How the database is reached | Backend | Requires idalib? |
|---|---|---|
| Attach to a database already open in the IDA GUI (plugin required) | `gui` | No |
| Open a file or IDB headlessly with the IDA Nexus plugin installed | `idat` | No |
| Open a file or IDB headlessly without the plugin, or with `IDA_NEXUS_IDALIB_ONLY=1` | `idalib` | Yes |

So idalib is the fallback for headless workers when the IDA Nexus plugin is not
installed. If you install the plugin, you do not need idalib in idare2's Python
environment.

### Minimum setups

- **No plugin, headless only:** install idare2 and IDA's idalib bindings in the
  same environment. This is the smallest setup, but it cannot attach to an IDA
  GUI.
- **Plugin, no idalib:** install idare2 and the IDA Nexus plugin. This supports
  GUI attach and headless `idat` workers.
- **Both:** the plugin is preferred; idalib remains the fallback.

Installing only the `ida-nexus` Python library is enough for `idare2 -v`,
`idare2 -L`, and attaching to a GUI that already has the plugin, but it is not
enough to open a database headlessly on its own.

## Installation

### Recommended: install the IDA Nexus plugin

Install the plugin into IDA so GUI databases can be shared and headless workers
run in IDA's own Python:

```bash
uvx ida-hcli plugin install https://github.com/HexRaysSA/ida-nexus
```

`uvx` comes with [uv](https://docs.astral.sh/uv/). Without uv:

```bash
python -m pip install ida-hcli
ida-hcli plugin install https://github.com/HexRaysSA/ida-nexus
```

Start or restart IDA after installing the plugin.

Then install idare2 in a Python 3.11+ virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install idare2
```

The `idare2` and `ir2` commands are available after activating the environment.

### Alternative: idalib fallback

If you cannot install the IDA Nexus plugin, install IDA's idalib bindings into
the **same** Python environment as idare2:

```bash
python -m venv .venv
source .venv/bin/activate

# Install IDA's idalib bindings first.
pip install <IDA>/idalib/python/idapro*.whl
python <IDA>/py-activate-idalib.py -d <IDA>

# Then install idare2.
pip install idare2
```

Set `IDA_NEXUS_IDALIB_ONLY=1` if you want to force this backend and prevent
IDA Nexus from starting `idat` or `ida` workers. The `idapro` distribution on
PyPI is a typing/stub package; the real idalib bindings are the wheel shipped
with IDA.

### Verify the installation

```bash
idare2 -v
idare2 -L
```

`idare2 -h` and `idare2 -v` work without an IDA license. `idare2 -L` lists
databases currently registered with IDA Nexus, including their backend, and an
empty list is normal before you open a database in IDA or pass a file to
idare2.

### From source

```bash
git clone https://github.com/fire3/idare2.git
cd idare2
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e '.[test]'

# If you use the idalib fallback, install it into this same environment.
uv pip install <IDA>/idalib/python/idapro*.whl
python <IDA>/py-activate-idalib.py -d <IDA>
```

## Usage

### Interactive mode

Open an executable, a raw binary, or an existing IDB:

```bash
idare2 firmware.bin
idare2 --idb saved.i64
```

Commands use radare2 syntax:

```text
[0x00015e10]> s main
[0x00015e10]> pd 6
[0x00015e10]> afl~main
[0x00015e10]> q
```

Use `?` for command help and `q` to exit. Use `wq` to save the IDB and exit.
Tab completion covers command names, `e` configuration keys, flags, function
names, and `$` variables/aliases; remote names are cached per editing cycle.
Command history is kept in `${XDG_STATE_HOME:-~/.local/state}/idare2/history`.

### Startup files

At startup idare2 reads, in order:

1. `~/.idare2rc`
2. `${XDG_CONFIG_HOME:-~/.config}/idare2/rc`
3. `${XDG_CONFIG_HOME:-~/.config}/idare2/rc.d/*` (sorted)
4. the nearest `.idare2rc` in the current directory or an ancestor

Set `IDARE2_RCFILE` to use a single alternate file instead. Pass `-N` (or
`-NN`) to skip rc loading entirely.

### Batch commands

Use `-q` to suppress the banner and `-c` to execute one or more commands:

```bash
idare2 -qc 's main; pd 10' firmware.bin
idare2 -q -c 'iI' -c 'axt' firmware.bin
idare2 -qc 'pd 20' firmware.bin | grep call
```

Multiple commands can be separated with `;`. A non-zero exit code is returned
if any batch command fails.

Scripts passed with `-I` run before `-i` scripts and `-c` commands; `-i`
scripts run after the database is open and before `-c` commands.

### JSON output

Use `-j` to make JSON-capable commands return JSON by default. Command-level
`j` suffixes are also supported:

```bash
idare2 -j -qc 'afl' firmware.bin
idare2 -qc 'aflj' firmware.bin
```

### Raw binaries

Specify the processor, bitness, byte order, and load address when importing a
binary without an ELF or PE header:

```bash
idare2 -a arm -b 32 -B 0x1000 firmware.bin
idare2 -a mipsb -b 32 --endian big -B 0x1000 firmware.bin
```

- `-a` is an IDA processor name, for example `metapc`, `arm:ARMv7`,
  `arm:ARMv8`, `armb`, `mipsl`, `mipsb`, `ppc`, `riscv`, `s390x`, `68000`,
  `sparcb`, or `sh4`.
- `-b` must be `16`, `32`, or `64`.
- `--endian big|little` overrides the byte order the raw loader would pick for
  that processor.
- `-B` is the load base and must be non-negative and 16-byte aligned.

These options apply when a new IDB is created. When `-B` is set, it also becomes
the initial entry point; otherwise idare2 uses the first valid address.
`tests/integration/test_arch_matrix.py` exercises these hints on 22
configurations (the 19 supported machines, including both byte orders).

### Existing databases and IDA GUI

Sharing a database that is already open in the IDA GUI requires the IDA Nexus
plugin. The idalib fallback can open files and IDBs by path, but it cannot
attach to a GUI session.

List active databases, open an IDB directly, or attach to a running session:

```bash
idare2 -L
idare2 --idb saved.i64 -qc 'afl~main'
idare2 --attach <session-id> -qc 'axt'
```

Session IDs are shown by `idare2 -L`.

### Writing changes

Sessions are read-only by default. Pass `-w` to allow writes:

```bash
idare2 -w -qc 's main; wx 9090; w' firmware.bin
idare2 -w -qc 'e io.cache=true; wx 90 @ main; wc+' firmware.bin
```

`w` saves the IDB. With `e io.cache=true`, writes are buffered until `wc+` is
used.

### Command language

Common radare2 operators are supported, including `@`, `~`, `|`, `>`, `>>`,
`!`, `.`, repeat prefixes such as `3pd`, and bare addresses for seeking.
`@@` iterates a command over addresses; `@@@` also sets the block size for each
item, including explicit `@@@= addr size ...` pairs.

```bash
idare2 -qc 'pd 8 @ main' firmware.bin
idare2 -qc 'afl~main' firmware.bin
idare2 -qc 'axt > refs.txt' firmware.bin
```

## Command overview

| Area | Commands |
|---|---|
| Seeking | `s` `s+` `s-` `sf` `sF` `sb` `sn` `so` `sp` `s=` `s:` `s*` |
| Disassembly | `pd` `pd -N` `pd--` `pD` `pdf` `pdb` `pdk` `pdr` `pi` `pdi` `pdl` `pdq` `pdj` `pdC` `pdJ` `pd,` `pdc` `pC` `pA` |
| Assembly | `pa` `wa` `wa*` `wa+` `waf` `waF` |
| Memory | `px` `pxw` `pxq` `pxd` `pxu` `p8` `p8j` `p8s` `p8,` `p8d` `p8x` `p8*` `p8b` `p8f` `pr` `pc` `p6` `pj` `p=` `pt` `pu` `pf` `pfj` `pfs` `ps` `psw` `psz` `psp` `psW` `psu` `psx` `psn` `pv` `pvu` `pvd` `pvp` `pvj` `pp*` `po*` `ph` `pwd` `x` `x8` `xw` `xq` `xj` |
| Information | `i` `iI` `ij` `it` `itj` `iD` `ia` `iaj` `il` `ilj` `ilq` `iS` `iSj` `iSS` `iS.` `iSh` `iSm` `ii` `is` `iz` `izz` `izzj` `ir` `ih` `iH` `ie` `iee` `ies` `iE` `iM` `iC` `iV` `iv` `iT` `ig` `ic` `icj` `icq` `icl` `ics` `ic*` `CL` `CLu` `CLf` `CLL` |
| Analysis | `aa` `aaa` `af` `aF` `afr` `afn` `afu` `afi` `afl` `aflj` `aflq` `afb` `afc` `afC` `afv` `afvj` `afvR` `afvW` `afx` `afxj` `ao` `aoj` `ab` `axt` `axf` `axj` `aflc` `afln` `afl+` `a8` `ad` `adk` `ah` `an` `agf` `agfj` `agfd` |
| Search | `/` `/x` `/v` `/r` `/w` `/wi` `/a` `/p` `//` `/+` |
| Writing | `w` `wq` `wx` `wa` `w0` `wd` `wf` `wi[1248][+-][n]` `w6[d/e/x]` `wc` `wc+` `wc-` `u` `U` |
| Metadata | `C` `Cj` `C*` `C.` `CC` `CCr` `CCu` `CC*` `CC.` `CC-` `C-` `Cd` `Cd.` `Ch` `Ch-` `Cs` `Cs.` `Cs.j` `Cs-` `Cs*` |
| Types | `t` `tj` `t*` `ts` `tu` `tp` `tpv` `tpx` `tc` `td` `tt` `tt-` `t-` `te` `tf` `tfj` `tfc` `tn` `tn-` `to` `dt` |
| Flags | `f` `f*` `f,` `f-` `f?` `fq` `fn` `fnj` `fN` `fr` `fx` |
| Sessions | `S` `Ps` `Po` `P-` `Pj` `P` `y` `yy` `yx` `yt` `yf` `cc` `c1` |
| Other | `?` `b` `e` `q` `L` `_` `%` `T` `*` |

Most information commands support a `j` suffix for JSON output.

## Behavior notes

- IDA performs analysis when the database is opened, so `aa` is usually a no-op.
- `asm.arch` and `asm.bits` are read-only. Set the architecture when creating a
  database with `-a` and `-b`.
- Sessions are read-only unless `-w` is passed.
- `w` with no arguments saves the IDB.
- `-j` enables JSON output; it does not start a JavaScript engine as it does in
  radare2.
- Flag names are written to the IDB by default. Set
  `e ida.flags.write=false` to keep them session-local.
- Unsupported commands fail explicitly instead of falling back to a different
  command.
- `pa` assembles an instruction to hexpairs; `wa` assembles and writes it. IDA's
  assembler is used first. When the processor module has no assembler, idare2
  falls back to radare2's `rasm2` if it is on `PATH` (or `IDARE2_RASM2` points
  to it), which covers common ARM, AArch64, MIPS, PPC, RISC-V and m68k targets.
- `pf` supports r2's scalar formats, inline `[n]` arrays, offset controls and
  session-local named formats; unsupported format characters fail explicitly.
- `wa*` and `waF*` print the equivalent `wx` command without modifying the
  database, so they work in read-only sessions.
- `agf` prints a compact ASCII function graph, `agfj`/`agj` return r2-shaped
  graph JSON, and `agfd` emits Graphviz DOT. `agg`/`aggd` are accepted aliases
  for the current function's DOT.
- `pd -N` disassembles backwards and `pd-- N` prints context (N before and N from the current address). `pdk` disassembles every method of the class at the seek. The `pxw`/`pxq`/`pxd`/`pxu` argument is a byte count, defaulting to the block size, and their row layout matches r2. `aflc`, `afln` and `afl+` count functions, print rename commands and sum sizes.
- `iS` lists ELF sections (an algorithm name adds a hash column), `iSS` lists
  program-header memory maps, and `izz` scans the whole input file, including
  non-loaded debug sections. `CL*` exposes the DWARF source-line data IDA
  imported; `ic` reconstructs classes from IDA's UDTs and C++ symbols.
- Command prefixes validate their suffixes: an unknown `pd`/`i`/`b`/... suffix
  is a usage error instead of silently running the base command.

## Development

The default test suite is offline and does not need IDA:

```bash
uv sync --group dev
uv run pytest
uv run ruff check .
```

`uv sync` and `uv run` manage `.venv` exactly, so they can replace the
`idapro` package that IDA's idalib wheel provides. For the IDA-backed suites,
install idalib after syncing and disable the implicit sync:

```bash
uv pip install <IDA>/idalib/python/idapro*.whl
python <IDA>/py-activate-idalib.py -d <IDA>

uv run --no-sync pytest -m real_ida
uv run --no-sync pytest -m parity
uv run --no-sync pytest -m arch_matrix   # raw-binary import/disassembly matrix
uv run --no-sync tools/arch_matrix.py    # the same, one row per CPU
```

Build the distribution archives and validate the PyPI metadata with:

```bash
uv build
uv run twine check dist/*
```

The test suite covers offline unit tests, real IDB integration, radare2 output
parity, and the architecture matrix in `tests/integration/test_arch_matrix.py`
(22 configurations covering the 19 supported machines).

## Releasing

See [RELEASING.md](https://github.com/fire3/idare2/blob/main/RELEASING.md) for
the version-bump checklist, TestPyPI dry run, and PyPI Trusted Publishing setup.
Release notes live in [CHANGELOG.md](https://github.com/fire3/idare2/blob/main/CHANGELOG.md).

## License

MIT. See [LICENSE](https://github.com/fire3/idare2/blob/main/LICENSE).
