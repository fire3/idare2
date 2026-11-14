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

## Quick start

```bash
# Once: teach idapro where IDA lives (skip this if HCLI installed IDA).
python <IDA>/idalib/python/py-activate-idalib.py -d <IDA>

# Install and check that the IDA binding loads.
pip install idare2
idare2 -V

# Inspect a binary, or open it interactively.
idare2 -q -c 'iI' ./sample
idare2 ./sample
```

## Requirements

- **IDA Pro 9.4 or newer**, with a valid IDA license. IDA is commercial software
  and is not bundled with idare2. IDA Nexus refuses to start on older kernels.
- **Python 3.11 or newer.**
- **A configured IDA installation.** `idapro` and IDA Nexus must find the IDA
  libraries (`libidalib.so` on Linux, `idalib.dll` on Windows), `idat`, and the
  processor modules. See [Configuring IDA](#configuring-ida).
- **Optional:** the IDA Nexus plugin for GUI attachment and `idat` headless
  workers, a Hex-Rays decompiler license for decompilation commands, and
  radare2's `rasm2` for the `pa`/`wa` assembler fallback.

Tested with IDA Pro 9.5, `ida-nexus` 0.14.2 / `ida-domain` 0.6.0, `idapro`
0.0.12, and Python 3.11-3.14. `pyproject.toml` requires `ida-nexus>=0.13,<1`;
the exact versions pip installs depend on what is available at install time.

`idare2` is a pure-Python CLI. The client process does not need IDA for
database work: commands run inside an IDA Nexus worker (or the IDA GUI), and
only that worker imports the `ida_*` modules. `pip install idare2` installs the
Python side, including the official `idapro` IDA Library module; it does not
install IDA or the IDA Nexus plugin.

### Configuring IDA

`idapro` resolves the IDA installation from, in order:

1. the `IDADIR` environment variable;
2. the `ida-install-dir` entry in IDA's user configuration file:
   - Linux and macOS: `~/.idapro/ida-config.json`
   - Windows: `%APPDATA%\Hex-Rays\IDA Pro\ida-config.json`
   - `IDAUSR` moves that directory; only its first entry is used.

To configure it:

1. Install IDA Pro 9.4+ and start the GUI once so the license is accepted.
   Headless idalib refuses to run before that.
2. Make the install path discoverable. An HCLI-installed IDA does this
   automatically; otherwise run the activation script once:

   ```bash
   python <IDA>/idalib/python/py-activate-idalib.py -d <IDA>
   ```

   Or set the path for the current shell instead:

   ```bash
   export IDADIR=<IDA>        # bash / zsh
   set IDADIR=<IDA>           # cmd.exe
   $env:IDADIR = "<IDA>"      # PowerShell
   ```

3. Check that the binding loads:

   ```bash
   python -c "import idapro, ida_kernwin; print(ida_kernwin.get_kernel_version())"
   ```

   This must print your IDA version, for example `9.5`. The configuration is
   per user, not per virtual environment, so every environment that installs
   `idare2` can use it.

> **WSL note:** idalib is a native library. A Windows IDA installation cannot be
> loaded by Linux Python under WSL, and a Linux IDA installation cannot be
> loaded by Windows Python. Install IDA for the same platform as the Python
> interpreter, or run idare2 on the other side.

### Does idare2 require idalib?

Not necessarily. IDA Nexus can use three backends:

| How the database is reached | Backend | Requires idalib? |
|---|---|---|
| Attach to a database already open in the IDA GUI (plugin required) | `gui` | No |
| Open a file or IDB headlessly with the IDA Nexus plugin installed | `idat` | No |
| Open a file or IDB headlessly without the plugin, or with `IDA_NEXUS_IDALIB_ONLY=1` | `idalib` | Yes |

With no plugin, IDA Nexus opens a headless idalib worker in idare2's Python
environment. That path uses the `idapro` module installed by `pip install
idare2`; you do not have to install the `idapro*.whl` that ships with IDA. If you
want to pin the exact binding version from your IDA installation, you can
install that wheel instead (see [Optional: pin the IDA-shipped idapro
wheel](#optional-pin-the-ida-shipped-idapro-wheel)).

### Minimum setups

- **No plugin, headless only:** `pip install idare2` plus a configured IDA
  install path. This is the smallest setup, but it cannot attach to an IDA GUI.
- **Plugin, no idalib:** `pip install idare2` plus the IDA Nexus plugin. This
  supports GUI attach and headless `idat` workers.
- **Both:** the plugin is preferred; idalib remains the fallback.

Without the plugin, the Python side installed by `pip install idare2` is enough
for `idare2 -v`, `idare2 -V`, and `idare2 -L`, and for attaching to a GUI that
already has the plugin. Opening a database headlessly additionally needs the
plugin (`idat`) or a configured idalib.

## Installation

The shortest headless setup is: install IDA 9.4+, start it once to accept the
license, run `py-activate-idalib.py -d <IDA>`, then `pip install idare2`. The
plugin is optional and is only needed for GUI attachment or `idat` workers.

### 1. Prepare IDA

Install IDA Pro 9.4+, start it once to accept the license, and configure the
install path. See [Configuring IDA](#configuring-ida) for both steps. This path
is also what lets IDA Nexus find `idat` when the plugin is installed.

### 2. Install idare2

```bash
python -m venv .venv
source .venv/bin/activate
pip install idare2
```

`pip install idare2` installs `ida-nexus`, `ida-domain`, and the official
`idapro` IDA Library module from PyPI. The `idare2` and `ir2` commands are
available after activating the environment.

### 3. Optional: install the IDA Nexus plugin

The plugin enables GUI database sharing and makes headless workers run as
`idat` inside IDA's own Python:

```bash
uvx ida-hcli plugin install https://github.com/HexRaysSA/ida-nexus
```

`uvx` comes with [uv](https://docs.astral.sh/uv/). Without uv:

```bash
python -m pip install ida-hcli
ida-hcli plugin install https://github.com/HexRaysSA/ida-nexus
```

Start or restart IDA after installing the plugin.

### Optional: pin the IDA-shipped idapro wheel

The PyPI `idapro` module is the real IDA Library Python module and works with a
configured IDA installation. If your IDA ships a different `idapro*.whl` and you
want that exact build, install it into the same environment:

```bash
pip install <IDA>/idalib/python/idapro*.whl
```

### Verify the installation

```bash
idare2 -v     # idare2 version only
idare2 -V     # idare2, ida-nexus, ida-domain, Python, and IDA versions
idare2 -L     # databases currently registered with IDA Nexus
```

`-V` is the diagnostic form. With a configured IDA installation the last line
reports the IDA kernel version:

```text
idare2      0.1.2
ida-nexus   0.13.4
ida-domain  0.5.1
python      3.14.6
ida         9.5
```

If the `ida` line says `(not importable: ...)`, the parenthesised text explains
why. See [The `ida` line is not importable](#the-ida-line-is-not-importable).
`-h`, `-v`, `-V`, and `-L` do not need a database. `-V` does try to load
idalib, which makes it the quickest end-to-end check of the IDA configuration.

An empty `idare2 -L` list is normal before you open a database in IDA or pass a
file to idare2.

Try a read-only command against a local executable:

```bash
cp /bin/ls /tmp/ls-sample
idare2 -q -c 'iI' /tmp/ls-sample
```

IDA writes the IDB next to the input file, so that directory must be writable.
Use an existing IDB with `--idb`, or copy the sample somewhere writable first.

### From source

```bash
git clone https://github.com/fire3/idare2.git
cd idare2
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e '.[test]'

# Configure IDA once if you have not already.
python <IDA>/idalib/python/py-activate-idalib.py -d <IDA>
# or: export IDADIR=<IDA>
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
configurations covering every supported processor, including both byte
orders.

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

When a writable batch ends, the changes are discarded unless the session asked
to keep them — an explicit `w`/`wq`, or `--save-on-close` on the command line
(`--no-save-on-close` forces the discard). A read-only session never writes
the database, whatever it runs.

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
| Memory | `px` `pxw` `pxq` `pxd` `pxu` `p8` `p8j` `p8s` `p8,` `p8d` `p8x` `p8*` `p8b` `p8f` `pr` `pc` `p6` `pj` `p=d` `pt` `pu` `pf` `pfj` `pfs` `ps` `psw` `psz` `psp` `psW` `psu` `psx` `psn` `pv` `pvu` `pvd` `pvp` `pvj` `ph` `pwd` `x` `x8` `xw` `xq` `xj` `pFa` `pFo` `pFp` `pFx` `pFaj` `pFxj` |
| Information | `i` `iI` `ij` `it` `itj` `iD` `ia` `iaj` `il` `ilj` `ilq` `iS` `iSj` `iSS` `iS.` `iSh` `iSm` `ii` `is` `iz` `izz` `izzj` `ir` `ih` `iH` `ie` `iee` `ies` `iE` `iM` `iC` `iV` `iv` `iT` `ig` `ic` `icj` `icq` `icl` `ics` `ic*` `CL` `CLu` `CLf` `CLL` |
| Analysis | `aa` `aaa` `af` `aF` `afr` `afn` `afu` `afi` `afl` `aflj` `aflq` `afb` `afc` `afC` `afv` `afvj` `afvR` `afvW` `afx` `afxj` `ao` `aoj` `ab` `axt` `axf` `axj` `aflc` `afln` `afl+` `a8` `ad` `adk` `ah` `an` `agf` `agfj` `agfd` |
| Search | `/` `/x` `/v` `/r` `/w` `/wi` `/a` `/p` `//` `/+` |
| Writing | `w` `wq` `wx` `wa` `w0` `wd` `wf` `wi[1248][+-][n]` `w6[d/e/x]` `wc` `wc+` `wc-` `u` `U` |
| Metadata | `C` `Cj` `C*` `C.` `CC` `CCr` `CCu` `CC*` `CC.` `CC-` `CCa` `CCa-` `C-` `Cd` `Cd.` `Cf` `Cf-` `Ch` `Ch-` `Cs` `Cs.` `Cs.j` `Cs-` `Cs*` |
| Types | `t` `tj` `t*` `ts` `tu` `tp` `tpv` `tpx` `tc` `td` `tt` `tt-` `t-` `te` `tf` `tfj` `tfc` `tn` `tn-` `to` `dt` |
| Flags | `f` `f*` `f,` `f-` `f?` `fq` `fn` `fnj` `fN` `fr` `fx` |
| Sessions | `S` `Ps` `Po` `P-` `Pj` `P` `y` `yy` `yx` `yt` `yf` `cc` `c1` |
| Other | `?` `b` `e` `q` `L` `_` `%` `T` `*` |

Most information commands support a `j` suffix for JSON output.

### Unsupported commands

Every radare2 command below fails explicitly (with the reason in the error)
instead of falling back to a different command. The groups follow the shape of
r2 6.2.6.

| Group | Commands | Why |
|---|---|---|
| Debugger | `d*` (`db dc ds dr dx dp dm do` …) | No debug backend; IDA's debugger is not reachable through ida-nexus. |
| File I/O | `o*` (`open`), `r*` (resize) | Single-database model: one database per session, opened on the command line. |
| Visual mode | `V`, `v`, `v.`, `ve`, `vi` | Terminal UI is a radare2 feature; idare2 is line-based. |
| Generators | `g*` (r_egg), `py` (rlang) | Shellcode generation and embedded scripting are radare2 features. |
| Zignatures | `z*` | Use IDA's own signature/FLIRT machinery instead. |
| Key-value store | `k*` (sdb) | r2's internal sdb has no IDA counterpart. |
| Magic / fs | `m*`, `pm` | `libmagic` and r2's filesystem layer are not wired up. |
| ESIL | `ae` | No emulator in the IDA path (`asm.emu` is accepted but inert). |
| Remote / infra | `=`, `:`, `(`, `,`, `{`, `#`, `<`, `-` | Remote control, macros, tables and hashbangs are radare2 plumbing. |
| C-metadata extras | `CF`, `CS`, `Cb`, `Cm`, `Cr`, `Ct`, `Cv`, `CC!` | Magic/signature/spaces metadata has no IDA storage; comments and data definitions (`C`, `CC*`, `CCa`, `Cd`, `Cf`, `Ch`, `Cs`) are supported. |
| Bin extras | `ib`, `iL`, `iO`, `ik`, `im`, `io`, `iu`, `iw`, `ix` | rbin-plugin options and per-bin key/value stores; DWARF source lines live under `CL`. |
| Print variants | `p-`, `pB`, `pF`, `pK`, `pb`, `pg`, `pk`, `pl`, `pmd`, `pq`, `pz` | Radar/zoom/ASN.1/QR renderings without an IDA equivalent. |
| Analysis extras | `ac` (editing), `aL`, `aj`, `ap`, `ar`, `as`, `av`, `bf`, `bg`, `bm` | Class editing needs write support (read-only `ic` exists); registers and plugins are debug/r2-side concepts. |
| Text log | `TT`, `TV` | `T` itself is supported; the tail/view variants are not. |

## Behavior notes

- IDA performs analysis when the database is opened, so `aa` is usually a no-op.
- `asm.arch` and `asm.bits` are read-only. Set the architecture when creating a
  database with `-a` and `-b`.
- `e asm.syntax` switches the immediate style of the disassembly output:
  `intel` (the default) prints r2's `0x11`, `masm` keeps IDA's native `11h`.
  `pa`/`wa`/`/a` accept either spelling and convert per assembler.
- `ie` reads the ELF entry point like r2; the IDA entry list (including
  `.init_proc`/`.term_proc`) stays available through `ies` and `iE`.
- `Cf` maps a pf format string to IDA data items (`Cf 16 [4]d`) and stores
  the format as a repeatable comment; `Cf-` undefines the span. Unions and
  nested struct formats are rejected.
- `pFa/pFo/pFp/pFx` decode ASN.1/DER, OIDs, PKCS#7 and X.509 with a strict
  client-side DER parser (see `pF?`); `j` suffixes emit JSON trees.
- `aflj` carries r2's graph statistics (`edges`, `cc`, `maxbbins`...);
  `nlocals` lives in `afij` only, because a Hex-Rays query per function
  triples the run of the table form.
- The `C` listing shows regular *and* repeatable comments; repeatable ones
  used to be set-but-invisible.
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

The IDA-backed suites use the `idapro` module installed by the project
dependencies. Configure IDA's install path as described in Installation, then:

```bash
uv run --no-sync pytest -m real_ida
uv run --no-sync pytest -m parity
uv run --no-sync pytest -m arch_matrix   # raw-binary import/disassembly matrix
uv run --no-sync tools/arch_matrix.py    # the same, one row per CPU
```

`--no-sync` keeps `uv` from re-resolving `.venv` between commands. It is
required if you pinned a specific IDA-shipped `idapro*.whl`; otherwise plain
`uv run ...` also works.

Before releasing (and after touching command dispatch or registration), run
the command-surface probe and archive its JSON locally:

```bash
python tools/cmdsurface.py --target /path/to/sample --json /tmp/cmdsurface.json
```

The 2026-11-14 baseline is 60% supported (310/510 tokens, r2 6.2.6); treat a
drop of more than ~3 points as a regression worth a CHANGELOG entry. The
parity suite runs locally only (`pytest -m parity`); CI stays offline-only
because it would need an IDA license.

Build the distribution archives and validate the PyPI metadata with:

```bash
uv build
uv run twine check dist/*
```

The test suite covers offline unit tests, real IDB integration, radare2 output
parity, and the architecture matrix in `tests/integration/test_arch_matrix.py`
(22 configurations covering every supported processor, including both byte
orders).

## Troubleshooting

### `Cannot load IDA library file libidalib.so` (or `idalib.dll`)

`idapro` cannot find your IDA installation. Run the activation script once:

```bash
python <IDA>/idalib/python/py-activate-idalib.py -d <IDA>
```

or set `IDADIR=<IDA>`.

### The `ida` line is not importable

`idare2 -V` reports `ida (not importable: ...)` when the current Python
interpreter cannot load the IDA Library module. The text after the colon is the
underlying error:

- `Cannot load IDA library file libidalib.so` (or `idalib.dll`): the install
  path is not configured. Run the activation script or set `IDADIR` as
  described in [Configuring IDA](#configuring-ida).
- `No module named 'idapro'`: the `idapro` package is missing from this
  environment. Reinstall with `pip install idare2`.
- Any other message: make sure `idare2 -V` runs in the same Python environment
  where you installed idare2.

Attaching to an IDA GUI that already has the plugin does not need idalib, but
headless idalib workers do.

### `The ida-nexus plugin is installed but idat was not found`

The plugin is present, but IDA Nexus still cannot locate `idat`. Configure the
IDA install path as above, or set `IDA_NEXUS_IDALIB_ONLY=1` to use idalib.

### `License not yet accepted, cannot run in batch mode`

Start the IDA GUI once and accept the license. Headless idalib workers reuse
that acceptance state.

### `WorkerStartError: idalib worker ... exited with status 1`

Check the install path and license first. To rule out the plugin path, run with
`IDA_NEXUS_IDALIB_ONLY=1`. If the worker log says `Failed to open database`, the
directory containing the input file may not be writable: IDA writes the IDB
next to the input. Copy the file to a writable directory or use an existing IDB
with `--idb`.

### `DatabaseBusyError: an unregistered IDA session owns ...`

Another IDA or idare2 worker owns the database. Use `idare2 -L` to list
registered instances, close the owner, or work on a copy.

## Releasing

See [RELEASING.md](https://github.com/fire3/idare2/blob/main/RELEASING.md) for
the version-bump checklist, TestPyPI dry run, and PyPI Trusted Publishing setup.
Release notes live in [CHANGELOG.md](https://github.com/fire3/idare2/blob/main/CHANGELOG.md).

## License

MIT. See [LICENSE](https://github.com/fire3/idare2/blob/main/LICENSE).
