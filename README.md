# idare2

`idare2` brings a radare2-style command line and output model to IDA Pro.
It drives an IDA database through [IDA Nexus](https://github.com/HexRaysSA/ida-nexus),
so analysis, disassembly, cross-references, types, strings, and decompilation come
directly from IDA and Hex-Rays.

Use it interactively or from scripts. When attached to a running IDA instance,
both clients share the same database.

## Requirements

- IDA Pro 9.1 or newer, including idalib
- Python 3.11 or newer

## Installation

Install the idalib Python bindings for your IDA installation:

```bash
pip install <IDA>/idalib/python/idapro*.whl
python <IDA>/py-activate-idalib.py -d <IDA>
```

Then install idare2:

```bash
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e '.[test]'
```

The `idare2` and `ir2` commands are available after activating the virtual
environment.

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

### Batch commands

Use `-q` to suppress the banner and `-c` to execute one or more commands:

```bash
idare2 -qc 's main; pd 10' firmware.bin
idare2 -q -c 'iI' -c 'axt' firmware.bin
idare2 -qc 'pd 20' firmware.bin | grep call
```

Multiple commands can be separated with `;`. A non-zero exit code is returned
if any batch command fails.

### JSON output

Use `-j` to make JSON-capable commands return JSON by default. Command-level
`j` suffixes are also supported:

```bash
idare2 -j -qc 'afl' firmware.bin
idare2 -qc 'aflj' firmware.bin
```

### Raw binaries

Specify the processor, bitness, and load address when importing a binary without
an ELF or PE header:

```bash
idare2 -a arm -b 32 -B 0x1000 firmware.bin
```

- `-a` is an IDA processor hint.
- `-b` must be `16`, `32`, or `64`.
- `-B` is the load base and must be non-negative and 16-byte aligned.

These options apply when a new IDB is created. When `-B` is set, it also becomes
the initial entry point; otherwise idare2 uses the first valid address.

### Existing databases and IDA GUI

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
| Disassembly | `pd` `pD` `pdf` `pdb` `pdr` `pi` `pdl` `pdq` `pdj` `pdc` |
| Assembly | `pa` `wa` `wa*` `wa+` `waf` `waF` |
| Memory | `px` `pxw` `pxq` `pxd` `pxu` `p8` `pr` `pc` `ps` `psw` `pv` `ph` `pwd` |
| Information | `i` `iI` `ij` `iS` `ii` `is` `iz` `ie` `iE` `iM` |
| Analysis | `aa` `aaa` `af` `afr` `afn` `afi` `afl` `afb` `afc` `afC` `ab` `axt` `axf` `axj` `agf` `agfj` `agfd` |
| Search | `/` `/x` `/v` `/r` `//` `/+` |
| Writing | `w` `wq` `wx` `wa` `w0` `wd` `wf` `wi[1248][+-][n]` `w6[d/e/x]` `wc` `wc+` `wc-` `u` `U` |
| Metadata | `C` `Cj` `C.` `CC` `CCr` `CCu` `CC.` `CC-` `C-` `Cd` `Cd.` |
| Types | `t` `tj` `t*` `ts` `tp` `tc` `tt` `t-` `td` `te` `dt` |
| Flags | `f` `f*` `f,` `f-` `f?` |
| Sessions | `S` `Ps` `Po` `P-` `Pj` `P` `y` `yy` `yx` `yt` `yf` `cc` `c1` |
| Other | `?` `b` `e` `q` `L` `_` |

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
- `wa*` and `waF*` print the equivalent `wx` command without modifying the
  database, so they work in read-only sessions.
- `agf` prints a compact ASCII function graph, `agfj`/`agj` return r2-shaped
  graph JSON, and `agfd` emits Graphviz DOT. `agg`/`aggd` are accepted aliases
  for the current function's DOT.

## Development

```bash
uv run pytest
uv run pytest -m real_ida
uv run pytest -m parity
uv run ruff check .
```

The test suite covers offline unit tests, real IDB integration, radare2 output
parity, and synthetic targets across 19 architectures.

## License

MIT
