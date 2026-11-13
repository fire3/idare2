# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Clarified the minimum IDA version and documented the IDA Nexus plugin and
  idalib installation paths, including when idalib is actually required.
- Documented that `pip install ida-nexus` installs the Python library, while
  the IDA GUI plugin is registered through `ida-hcli`.
- Added minimum setup combinations for plugin-only, idalib-only, and both.

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
- Optional `pasm2` fallback for processors without an IDA assembler.

### Packaging

- PEP 639 license metadata, a single-sourced version, and validated sdist/wheel
  builds.
- GitHub Actions CI across Python 3.11-3.14 and PyPI/TestPyPI Trusted
  Publishing workflows.

[Unreleased]: https://github.com/fire3/idare2/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/fire3/idare2/releases/tag/v0.1.0
