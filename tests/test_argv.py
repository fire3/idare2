"""CLI argument parsing, including the three-tier flag policy."""

from __future__ import annotations

import pytest

from idare2 import argv, cli
from idare2.errors import UsageError


def test_empty() -> None:
    options = argv.parse([])
    assert options.file is None
    assert options.readonly is True


def test_file_and_commands() -> None:
    options = argv.parse(["firmware.bin", "-c", "pd 10", "-c", "px 16"])
    assert options.file == "firmware.bin"
    assert options.commands == ["pd 10", "px 16"]


def test_clustered_short_flags() -> None:
    # `-qc 'pd 10'` must behave exactly like `-q -c 'pd 10'`.
    options = argv.parse(["-qc", "pd 10", "firmware.bin"])
    assert options.quiet == 1
    assert options.commands == ["pd 10"]


def test_doubled_flags() -> None:
    assert argv.parse(["-qq"]).quiet == 2
    assert argv.parse(["-AA"]).analyze == 2
    assert argv.parse(["-NN"]).skip_rc == 2


def test_single_flags() -> None:
    options = argv.parse(["-A", "-N", "-q", "-w", "-j"])
    assert (options.analyze, options.skip_rc, options.quiet) == (1, 1, 1)
    assert options.readonly is False
    assert options.json is True


def test_eval_flag() -> None:
    options = argv.parse(["-e", "scr.color=0", "-e", "ida.timeout=5"])
    assert options.evals == [("scr.color", "0"), ("ida.timeout", "5")]


def test_eval_requires_a_value() -> None:
    with pytest.raises(UsageError, match="key=value"):
        argv.parse(["-e", "scr.color"])


def test_import_hints() -> None:
    options = argv.parse(["-a", "arm", "-b", "32", "-B", "0x8000"])
    assert (options.arch, options.bits, options.base) == ("arm", "32", "0x8000")


def test_import_hints_become_typed_target_fields() -> None:
    target = cli._target_from(
        argv.parse(["-a", "arm", "-b", "32", "-B", "0x8000", "firmware.bin"])
    )
    assert (target.processor, target.bits, target.image_base) == ("arm", 32, 0x8000)


@pytest.mark.parametrize("bits", ["0", "24", "128", "not-a-number"])
def test_invalid_bitness_is_a_usage_error(bits: str) -> None:
    with pytest.raises(UsageError, match="bit width|-b must be"):
        cli._target_from(argv.parse(["-b", bits, "firmware.bin"]))


@pytest.mark.parametrize(("base", "message"), [("0x1001", "16-byte aligned"), ("-16", "non-negative")])
def test_invalid_load_base_is_a_usage_error(base: str, message: str) -> None:
    with pytest.raises(UsageError, match=message):
        cli._target_from(argv.parse(["-B", base, "firmware.bin"]))


def test_m_is_an_alias_for_base() -> None:
    assert argv.parse(["-m", "0x400000"]).base == "0x400000"


def test_long_options() -> None:
    options = argv.parse(
        [
            "--attach",
            "12345-abcdef",
            "--no-spawn",
            "--linger",
            "60",
            "--timeout=15",
        ]
    )
    assert options.attach == "12345-abcdef"
    assert options.spawn is False
    assert options.linger == 60.0
    assert options.timeout == 15.0


def test_ignored_flags_are_collected_not_rejected() -> None:
    options = argv.parse(["-T", "-u"])
    flags = [flag for flag, _ in options.ignored]
    assert "-T" in flags
    assert "-u" in flags


@pytest.mark.parametrize("flag", ["-d", "-D", "-r", "-R", "-x", "-X", "-P"])
def test_rejected_flags_fail_loudly(flag: str) -> None:
    with pytest.raises(UsageError, match="not supported by idare2"):
        argv.parse([flag])


def test_end_of_options() -> None:
    options = argv.parse(["--", "-weird-name.bin"])
    assert options.file == "-weird-name.bin"


def test_two_files_is_an_error() -> None:
    with pytest.raises(UsageError, match="only one file"):
        argv.parse(["a.bin", "b.bin"])


def test_unknown_option() -> None:
    with pytest.raises(UsageError, match="unknown option"):
        argv.parse(["-Z"])
    with pytest.raises(UsageError, match="unknown option"):
        argv.parse(["--nope"])


def test_backend_validation() -> None:
    with pytest.raises(UsageError, match="--backend must be"):
        argv.parse(["--backend", "bogus"])


def test_help_and_version_do_not_need_a_database() -> None:
    assert argv.parse(["-h"]).wants_database is False
    assert argv.parse(["-v"]).wants_database is False
    assert argv.parse(["-L"]).wants_database is False
    assert argv.parse(["foo.bin"]).wants_database is True
