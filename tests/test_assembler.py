"""Client assembly backend: IDA first, optional radare2 fallback second."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from idare2 import assembler
from idare2.errors import CommandError, UsageError


class _Remote:
    def __init__(self, error: Exception | None = None, data: bytes = b"\x90") -> None:
        self.error = error
        self.data = data
        self.calls: list[tuple[str, dict]] = []

    def call(self, operation: str, **arguments):
        self.calls.append((operation, arguments))
        if self.error is not None:
            raise self.error
        return {"ea": arguments["ea"], "size": len(self.data), "data": self.data}


def _session(
    remote: _Remote, *, arch: str = "ARM", bits: int = 32, endian: str = "little"
):
    return SimpleNamespace(
        remote=remote,
        seek=0x1000,
        info={"architecture": arch, "bits": bits, "endian": endian},
    )


def test_ida_success_does_not_need_rasm2(monkeypatch) -> None:
    monkeypatch.setattr(assembler.shutil, "which", lambda _name: None)
    remote = _Remote(data=b"\x01\x00\xa0\xe1")
    session = _session(remote)

    assert assembler.assemble(session, "nop", ea=0x2000) == b"\x01\x00\xa0\xe1"
    assert remote.calls == [("assemble", {"ea": 0x2000, "text": "nop"})]


def test_program_counter_placeholder_is_substituted(monkeypatch) -> None:
    monkeypatch.setattr(assembler.shutil, "which", lambda _name: None)
    remote = _Remote(data=b"\x00\x00\x00\x00")
    session = _session(remote)

    assembler.assemble(session, "call $$", ea=0x401000)
    assert remote.calls == [
        ("assemble", {"ea": 0x401000, "text": "call 0x401000"})
    ]


def test_rasm2_fallback_uses_the_database_architecture(monkeypatch) -> None:
    remote = _Remote(error=CommandError("IDA has no assembler"))
    session = _session(remote, arch="ARM", bits=32, endian="little")
    seen: list[list[str]] = []

    monkeypatch.setattr(assembler.shutil, "which", lambda name: f"/opt/{name}")
    monkeypatch.setattr(
        assembler.subprocess,
        "run",
        lambda argv, **kwargs: (
            seen.append(argv)
            or SimpleNamespace(returncode=0, stdout="0000a0e1\n", stderr="")
        ),
    )

    assert assembler.assemble(session, "nop") == b"\x00\x00\xa0\xe1"
    assert seen == [
        ["/opt/rasm2", "-q", "-a", "arm", "-s", "0x1000", "-b", "32", "--", "nop"]
    ]


def test_rasm2_fallback_accepts_open_summary_bitness(monkeypatch) -> None:
    remote = _Remote(error=CommandError("IDA has no assembler"))
    session = _session(remote)
    session.info = {"architecture": "ARM", "bitness": 32, "endian": "little"}
    seen: list[list[str]] = []

    monkeypatch.setattr(assembler.shutil, "which", lambda _name: "/opt/rasm2")
    monkeypatch.setattr(
        assembler.subprocess,
        "run",
        lambda argv, **kwargs: (
            seen.append(argv)
            or SimpleNamespace(returncode=0, stdout="0000a0e1", stderr="")
        ),
    )

    assert assembler.assemble(session, "nop") == bytes.fromhex("0000a0e1")
    assert seen[0][seen[0].index("-b") + 1] == "32"


def test_rasm2_fallback_accepts_file_info_arch_key() -> None:
    session = SimpleNamespace(info={"arch": "MIPS", "bits": 32})
    assert assembler.r2_arch(session) == "mips"


def test_rasm2_fallback_honours_big_endian_and_arm64(monkeypatch) -> None:
    remote = _Remote(error=CommandError("IDA has no assembler"))
    session = _session(remote, arch="ARM64", bits=64, endian="big")
    seen: list[list[str]] = []

    monkeypatch.setattr(assembler.shutil, "which", lambda _name: "/opt/rasm2")
    monkeypatch.setattr(
        assembler.subprocess,
        "run",
        lambda argv, **kwargs: (
            seen.append(argv)
            or SimpleNamespace(returncode=0, stdout="1f2003d5", stderr="")
        ),
    )

    assert assembler.assemble(session, "nop") == bytes.fromhex("1f2003d5")
    assert seen[0][3] == "arm"
    assert "-e" in seen[0]
    assert seen[0][seen[0].index("-b") + 1] == "64"


def test_missing_rasm2_preserves_the_ida_error(monkeypatch) -> None:
    monkeypatch.setattr(assembler.shutil, "which", lambda _name: None)
    session = _session(_Remote(error=CommandError("IDA has no assembler")))

    with pytest.raises(CommandError, match="IDA has no assembler"):
        assembler.assemble(session, "nop")


def test_rasm2_failure_is_reported(monkeypatch) -> None:
    monkeypatch.setattr(assembler.shutil, "which", lambda _name: "/opt/rasm2")
    monkeypatch.setattr(
        assembler.subprocess,
        "run",
        lambda argv, **kwargs: SimpleNamespace(
            returncode=1, stdout="", stderr="ERROR: Cannot assemble 'wat'"
        ),
    )
    session = _session(_Remote(error=CommandError("IDA has no assembler")))

    with pytest.raises(CommandError, match="rasm2.*Cannot assemble"):
        assembler.assemble(session, "wat")


def test_empty_assembly_is_a_usage_error() -> None:
    session = _session(_Remote())
    with pytest.raises(UsageError, match="needs an instruction"):
        assembler.assemble(session, "   ")
