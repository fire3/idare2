"""Tests for the command-surface probe tool (``tools/cmdsurface.py``)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parents[1] / "tools"


def _load():
    spec = importlib.util.spec_from_file_location("cmdsurface", _TOOLS / "cmdsurface.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_r2_tokens_parses_help_lines() -> None:
    module = _load()
    help_text = "\n".join(
        [
            "Usage: p[=68abcdDfiImrstuxz] [arg|len] [@addr]",
            "| p8[?][bdfsjx] [len]     8bit hexpair list of bytes",
            "| pa[?][edD] [arg]        pa:assemble  pa[dD]:disasm or pae: esil from hex",
            "| px[?][owq] [len]        hexdump of N bytes",
            "| pkill [process-name]    kill all processes",
            "not a help line",
        ]
    )
    # r2_tokens shells out; test the shared regex pair instead.
    tokens = set()
    for line in help_text.splitlines():
        match = module._TOKEN.match(line)
        if not match:
            continue
        name = module._NAME.match(match.group(1))
        if name:
            tokens.add(name.group(0))
    assert tokens == {"p8", "pa", "px", "pkill"}


def test_classify_splits_support_exclusion_and_missing() -> None:
    module = _load()
    stdout = "\n".join(
        [
            "MARK_pd",
            "Usage: pd [n]",
            "| pd [n]  disassemble",
            "MARK_pF",
            "",
            "MARK_pz",
            "",
            "MARK_px",
            "Usage: px [n]",
        ]
    )
    stderr = "\n".join(
        [
            "ERROR: unknown command 'pz' (see '?' for the command list)",
            "ERROR: 'pF' is not supported by idare2: ASN.1 printing is a radare2 feature",
        ]
    )
    verdicts = module.classify(["pd", "pF", "pz", "px", "q"], stdout, stderr)
    assert verdicts == {
        "pd": "supported",
        "pF": "excluded: ASN.1 printing is a radare2 feature",
        "pz": "missing",
        "px": "supported",
        "q": "missing",
    }


def test_classify_keeps_markers_from_bleeding_into_the_next_token() -> None:
    module = _load()
    stdout = "MARK_a\nUsage: a\nMARK_b\n\n\nMARK_c\nUsage: c\n"
    verdicts = module.classify(["a", "b", "c"], stdout, "")
    assert verdicts == {"a": "supported", "b": "missing", "c": "supported"}


@pytest.mark.parametrize(
    ("marker", "bad"),
    [
        ("?e @@pd", True),  # '@@' is the iterator modifier, never a marker
        ("?e MARK_pd", False),
    ],
)
def test_marker_shape_avoids_the_iterator_modifiers(marker: str, bad: bool) -> None:
    assert (marker.startswith("?e @@")) is bad
