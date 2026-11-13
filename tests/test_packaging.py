"""Packaging metadata must stay in sync with the import package.

The version is single-sourced in ``src/idare2/__init__.py`` and read by
hatchling, so ``pyproject.toml`` must not grow a second static version.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import idare2

ROOT = Path(__file__).resolve().parents[1]


def _project() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def test_version_is_single_sourced() -> None:
    project = _project()
    assert project["name"] == "idare2"
    assert project["dynamic"] == ["version"]
    assert "version" not in project
    assert idare2.__version__


def test_console_scripts_are_declared() -> None:
    scripts = _project()["scripts"]
    assert scripts["idare2"] == "idare2.cli:main"
    assert scripts["ir2"] == "idare2.cli:main"


def test_pypi_badge_matches_the_package_version() -> None:
    svg = (ROOT / "assets" / "badges" / "pypi.svg").read_text(encoding="utf-8")
    assert f"v{idare2.__version__}" in svg
