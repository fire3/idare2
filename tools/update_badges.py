#!/usr/bin/env python3
"""Regenerate the self-hosted README badges from project metadata.

The PyPI, Python-version, and license badges are plain SVGs in
``assets/badges/`` so the README does not depend on an external badge service.
The CI badge intentionally stays dynamic and points at GitHub Actions.

Run this after bumping ``__version__``:

    uv run tools/update_badges.py
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets" / "badges"

LABEL_COLOR = "#24292f"
PYPI_COLOR = "#3775a9"
PYTHON_COLOR = "#3776ab"
LICENSE_COLOR = "#2ea44f"

#: Rough average glyph width for 11px Verdana; badges are text-only.
CHAR_WIDTH = 5.9
MIN_SECTION = 42
PADDING = 12


def _section_width(text: str) -> int:
    return max(MIN_SECTION, round(len(text) * CHAR_WIDTH) + PADDING)


def _badge(label: str, value: str, color: str) -> str:
    label_width = _section_width(label)
    value_width = _section_width(value)
    width = label_width + value_width
    label_x = label_width / 2
    value_x = label_width + value_width / 2
    aria = escape(f"{label}: {value}")
    label_text = escape(label)
    value_text = escape(value)
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" role="img" aria-label="{aria}">
  <title>{aria}</title>
  <defs>
    <linearGradient id="g" x2="0" y2="100%">
      <stop offset="0" stop-color="#fff" stop-opacity=".18"/>
      <stop offset="1" stop-color="#000" stop-opacity=".08"/>
    </linearGradient>
    <clipPath id="r">
      <rect width="{width}" height="20" rx="3"/>
    </clipPath>
  </defs>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="{LABEL_COLOR}"/>
    <rect x="{label_width}" width="{value_width}" height="20" fill="{color}"/>
    <rect width="{width}" height="20" fill="url(#g)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">
    <text x="{label_x:g}" y="15" fill="#000" fill-opacity=".35">{label_text}</text>
    <text x="{label_x:g}" y="14">{label_text}</text>
    <text x="{value_x:g}" y="15" fill="#000" fill-opacity=".35">{value_text}</text>
    <text x="{value_x:g}" y="14">{value_text}</text>
  </g>
</svg>
"""


def _project() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def _version() -> str:
    text = (ROOT / "src" / "idare2" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"', text, re.MULTILINE)
    if not match:
        raise SystemExit("cannot find __version__ in src/idare2/__init__.py")
    return match.group(1)


def _python_versions(project: dict) -> str:
    versions = [
        classifier.rsplit(" :: ", 1)[-1]
        for classifier in project["classifiers"]
        if classifier.startswith("Programming Language :: Python :: 3.")
    ]
    if not versions:
        raise SystemExit("no Python 3.x classifiers in pyproject.toml")
    return " | ".join(versions)


def _license(project: dict) -> str:
    value = project.get("license", "MIT")
    if isinstance(value, dict):
        value = value.get("text", value.get("file", "MIT"))
    return str(value)


def main() -> None:
    project = _project()
    version = _version()
    badges = {
        "pypi.svg": _badge("PyPI", f"v{version}", PYPI_COLOR),
        "python.svg": _badge("Python", _python_versions(project), PYTHON_COLOR),
        "license.svg": _badge("License", _license(project), LICENSE_COLOR),
    }
    OUT.mkdir(parents=True, exist_ok=True)
    for name, svg in badges.items():
        path = OUT / name
        path.write_text(svg, encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
