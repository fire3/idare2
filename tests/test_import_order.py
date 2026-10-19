"""The remote package must stay importable outside IDA.

``idare2.remote.*`` is imported by the CLI process too (for the op names and the
error taxonomy), so no module in it may import ``ida_*`` at module level.  IDA
modules are only available inside the IDA process, and a module-level import
would break ``idare2 -h`` on a machine without IDAPython on ``sys.path``.

This walks the AST rather than importing, so the check itself works anywhere.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REMOTE_ROOT = Path(__file__).resolve().parents[1] / "src" / "idare2" / "remote"


def _modules() -> list[Path]:
    return sorted(REMOTE_ROOT.rglob("*.py"))


@pytest.mark.parametrize("path", _modules(), ids=lambda p: p.relative_to(REMOTE_ROOT).as_posix())
def test_no_module_level_ida_imports(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offenders: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            offenders.extend(
                alias.name for alias in node.names if alias.name.startswith("ida_")
            )
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module
            and (node.module.startswith("ida_") or node.module == "idapro")
        ):
            offenders.append(node.module)
    assert not offenders, (
        f"{path.name} imports {offenders} at module level; move it inside the "
        "function that needs it"
    )


def test_remote_package_imports_without_ida() -> None:
    # The CLI imports these for op names; if that ever pulls in IDA, this fails.
    import idare2.remote  # noqa: F401
    import idare2.remote.dispatch  # noqa: F401
    import idare2.remote.entry  # noqa: F401
    import idare2.remote.helpers  # noqa: F401
    import idare2.remote.ops  # noqa: F401


def test_top_level_package_is_trivial() -> None:
    import idare2

    assert idare2.__version__
    # No heavy imports leaked into the package root.
    assert not hasattr(idare2, "DatabaseHandle")
