"""Op modules.  Importing this package registers every handler.

``load_all()`` is called once per IDA process by :mod:`idare2.remote.entry`.
"""

from __future__ import annotations

_LOADED = False


def load_all() -> None:
    """Import every op module so the ``@op`` decorators run."""
    global _LOADED
    if _LOADED:
        return
    from idare2.remote.ops import (  # noqa: F401
        analysis,
        comments,
        decompile,
        disasm,
        info,
        memory,
        search,
        session,
        types,
        write,
    )

    _LOADED = True
