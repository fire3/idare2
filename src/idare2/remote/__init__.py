"""IDA-side entry points, executed inside the IDA process through Nexus.

Nothing in this subpackage may import ``ida_*`` at module level -- the modules
are imported on both sides (the CLI needs the op names and the error taxonomy),
and only the IDA process has the IDAPython modules.  ``tests/test_import_order``
enforces that.
"""

from idare2.remote.dispatch import HANDLERS, invoke, op

__all__ = ["HANDLERS", "invoke", "op"]
