"""idare2 — radare2-style CLI over IDA Pro databases.

The package root is intentionally trivial: this module is imported inside the
IDA process by :mod:`idare2.remote.entry`, so it must not pull in anything that
is unavailable in IDA's own Python (no ``ida_nexus``, no ``ida_*``).
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
