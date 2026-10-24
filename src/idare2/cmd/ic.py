"""The ``ic`` class family.

IDA has no C++ class list: DWARF/PDB/RTTI information ends up in the type
system as UDTs with a ``_vptr`` member or base classes, and methods are
ordinary functions whose demangled name starts with ``Class::``.  The remote
``classes`` operation reconstructs r2's shape from those two sources.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from idare2.cmd import command
from idare2.errors import UsageError
from idare2.fmt import to_json

if TYPE_CHECKING:
    from idare2.parser import Statement
    from idare2.session import Session

IC_DETAIL = [
    ("ic", "", "list classes, methods and fields"),
    ("icj", "", "classes as JSON"),
    ("icq", "", "classes with their address range"),
    ("icqq", "", "class names only"),
    ("icl", "", "method addresses, one line per class"),
    ("iclc", "", "class count"),
    ("ics", "", "class and method addresses as simple rows"),
    ("ic.", "", "class/method at the current address"),
    ("ic*", "", "classes as radare2 commands"),
]

IC_TOKENS = frozenset({"ic", "icj", "icq", "icqq", "icl", "iclc", "ics", "ic.", "ic*"})

IC_UNSUPPORTED = frozenset({"ic+", "ic-", "icc", "icg", "iccj"})


def _span(entry: dict[str, Any]) -> tuple[int, int, int]:
    """``(addr, start, end)`` for a class; methods stand in for a vftable."""
    methods = [int(method["addr"]) for method in entry.get("methods") or []]
    addr = int(entry.get("addr") or (min(methods) if methods else 0))
    start = min([addr, *methods]) if methods else addr
    end = max([addr + 1, *(address + 4 for address in methods)])
    return addr, start, end


def _method_flags(method: dict[str, Any]) -> str:
    flags = method.get("flags") or []
    if "constructor" in flags:
        return "C"
    if "destructor" in flags:
        return "D"
    return " "


def _classes_text(classes: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for entry in classes:
        addr, start, end = _span(entry)
        lines.append(
            f"0x{addr:08x} [0x{start:08x} - 0x{end:08x}] {end - start:6d} "
            f"c++ class {entry['index']} {entry['classname']}"
        )
        for slot, method in enumerate(entry.get("methods") or []):
            lines.append(
                f"0x{int(method['addr']):08x} c++   method {slot:3d} "
                f"{_method_flags(method)} {method['name']}"
            )
    return lines


@command(
    "ic",
    usage="[jq.l]",
    summary="list classes, methods and fields",
    detail=IC_DETAIL,
    json_suffix=True,
    suffixes=frozenset({"", "j", "q", "qq", "l", "lc", "s", "*", "."}),
    suffix_label="class command",
    suffix_help="ic?",
)
def classes(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    if token in IC_UNSUPPORTED:
        raise UsageError(
            f"unsupported class command '{token}' (class editing is not implemented)"
        )
    if token not in IC_TOKENS:
        raise UsageError(f"unsupported class command '{token}' (see ic?)")

    if token == "ic.":
        payload = session.remote.call("class_at", ea=session.seek)
        if not payload:
            return []
        return [f"{payload['classname']}::{payload['method']}"]

    rows = session.remote.call("classes")
    if token == "icj":
        return [to_json(rows)]
    if token == "icqq":
        return [str(entry["classname"]) for entry in rows]
    if token == "iclc":
        return [str(len(rows))]
    if token == "icl":
        return [
            " ".join(f"0x{int(method['addr']):x}" for method in entry.get("methods") or [])
            for entry in rows
        ]
    if token == "ics":
        return [
            f"0x{int(method['addr']):x} [{entry['classname']}] {method['name']}"
            for entry in rows
            for method in entry.get("methods") or []
        ]
    if token == "ic*":
        lines = ["fs classes"]
        for entry in rows:
            addr, _start, _end = _span(entry)
            lines.append(f"'f class.{entry['classname']} = 0x{addr:x}")
            for method in entry.get("methods") or []:
                lines.append(
                    f"'f method.{entry['classname']}.{method['name']} = "
                    f"0x{int(method['addr']):x}"
                )
        lines.append("fs-")
        return lines
    if token == "icq":
        return [
            f"0x{addr:08x} [0x{start:08x} - 0x{end:08x}] c++ {entry['classname']}"
            for entry in rows
            for addr, start, end in [_span(entry)]
        ]
    return _classes_text(rows)
