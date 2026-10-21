"""Function-graph rendering for the ``ag`` command family.

The remote ``graph`` operation returns a plain dict containing the function,
its basic blocks, and the disassembled operations in each block.  Keeping the
three output modes here -- rather than in the command handler -- lets the graph
JSON stay machine-readable while the ASCII and DOT forms share exactly the same
edge selection.
"""

from __future__ import annotations

from typing import Any

from idare2.fmt import addr_width, fmt_addr


def _address(value: int, session: Any) -> str:
    bits = session.info.get("bits")
    return fmt_addr(int(value), addr_width(bits))


def _edge_list(block: dict[str, Any]) -> list[tuple[str | None, int]]:
    """Directed edges from a block, tagged as ``jump`` or ``fail`` when known."""
    jump = block.get("jump")
    fail = block.get("fail")
    edges: list[tuple[str | None, int]] = []
    seen: set[int] = set()
    if jump is not None:
        target = int(jump)
        edges.append(("jump", target))
        seen.add(target)
    if fail is not None:
        target = int(fail)
        edges.append(("fail", target))
        seen.add(target)
    for successor in block.get("successors") or []:
        target = int(successor)
        if target not in seen:
            edges.append((None, target))
            seen.add(target)
    return edges


def _op_text(op: dict[str, Any]) -> str:
    text = str(op.get("disasm") or op.get("opcode") or "")
    comment = str(op.get("comment") or "")
    return f"{text} ; {comment}" if comment else text


def _block_body(block: dict[str, Any], index: int, session: Any) -> list[str]:
    start = int(block["addr"])
    size = int(block.get("size") or 0)
    body = [f"{_address(start, session)}  [#{index}]  size {size}"]
    for op in block.get("ops") or []:
        ea = int(op.get("addr") or op.get("ea") or 0)
        body.append(f"{_address(ea, session)}  {_op_text(op)}")
    return body


def format_ascii(graph: dict[str, Any], session: Any) -> list[str]:
    """``agf`` -- a compact, deterministic basic-block graph.

    radare2 lays nodes out on a two-dimensional canvas.  idare2 keeps the same
    information (address, instructions, jump/fail edges) in a vertical form so
    output remains stable in batch mode and through ``~``/``>`` filters.
    """
    lines: list[str] = []
    name = str(graph.get("name") or "?")
    start = int(graph.get("addr") or 0)
    size = int(graph.get("size") or 0)
    blocks = list(graph.get("blocks") or [])
    lines.append(
        f"-- {name} @ {_address(start, session)} size {size} blocks {len(blocks)} --"
    )

    for index, block in enumerate(blocks):
        body = _block_body(block, index, session)
        width = max((len(line) for line in body), default=0)
        lines.append("┌" + "─" * (width + 2) + "┐")
        lines.extend(f"│ {line.ljust(width)} │" for line in body)
        lines.append("└" + "─" * (width + 2) + "┘")

        edges = _edge_list(block)
        for edge_index, (kind, target) in enumerate(edges):
            branch = "└" if edge_index == len(edges) - 1 else "├"
            label = f"{kind} " if kind else ""
            lines.append(f"  {branch}─ {label}{_address(target, session)}")
        if index != len(blocks) - 1:
            lines.append("")

    return lines


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\l")


def _dot_label(
    graph: dict[str, Any], block: dict[str, Any], index: int, session: Any
) -> str:
    rows: list[str] = []
    if index == 0:
        name = str(graph.get("name") or "")
        if name:
            rows.append(f";-- {name} --")
    start = int(block["addr"])
    for op in block.get("ops") or []:
        ea = int(op.get("addr") or op.get("ea") or 0)
        rows.append(f"{_address(ea, session)}  {_op_text(op)}")
    if not rows:
        rows.append(f"{_address(start, session)}")
    return "\\l".join(_dot_escape(row) for row in rows) + "\\l"


def format_dot(graph: dict[str, Any], session: Any) -> list[str]:
    """``agfd`` / ``agg`` -- Graphviz DOT for the current function graph."""
    name = str(graph.get("name") or "?")
    lines = [
        "digraph code {",
        '\tgraph [fontsize=8 fontname="Courier" bgcolor=azure splines="ortho"];',
        "\tnode [fillcolor=white style=filled shape=box];",
        '\tedge [arrowhead="normal"];',
    ]
    for index, block in enumerate(graph.get("blocks") or []):
        start = int(block["addr"])
        node = _address(start, session)
        label = _dot_label(graph, block, index, session)
        lines.append(
            f'\t"{node}" [URL="{_dot_escape(name)}/{node}", '
            f'fontcolor="#767676", fontname="Courier", label="{label}"];'
        )

    for block in graph.get("blocks") or []:
        source = _address(int(block["addr"]), session)
        for kind, target in _edge_list(block):
            color = {"jump": "#13a10e", "fail": "#c50f1f"}.get(kind, "#3a96dd")
            lines.append(
                f'\t"{source}" -> "{_address(target, session)}" [color="{color}"];'
            )
    lines.append("}")
    return lines
