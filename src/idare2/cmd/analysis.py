"""The ``a`` analysis family.

The important semantic difference from radare2: IDA has already analysed the
database by the time we attach.  ``aa`` therefore *waits* rather than
*analyses*, and ``afl`` returns results without it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from idare2.cmd import command, numeric_args, with_more
from idare2.errors import UsageError
from idare2.fmt import disasm as fmt_disasm
from idare2.fmt import graph as fmt_graph
from idare2.fmt import listing as fmt_listing
from idare2.fmt import to_json
from idare2.fmt import xrefs as fmt_xrefs

if TYPE_CHECKING:
    from idare2.parser import Statement
    from idare2.session import Session

ANALYSIS_DETAIL = [
    ("a", "", "file information (idare2 maps r2's analysis info here)"),
    ("ai", "", "file information (r2's address-info form is not available)"),
    ("aa", "", "wait for IDA's automatic analysis to settle"),
    ("aaa", "", "the same, plus analysis of unrecognised regions"),
    ("af", "", "create a function at the current address"),
    ("afr", "", "re-analyse the current function"),
    ("afn", "[name]", "rename the current function"),
    ("afu", "addr", "resize the function to end at addr"),
    ("afi", "", "function details"),
    ("afl", "[pat]", "list functions"),
    ("aflj", "[pat]", "list functions as JSON"),
    ("aflq", "[pat]", "list function addresses only"),
    ("afb", "", "list the basic blocks of the current function"),
    ("afc", "", "callers of the current function"),
    ("afC", "", "callees of the current function"),
    ("afv", "", "local variables and arguments (needs Hex-Rays)"),
    ("afvj", "", "local variables as JSON (needs Hex-Rays)"),
    ("afvR", "[name]", "addresses where variables are read"),
    ("afvW", "[name]", "addresses where variables are written"),
    ("afx", "[addr]", "references made from the function"),
    ("afxj", "[addr]", "references made from the function as JSON"),
    ("axt", "[addr]", "cross-references to an address"),
    ("axf", "[addr]", "cross-references from an address"),
    ("axj", "[addr]", "cross-references as JSON"),
    ("ab", "", "the basic block at the current address"),
    ("agf", "[addr]", "basic-block function graph"),
    ("agfj", "[addr]", "basic-block function graph as JSON"),
    ("agfd", "[addr]", "basic-block function graph as Graphviz DOT"),
]

FUNCTION_DETAIL = [
    ("af", "", "create a function at the current address"),
    ("afr", "", "re-analyse the current function"),
    ("afu", "addr", "resize the function to end at addr"),
    ("afi", "", "function details"),
    ("afij", "", "function details as JSON"),
    ("afl", "[pat]", "list functions"),
    ("aflj", "[pat]", "list functions as JSON"),
    ("aflq", "[pat]", "list function addresses only"),
    ("afb", "", "list the basic blocks of the current function"),
    ("afbj", "", "the basic blocks as JSON"),
    ("afc", "", "callers of the current function"),
    ("afC", "", "callees of the current function"),
    ("afv", "", "local variables and arguments (needs Hex-Rays)"),
    ("afvj", "", "local variables as JSON (needs Hex-Rays)"),
    ("afvR", "[name]", "addresses where variables are read"),
    ("afvW", "[name]", "addresses where variables are written"),
    ("afx", "[addr]", "references made from the function"),
    ("afxj", "[addr]", "references made from the function as JSON"),
]


@command(
    "a",
    usage="[a]",
    summary="analysis",
    detail=ANALYSIS_DETAIL,
    suffixes=frozenset({"", "a", "aa", "aaa", "i"}),
    suffix_label="analysis command",
    suffix_help="a?",
)
def analysis(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    if token in ("aa", "aaa", "aaaa"):
        return _await_analysis(session, deep=token != "aa")
    if token in ("a", "ai"):
        return fmt_listing.format_info(session.info, session)
    raise UsageError(f"unsupported analysis command '{token}' (see a?)")


def _await_analysis(session: Session, *, deep: bool) -> list[str]:
    backend = getattr(session.handle.instance, "backend", "idalib")
    if backend == "gui":
        status = session.handle.poll_autoanalysis()
        if status.get("complete"):
            return ["-- analysis already complete (IDA autoanalysis) --"]
        return ["-- GUI analysis still running; not forcing it --"]
    session.handle.wait_autoanalysis(session.config.get_int("ida.timeout") * 20)
    if not deep:
        return ["-- analysis complete --"]
    payload = session.remote.call("deep_analyze")
    if not payload.get("analyzed"):
        return ["-- analysis complete; no additional regions to analyse --"]
    return ["-- analysis complete (deep) --"]


@command(
    "a[fF]",
    usage="[?]",
    summary="function analysis",
    detail=FUNCTION_DETAIL,
    json_suffix=True,
)
def function_analysis(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    rest, count, offset = numeric_args(session, statement)

    if token == "af":
        target = session.resolve(rest[0]) if rest else session.seek
        payload = session.remote.call("create_function", ea=target)
        return [f"-- function {payload.get('name')} at {session.format_addr(int(payload['ea']))} --"]

    if token == "afr":
        target = session.resolve(rest[0]) if rest else session.seek
        session.remote.call("reanalyze", ea=target)
        return []

    if token == "afn" or token == "afN":
        return _rename(session, rest)

    if token == "afu":
        return _resize(session, statement)

    if token in ("afl", "aflj", "aflq"):
        pattern = rest[0] if rest else None
        payload, meta = session.remote.call_with_meta(
            "functions", pattern=pattern, offset=offset, count=count
        )
        if token == "aflj":
            return [to_json(payload)]
        if token == "aflq":
            # r2's quiet form is the address alone, one per line.
            return [f"0x{int(item['ea']):08x}" for item in payload]
        return with_more(fmt_listing.format_functions(payload, session), meta)

    # Other `afl` modifiers (afl*, aflm, afll, afln, afls, ...) are not
    # implemented.  They used to fall into the branch above and print the
    # ordinary listing, silently claiming to support whatever was asked.
    if token.startswith("afl"):
        raise UsageError(f"unsupported function command '{token}' (see af?)")

    # `afbj`/`afij` have to be named explicitly: the JSON branch inside used to
    # be unreachable because the guard above it compared the whole token, so
    # `afij` fell through to "unsupported function command".
    if token in ("afb", "afbj"):
        target = session.resolve(rest[0]) if rest else session.seek
        blocks = session.remote.call("blocks", ea=target)
        if token.endswith("j"):
            return [to_json(blocks)]
        return fmt_disasm.format_blocks(blocks, session)

    if token in ("afi", "afij"):
        target = session.resolve(rest[0]) if rest else session.seek
        payload = session.remote.call("function_info", ea=target)
        if token.endswith("j"):
            return [to_json(payload)]
        return fmt_disasm.format_function_info(payload, session)

    if token in ("afc", "afC"):
        target = session.resolve(rest[0]) if rest else session.seek
        op = "callers" if token == "afc" else "callees"
        payload = session.remote.call(op, ea=target)
        formatter = fmt_xrefs.format_callers if token == "afc" else fmt_xrefs.format_callees
        return formatter(payload, session)

    if token in ("afx", "afxj"):
        target = session.resolve(rest[0]) if rest else session.seek
        payload = session.remote.call("function_xrefs", ea=target)
        if token.endswith("j"):
            return [to_json(payload)]
        return fmt_xrefs.format_function_xrefs(payload)

    if token in ("afv", "afvj"):
        target = session.resolve(rest[0]) if rest else session.seek
        payload = session.remote.call("function_locals", ea=target)
        if token.endswith("j"):
            return [to_json(payload)]
        return fmt_disasm.format_locals(payload)

    if token in ("afvR", "afvW", "afvRj", "afvWj"):
        return _var_accesses(session, statement, rest)

    raise UsageError(f"unsupported function command '{token}' (see af?)")


def _var_accesses(
    session: Session, statement: Statement, rest: list[str]
) -> list[str]:
    """``afvR``/``afvW`` -- addresses where each variable is read or written."""
    token = statement.cmd
    kind = "read" if "R" in token else "write"
    name = rest[0] if rest else None
    if len(rest) > 1:
        raise UsageError(f"{token} takes at most one variable name")
    rows = session.remote.call("var_accesses", ea=session.seek, name=name)
    if token.endswith("j"):
        return [to_json([{"name": row["name"], "addrs": row[kind]} for row in rows])]
    lines = []
    for row in rows:
        addrs = row[kind]
        line = f"{row['name']:>10}"
        if addrs:
            line += "  " + ",".join(f"0x{int(ea):x}" for ea in addrs)
        lines.append(line)
    return lines


def _resize(session: Session, statement: Statement) -> list[str]:
    """``afu <end>`` -- move the end of the function containing the seek.

    The end is read from the raw argv: ``numeric_args`` would swallow a bare
    hex end address as a repeat count.
    """
    from idare2 import cmd as cmd_module

    cmd_module.require_write(session, "'afu'")
    words = statement.argv
    if len(words) != 1:
        raise UsageError("afu needs an end address")
    end = session.resolve(words[0])
    session.remote.call("resize_function", ea=session.seek, end=end)
    return []


def _rename(session: Session, rest: list[str]) -> list[str]:
    from idare2 import cmd as cmd_module

    cmd_module.require_write(session, "'afn'")
    if not rest:
        raise UsageError("afn needs a name")
    name = rest[0]
    session.remote.call("set_name", ea=session.seek, name=name)
    session.flags.add(name, session.seek)
    return []


@command("a[xX]", usage="[addr]", summary="cross-references", json_suffix=True)
def xrefs(session: Session, statement: Statement) -> list[str]:
    token = statement.cmd
    rest, _count, _offset = numeric_args(session, statement)
    target = session.resolve(rest[0]) if rest else session.seek
    direction = "to" if token.startswith("axt") else "from"
    payload = session.remote.call("xrefs", ea=target, direction=direction)
    if token.endswith("j"):
        return [to_json(payload)]
    return fmt_xrefs.format_xrefs(payload, session)


@command("a[bB]", usage="", summary="basic block at the current address", json_suffix=True)
def basic_block(session: Session, statement: Statement) -> list[str]:
    payload = session.remote.call("block_info", ea=session.seek)
    if statement.cmd.endswith("j"):
        return [to_json(payload)]
    return [
        f"index: {payload['index']}/{payload['count']}",
        f"start: {session.format_addr(int(payload['start']))}",
        f"end:   {session.format_addr(int(payload['end']))}",
        f"size:  {payload['size']}",
    ]


GRAPH_DETAIL = [
    ("ag", "[addr]", "basic-block function graph"),
    ("agf", "[addr]", "basic-block function graph"),
    ("agfj", "[addr]", "basic-block function graph as JSON"),
    ("agj", "[addr]", "alias for agfj"),
    ("agfd", "[addr]", "basic-block function graph as Graphviz DOT"),
    ("agg", "[addr]", "alias for agfd (current function DOT)"),
    ("aggd", "[addr]", "alias for agfd"),
]


@command(
    "ag",
    usage="[addr]",
    summary="basic-block function graph",
    detail=GRAPH_DETAIL,
    json_suffix=True,
)
@command("agf", usage="[addr]", detail=GRAPH_DETAIL, json_suffix=True)
@command("agfj", usage="[addr]", detail=GRAPH_DETAIL)
@command("agj", usage="[addr]", detail=GRAPH_DETAIL)
@command("agfd", usage="[addr]", detail=GRAPH_DETAIL)
@command("agg", usage="[addr]", detail=GRAPH_DETAIL)
@command("aggd", usage="[addr]", detail=GRAPH_DETAIL)
def function_graph(session: Session, statement: Statement) -> list[str]:
    """Render the current function's basic-block graph.

    ``agf`` is the compact ASCII form, ``agfj``/``agj`` the r2-shaped JSON
    form, and ``agfd`` Graphviz DOT.  idare2 accepts ``agg``/``aggd`` as
    convenient aliases for function DOT; radare2 reserves ``agg`` for its
    separate custom-graph canvas.
    """
    token = statement.cmd
    rest, _count, _offset = numeric_args(session, statement)
    target = session.resolve(rest[0]) if rest else session.seek
    payload = session.remote.call("graph", ea=target)

    if token in ("agfj", "agj"):
        return [to_json([payload])]
    if token in ("agfd", "agg", "aggd"):
        return fmt_graph.format_dot(payload, session)
    if token in ("ag", "agf"):
        return fmt_graph.format_ascii(payload, session)
    raise UsageError(f"unsupported graph command '{token}' (see ag?)")
