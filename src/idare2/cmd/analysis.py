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
from idare2.fmt import listing as fmt_listing
from idare2.fmt import to_json
from idare2.fmt import xrefs as fmt_xrefs

if TYPE_CHECKING:
    from idare2.parser import Statement
    from idare2.session import Session

ANALYSIS_DETAIL = [
    ("aa", "", "wait for IDA's automatic analysis to settle"),
    ("aaa", "", "the same, plus analysis of unrecognised regions"),
    ("af", "", "create a function at the current address"),
    ("afr", "", "re-analyse the current function"),
    ("afn", "[name]", "rename the current function"),
    ("afi", "", "function details"),
    ("afl", "[pat]", "list functions"),
    ("aflj", "[pat]", "list functions as JSON"),
    ("afb", "", "list the basic blocks of the current function"),
    ("afc", "", "callers of the current function"),
    ("afC", "", "callees of the current function"),
    ("axt", "[addr]", "cross-references to an address"),
    ("axf", "[addr]", "cross-references from an address"),
    ("axj", "[addr]", "cross-references as JSON"),
    ("ab", "", "the basic block at the current address"),
]

FUNCTION_DETAIL = [
    ("af", "", "create a function at the current address"),
    ("afr", "", "re-analyse the current function"),
    ("afi", "", "function details"),
    ("afij", "", "function details as JSON"),
    ("afl", "[pat]", "list functions"),
    ("afb", "", "list the basic blocks of the current function"),
    ("afbj", "", "the basic blocks as JSON"),
    ("afc", "", "callers of the current function"),
    ("afC", "", "callees of the current function"),
]


@command("a", usage="[a]", summary="analysis", detail=ANALYSIS_DETAIL)
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
    suffix = " (deep)" if deep else ""
    return [f"-- analysis complete{suffix} --"]


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

    if token in ("afn", "afN"):
        return _rename(session, rest)

    if token.startswith("afl"):
        pattern = rest[0] if rest else None
        payload, meta = session.remote.call_with_meta(
            "functions", pattern=pattern, offset=offset, count=count
        )
        if token.endswith("j"):
            return [to_json(payload)]
        return with_more(fmt_listing.format_functions(payload, session), meta)

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

    raise UsageError(f"unsupported function command '{token}' (see af?)")


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
