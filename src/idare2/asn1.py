"""Client-side DER/ASN.1 parsing backing ``pFa``/``pFo``/``pFp``/``pFx``.

Zero remote dependencies: the command reads bytes with the existing
``read_bytes`` op and this module parses them in the client process, so the
behaviour is identical on every backend and costs the worker nothing.

Strict DER only -- r2's ``pFa`` behaves the same way.  BER indefinite
lengths, non-minimal length encodings and multi-byte tags raise
``UsageError`` instead of degrading; a truncated tree reports the offset.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from idare2.errors import UsageError

#: Recursion guard against crafted nesting bombs.
MAX_DEPTH = 32

#: Universal tag numbers that actually appear in DER structures.
TAG_NAMES = {
    1: "BOOLEAN",
    2: "INTEGER",
    3: "BIT_STRING",
    4: "OCTET_STRING",
    5: "NULL",
    6: "OID",
    7: "ObjectDescriptor",
    9: "REAL",
    10: "ENUMERATED",
    12: "UTF8String",
    13: "RELATIVE_OID",
    14: "NumericString",
    18: "NumericString",
    19: "PrintableString",
    20: "TeletexString",
    22: "IA5String",
    23: "UTCTime",
    24: "GeneralizedTime",
    26: "VisibleString",
    28: "UniversalString",
    30: "BMPString",
    16: "SEQUENCE",
    17: "SET",
}


@dataclass
class Node:
    """One DER tag-length-value element."""

    tag_class: int  # 0 universal, 1 application, 2 context, 3 private
    constructed: bool
    tag_no: int
    offset: int
    header_len: int
    value: bytes
    children: list[Node] = field(default_factory=list)

    @property
    def total_len(self) -> int:
        return self.header_len + len(self.value)

    def name(self) -> str:
        if self.tag_class == 2:
            return f"[{self.tag_no}]"
        return TAG_NAMES.get(self.tag_no, f"TAG_{self.tag_no}")


def parse(data: bytes, offset: int = 0, end: int | None = None, depth: int = 0) -> list[Node]:
    """Parse a strict-DER tree; top level may hold several elements."""
    if depth > MAX_DEPTH:
        raise UsageError(f"ASN.1: nesting deeper than {MAX_DEPTH} at offset {offset}")
    if end is None:
        end = len(data)
    nodes: list[Node] = []
    cursor = offset
    while cursor < end:
        node, consumed = _parse_one(data, cursor, end, depth)
        nodes.append(node)
        cursor += consumed
    if cursor != end:
        raise UsageError(f"ASN.1: trailing garbage after {cursor}")
    return nodes


def _parse_one(data: bytes, start: int, end: int, depth: int) -> tuple[Node, int]:
    if start >= end:
        raise UsageError(f"ASN.1: truncated header at offset {start}")
    first = data[start]
    tag_class = first >> 6
    constructed = bool(first & 0x20)
    tag_no = first & 0x1F
    if tag_no == 0x1F:
        raise UsageError(f"ASN.1: multi-byte tags are not DER at offset {start}")
    cursor = start + 1
    if cursor >= end:
        raise UsageError(f"ASN.1: truncated length at offset {start}")
    first_len = data[cursor]
    cursor += 1
    if first_len == 0x80:
        raise UsageError(f"ASN.1: BER indefinite length at offset {start}")
    if first_len & 0x80:
        count = first_len & 0x7F
        if count > 8 or cursor + count > end:
            raise UsageError(f"ASN.1: bad long-form length at offset {start}")
        raw = data[cursor : cursor + count]
        if len(raw) > 1 and raw[0] == 0:
            raise UsageError(
                f"ASN.1: non-minimal length encoding at offset {start}"
            )
        length = int.from_bytes(raw, "big")
        cursor += count
    else:
        length = first_len
    if cursor + length > end:
        raise UsageError(
            f"ASN.1: truncated value at offset {start}"
            f" (needs {length} bytes, {end - cursor} left)"
        )
    value = data[cursor : cursor + length]
    node = Node(tag_class, constructed, tag_no, start, cursor - start, value)
    if constructed:
        node.children = parse(value, 0, len(value), depth + 1)
    return node, node.total_len


def decode_oid(raw: bytes) -> str:
    """OID content bytes -> dotted decimal (r2's ``pFo``)."""
    if not raw:
        raise UsageError("ASN.1: empty OID")
    out: list[int] = []
    value = 0
    for byte in raw:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            out.append(value)
            value = 0
    if raw[-1] & 0x80:
        raise UsageError("ASN.1: truncated OID component")
    if not out:
        raise UsageError("ASN.1: empty OID")
    # The first byte packs the first two arcs (x*40+y when x < 2).
    first = out[0]
    arcs = [first // 40, first % 40] if first < 80 else [2, first - 80]
    return ".".join(str(arc) for arc in [*arcs, *out[1:]])


#: OIDs that matter for reading a certificate; unknown ones render dotted.
OID_NAMES = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.2.1": "ecPublicKey",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.5": "serialNumber",
    "1.2.840.113549.1.9.1": "emailAddress",
    "2.5.29.17": "subjectAltName",
    "2.5.29.19": "basicConstraints",
    "2.5.29.15": "keyUsage",
    "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
}

#: PKCS#7 content types.
_PKCS7_OIDS = {
    "1.2.840.113549.1.7.1": "data",
    "1.2.840.113549.1.7.2": "signedData",
    "1.2.840.113549.1.7.3": "envelopedData",
    "1.2.840.113549.1.7.4": "signedAndEnvelopedData",
    "1.2.840.113549.1.7.5": "digestedData",
    "1.2.840.113549.1.7.6": "encryptedData",
}


def oid_name(dotted: str) -> str:
    return OID_NAMES.get(dotted, _PKCS7_OIDS.get(dotted, dotted))


def _digest(raw: bytes, limit: int = 16) -> str:
    text = raw.hex()
    if len(raw) <= limit:
        return text
    return text[: limit * 2] + "…"


def render_asn1(nodes: list[Node], *, indent: int = 0, base: int = 0) -> list[str]:
    """``pFa``: an indented tree with r2's absolute-offset column."""
    out: list[str] = []
    for node in nodes:
        offset = base + node.offset
        kind = "cons" if node.constructed else "prim"
        line = (
            f"{' ' * indent}0x{offset:x}: {kind} <{node.name()}>"
            f" len={len(node.value)}"
        )
        if node.tag_class == 2:
            line = f"{' ' * indent}0x{offset:x}: ctx [{node.tag_no}] len={len(node.value)}"
        if not node.constructed and node.value:
            line += f" = {_digest(node.value)}"
        if node.tag_no == 6 and node.tag_class == 0:
            line += f" ({oid_name(decode_oid(node.value))})"
        out.append(line)
        if node.children:
            out.extend(
                render_asn1(node.children, indent=indent + 2, base=offset + node.header_len)
            )
    return out


def render_oid(node: Node) -> list[str]:
    """``pFo``: the OID the block encodes."""
    return [f"{decode_oid(node.value)} ({oid_name(decode_oid(node.value))})"]


def _find(node: Node, tag_no: int, *, index: int = 0) -> Node | None:
    """The index-th child with the given universal tag number."""
    matches = [child for child in node.children if child.tag_class == 0 and child.tag_no == tag_no]
    return matches[index] if index < len(matches) else None


def _children_of_class(node: Node, tag_no: int) -> list[Node]:
    return [child for child in node.children if child.tag_class == 2 and child.tag_no == tag_no]


def _name_lines(name_node: Node, label: str) -> list[str]:
    parts = []
    for rdn_set in name_node.children:  # SET of AttributeTypeAndValue
        for atv in rdn_set.children:  # SEQUENCE { OID, value }
            if not atv.children:
                continue
            oid_node, value_node = atv.children[0], atv.children[-1]
            dotted = decode_oid(oid_node.value) if oid_node.tag_no == 6 else ""
            key = oid_name(dotted) if dotted else oid_node.name()
            text = value_node.value.decode("utf-8", errors="replace")
            parts.append(f"{key}={text}")
    return [f"{label}: {', '.join(parts)}"] if parts else []


def render_x509(root: Node) -> list[str]:
    """``pFx``: the certificate's readable fields, r2's ``key: value`` rows."""
    if root.tag_no != 16 or not root.children:
        raise UsageError("pFx: not a certificate (expected a SEQUENCE)")
    tbs = _find(root, 16)
    if tbs is None:
        raise UsageError("pFx: no tbsCertificate SEQUENCE")
    out: list[str] = []
    serial = _find(tbs, 2)
    if serial is not None:
        out.append(f"serial: {_digest(serial.value)}")
    sigalg = _find(tbs, 6)
    if sigalg is not None:
        dotted = decode_oid(sigalg.value)
        out.append(f"signatureAlgorithm: {oid_name(dotted)} ({dotted})")
    # tbs order: [version], serial, sigAlg, issuer, validity, subject, ...
    names: list[Node] = []
    validity: Node | None = None
    for child in tbs.children:
        if child.tag_class != 0 or child.tag_no != 16:
            continue
        kid_tags = {grand.tag_no for grand in child.children if grand.tag_class == 0}
        if kid_tags and kid_tags <= {17}:
            names.append(child)  # a Name is SEQUENCEs of SETs of AttributeTypeAndValue
        elif kid_tags and kid_tags <= {23, 24}:
            validity = child
    if len(names) >= 1:
        out.extend(_name_lines(names[0], "issuer"))
    if len(names) >= 2:
        out.extend(_name_lines(names[1], "subject"))
    if validity is not None:
        times = [
            grand.value.decode("ascii", errors="replace")
            for grand in validity.children
            if grand.tag_no in (23, 24)
        ]
        if len(times) >= 2:
            out.append(f"notBefore: {times[0]}")
            out.append(f"notAfter: {times[1]}")
    return out


def render_pkcs7(root: Node) -> list[str]:
    """``pFp``: the PKCS#7 contentInfo's top-level fields."""
    if root.tag_no != 16 or not root.children:
        raise UsageError("pFp: not a PKCS#7 structure (expected a SEQUENCE)")
    content_type = _find(root, 6)
    if content_type is None:
        raise UsageError("pFp: no contentType OID")
    dotted = decode_oid(content_type.value)
    out = [f"contentType: {oid_name(dotted)} ({dotted})"]
    oid_children = _children_of_class(root, 0)
    if oid_children:
        content = oid_children[0]  # the [0] EXPLICIT wrapping signedData
        signed = next(
            (c for c in content.children if c.tag_class == 0 and c.tag_no == 16),
            content,
        )
        certs = _children_of_class(signed, 0)
        if certs:
            out.append(f"certificates: {len(certs)}")
        if any(c.tag_class == 0 and c.tag_no == 16 for c in signed.children):
            out.append("signerInfos: 1")
    return out


def node_json(node: Node, *, base: int = 0) -> dict[str, Any]:
    """``pFaj``: the tree as JSON (stable key set, absolute offsets)."""
    offset = base + node.offset
    payload: dict[str, Any] = {
        "tag": node.name(),
        "tag_class": node.tag_class,
        "constructed": node.constructed,
        "offset": offset,
        "header_len": node.header_len,
        "length": len(node.value),
        "value_hex": _digest(node.value, limit=32),
    }
    if node.tag_no == 6 and node.tag_class == 0:
        payload["oid"] = decode_oid(node.value)
    if node.children:
        child_base = offset + node.header_len
        payload["children"] = [node_json(child, base=child_base) for child in node.children]
    return payload


def dumps(nodes: list[Node]) -> str:
    return json.dumps([node_json(node) for node in nodes], indent=2)
