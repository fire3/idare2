"""Tests for the client-side DER/ASN.1 parsing behind ``pF``."""

from __future__ import annotations

import json

import pytest

from idare2 import asn1
from idare2.errors import UsageError

# -- a tiny DER encoder: fixtures stay deterministic and dependency-free ----


def _tlv(tag: int, value: bytes, *, constructed: bool = False) -> bytes:
    first = tag | (0x20 if constructed else 0)
    length = len(value)
    if length < 0x80:
        return bytes([first, length]) + value
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([first, 0x80 | len(encoded)]) + encoded + value


def _oid(dotted: str) -> bytes:
    arcs = [int(part) for part in dotted.split(".")]
    body = bytearray([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunk = bytearray([arc & 0x7F])
        arc >>= 7
        while arc:
            chunk.insert(0, 0x80 | (arc & 0x7F))
            arc >>= 7
        body += chunk
    return _tlv(0x06, bytes(body))


def _int(value: int) -> bytes:
    body = value.to_bytes(max((value.bit_length() + 7) // 8, 1), "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return _tlv(0x02, body)


def _name(cn: str) -> bytes:
    atv = _tlv(0x30, _oid("2.5.4.3") + _tlv(0x0C, cn.encode()), constructed=True)
    rdn = _tlv(0x31, atv, constructed=True)
    return _tlv(0x30, rdn, constructed=True)


def _cert(serial: int = 0x1234) -> bytes:
    tbs = _tlv(
        0x30,
        _int(serial)
        + _oid("1.2.840.113549.1.1.11")
        + _name("Test Issuer")
        + _tlv(
            0x30,
            _tlv(0x17, b"240101000000Z") + _tlv(0x17, b"250101000000Z"),
            constructed=True,
        )
        + _name("Test Subject"),
        constructed=True,
    )
    return _tlv(0x30, tbs + _oid("1.2.840.113549.1.1.11") + _tlv(0x03, b"\x00" + b"\x11" * 8), constructed=True)


# -- parser -----------------------------------------------------------------


def test_parse_walks_a_simple_tree() -> None:
    data = _cert()
    nodes = asn1.parse(data)
    assert len(nodes) == 1
    root = nodes[0]
    assert root.name() == "SEQUENCE" and root.constructed
    assert root.total_len == len(data)
    # tbsCertificate, signatureAlgorithm, signatureValue
    assert [child.name() for child in root.children] == [
        "SEQUENCE",
        "OID",
        "BIT_STRING",
    ]


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (_tlv(0x30, b"\x01")[:-1], "truncated"),
        (bytes([0x30, 0x80, 0x00]), "BER indefinite"),
        (bytes([0x30, 0x82, 0x00, 0x02, 1, 2]), "non-minimal"),
        (bytes([0x1F, 0x02, 0x01, 0x00]), "multi-byte tags"),
        (bytes([0x30, 0x03, 0x01]), "truncated"),
    ],
)
def test_parse_rejects_non_der(data: bytes, message: str) -> None:
    with pytest.raises(UsageError) as excinfo:
        asn1.parse(data)
    assert message in str(excinfo.value)


def test_parse_rejects_deep_nesting() -> None:
    data = b""
    for _ in range(asn1.MAX_DEPTH + 1):
        data = _tlv(0x30, data, constructed=True)
    with pytest.raises(UsageError) as excinfo:
        asn1.parse(data)
    assert "nesting deeper" in str(excinfo.value)


def test_decode_oid_matches_r2_arcs() -> None:
    assert asn1.decode_oid(bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B])) == (
        "1.2.840.113549.1.1.11"
    )
    assert asn1.decode_oid(bytes([0x55, 0x04, 0x03])) == "2.5.4.3"
    with pytest.raises(UsageError):
        asn1.decode_oid(b"")


def test_oid_name_known_and_unknown() -> None:
    assert asn1.oid_name("1.2.840.113549.1.1.11") == "sha256WithRSAEncryption"
    assert asn1.oid_name("1.2.3.4.5") == "1.2.3.4.5"


# -- renderers --------------------------------------------------------------


def test_render_asn1_shows_offsets_tags_and_digests() -> None:
    lines = asn1.render_asn1(asn1.parse(_cert()))
    assert lines[0].startswith("0x0: cons <SEQUENCE> len=")
    assert any("<OID>" in line and "sha256WithRSAEncryption" in line for line in lines)
    assert lines[0].endswith("")  # a constructed node carries no digest


def test_render_x509_extracts_the_read_fields() -> None:
    lines = asn1.render_x509(asn1.parse(_cert(serial=0x5678))[0])
    text = "\n".join(lines)
    assert "signatureAlgorithm: sha256WithRSAEncryption" in text
    assert "issuer: CN=Test Issuer" in text
    assert "subject: CN=Test Subject" in text
    assert "notBefore: 240101000000Z" in text
    assert "notAfter: 250101000000Z" in text


def test_render_x509_rejects_non_certificates() -> None:
    with pytest.raises(UsageError):
        asn1.render_x509(asn1.parse(_int(5))[0])


def test_render_oid() -> None:
    nodes = asn1.parse(_oid("2.5.4.3"))
    assert asn1.render_oid(nodes[0]) == ["2.5.4.3 (CN)"]


def test_json_tree_is_stable() -> None:
    payload = json.loads(asn1.dumps(asn1.parse(_cert())))
    root = payload[0]
    assert root["tag"] == "SEQUENCE"
    assert root["offset"] == 0
    # children carry absolute offsets (the outer header is 2 bytes here)
    assert root["children"][0]["offset"] == 2
    assert root["children"][0]["children"][0]["offset"] == 4
    assert len(root["children"]) == 3
    oid_child = root["children"][1]
    assert oid_child["oid"] == "1.2.840.113549.1.1.11"


def test_render_pkcs7() -> None:
    # signedData: SEQUENCE { contentType OID, [0] SEQUENCE { ... [0] certs } }
    signed = _tlv(
        0x30,
        _tlv(0xA0, _cert(), constructed=True) + _tlv(0x30, b"", constructed=True),
        constructed=True,
    )
    nodes = asn1.parse(
        _tlv(
            0x30,
            _oid("1.2.840.113549.1.7.2") + _tlv(0xA0, signed, constructed=True),
            constructed=True,
        )
    )
    lines = asn1.render_pkcs7(nodes[0])
    assert "contentType: signedData" in lines[0]
    assert "certificates: 1" in "\n".join(lines)
    assert "signerInfos: 1" in "\n".join(lines)
