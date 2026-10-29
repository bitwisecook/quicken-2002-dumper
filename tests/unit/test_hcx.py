"""Synthetic C-Index containers, independent of private/vendor file bytes."""

from __future__ import annotations

import hashlib
import json
import struct
import unittest
from pathlib import Path
from typing import TypedDict, cast

from quicken_qdf.format import FormatError
from quicken_qdf.hcx import HCX, HEADER_SIZE, NODE_SIZE


class Segment(TypedDict):
    offset: int
    hex: str


class Expected(TypedDict):
    record_count: int
    node_count: int
    index_record_count: int
    rate: float
    flags: int


class Fixture(TypedDict):
    name: str
    byte_count: int
    sha256: str
    segments: list[Segment]
    expected: Expected


class FixtureFile(TypedDict):
    cases: list[Fixture]


def _payload(
    *, rate: float | None = 1.25, flags: int | None = None, extra: tuple[int, int] | None = None
) -> bytes:
    body = bytearray(b"\x00\x00\x00")  # state byte, then zero-length field 0
    for tag, value in [(1, 7), (2, 0x0068070B)]:
        body.extend(struct.pack("<HI", tag, value))
    if rate is not None:
        body.extend(struct.pack("<Hf", 3, rate))
    if flags is not None:
        body.extend(struct.pack("<HI", 4, flags))
    if extra is not None:
        body.extend(struct.pack("<HI", *extra))
    body.extend(b"\xff\xff")
    checksum = 0
    for value in body:
        checksum = ((checksum + value) * 2) & 255
    # Nonzero upper checksum byte deliberately verifies native low-byte scope.
    return struct.pack("<HH", 0xBEEF, 0xA500 | checksum) + body


def make_index_entry(
    index: int, key: bytes, payload: bytes = b"", *, child: int | None = None
) -> bytes:
    body = bytes([index, 0x80]) + struct.pack("<I", 42) + key + payload
    if child is not None:
        body += struct.pack("<I", child)
    return bytes([len(body)]) + body


def make_index_node(
    entries: list[bytes], *, level: int = 0, left: int = 0, following: int = -1, previous: int = -1
) -> bytes:
    body = b"".join(entries)
    header = struct.pack(
        "<IiiHHH", left, following, previous, level, len(entries), NODE_SIZE - 18 - len(body)
    )
    return (header + body).ljust(NODE_SIZE, b"\0")


def make_hcx(
    *,
    populated: bool = True,
    split: bool = False,
    rate: float | None = 1.25,
    flags: int | None = None,
    extra: tuple[int, int] | None = None,
) -> bytes:
    header = bytearray(HEADER_SIZE)
    for offset, value in {
        4: 0x56,
        0x10: 0x41,
        0x14: 0x4C,
        0x18: 0x49,
        0x20: 0x44,
        0x28: 0x41,
        0x30: 0x54,
        0x38: 0x31,
    }.items():
        struct.pack_into("<I", header, offset, value)
    struct.pack_into("<I", header, 8, 1)
    header[0xC1:0xC4] = bytes([8, 5, 5])
    header[0xF2] = 2
    allocated = 3 if split else 1
    for offset, value in [
        (0x0C, 2 if split else 0),
        (0x1C, 2 if split else 1),
        (0x24, allocated),
        (0x34, allocated + 1),
        (0x3C, 0xFFFFFFFF),
        (0x44, int(populated)),
        (0x2C, 43),
    ]:
        struct.pack_into("<I", header, offset, value)
    entries = []
    if populated:
        entries = [
            make_index_entry(1, b"\x08" + struct.pack("<II", 7, 0x0068070B)),
            make_index_entry(2, struct.pack("<I", 7)),
            make_index_entry(3, struct.pack("<I", 0x0068070B)),
            make_index_entry(49, b"\0", _payload(rate=rate, flags=flags, extra=extra)),
        ]
    if split:
        nodes = [
            make_index_node(entries[:2], following=1),
            make_index_node(entries[2:], previous=0),
            make_index_node([make_index_entry(2, struct.pack("<I", 7), child=1)], level=1),
        ]
    else:
        nodes = [make_index_node(entries)]
    return bytes(header) + b"".join(nodes) + bytes(NODE_SIZE)


class HCXTests(unittest.TestCase):
    def test_frozen_compatibility_vectors(self) -> None:
        path = Path(__file__).resolve().parents[1] / "vectors" / "hcx_format1.json"
        document = cast(FixtureFile, json.loads(path.read_text()))
        self.assertGreaterEqual(len(document["cases"]), 3)
        for fixture in document["cases"]:
            with self.subTest(fixture=fixture["name"]):
                source = bytearray(fixture["byte_count"])
                for segment in fixture["segments"]:
                    data = bytes.fromhex(segment["hex"])
                    offset = segment["offset"]
                    source[offset : offset + len(data)] = data
                self.assertEqual(hashlib.sha256(source).hexdigest(), fixture["sha256"])
                hcx = HCX(bytes(source))
                expected = fixture["expected"]
                self.assertEqual(len(hcx.records), expected["record_count"])
                self.assertEqual(len(hcx.nodes), expected["node_count"])
                self.assertEqual(len(hcx.index_records), expected["index_record_count"])
                self.assertEqual(hcx.header + b"".join(n.data for n in hcx.nodes), source)
                for record in hcx.records:
                    self.assertEqual(record.rate, expected["rate"])
                    self.assertEqual(record.flags, expected["flags"])

    def test_primary_currency_date_pair_is_unique(self) -> None:
        source = make_hcx()
        hcx = HCX(source)
        entries = [entry.raw for entry in hcx.index_records]
        for entry in hcx.index_records:
            duplicate = bytearray(entry.raw)
            struct.pack_into("<I", duplicate, 3, 43)
            entries.append(bytes(duplicate))
        header = bytearray(hcx.header)
        struct.pack_into("<I", header, 0x44, 2)
        duplicate_file = bytes(header) + make_index_node(entries) + bytes(NODE_SIZE)
        with self.assertRaisesRegex(FormatError, "unique currency/date"):
            HCX(duplicate_file)

    def test_empty_history_preserves_preallocated_bytes(self) -> None:
        source = make_hcx(populated=False)
        hcx = HCX(source)
        self.assertEqual(hcx.records, [])
        self.assertEqual(hcx.index_records, [])
        self.assertEqual(b"".join([hcx.header] + [node.data for node in hcx.nodes]), source)
        self.assertEqual([node.active for node in hcx.nodes], [True, False])

    def test_internal_tree_and_secondary_indexes_recover_one_record(self) -> None:
        hcx = HCX(make_hcx(split=True, flags=8))
        (record,) = hcx.records
        self.assertEqual(
            (
                record.record_number,
                record.currency_ref,
                record.packed_date,
                record.rate,
                record.flags,
            ),
            (42, 7, 0x0068070B, 1.25, 8),
        )
        self.assertEqual(record.page_number, 1)
        self.assertEqual(len(hcx.index_records), 5)
        self.assertEqual([node.active for node in hcx.nodes], [True, True, True, False])
        self.assertEqual(record.payload, _payload(flags=8))

    def test_native_zero_suppression_and_checksum_scope(self) -> None:
        (record,) = HCX(make_hcx(rate=None)).records
        self.assertEqual((record.rate, record.flags), (0.0, 0))
        self.assertEqual(record.payload[3], 0xA5)

    def test_deleted_nodes_are_retained_and_free_list_is_checked(self) -> None:
        source = bytearray(make_hcx())
        struct.pack_into("<I", source, 0x24, 2)
        struct.pack_into("<i", source, 0x3C, 1)
        struct.pack_into("<i", source, HEADER_SIZE + NODE_SIZE + 4, -1)
        hcx = HCX(bytes(source))
        self.assertEqual(len(hcx.records), 1)
        self.assertFalse(hcx.nodes[1].active)
        for target in (0, 1, 99):
            with self.subTest(free_next=target):
                damaged = bytearray(source)
                struct.pack_into("<i", damaged, HEADER_SIZE + NODE_SIZE + 4, target)
                with self.assertRaisesRegex(FormatError, "free list"):
                    HCX(bytes(damaged))

    def test_signed_finite_rate_is_preserved(self) -> None:
        (record,) = HCX(make_hcx(rate=-2.5)).records
        self.assertEqual(record.rate, -2.5)

    def test_damaged_header_and_tree_are_rejected(self) -> None:
        cases = [
            ("signature", 4, 0),
            ("byte order", 8, 2),
            ("root", 0x0C, 99),
            ("height", 0x1C, 100),
            ("allocated count", 0x24, 100),
            ("capacity", 0x34, 100),
            ("record count", 0x44, 2),
            ("cycle", HEADER_SIZE + 2 * NODE_SIZE, 2),
            ("sibling", HEADER_SIZE + 4, 100),
        ]
        for name, offset, value in cases:
            with self.subTest(name=name):
                source = bytearray(make_hcx(split=True))
                struct.pack_into("<I", source, offset, value)
                with self.assertRaises(FormatError):
                    HCX(bytes(source))

    def test_wrong_internal_separator_is_rejected(self) -> None:
        source = bytearray(make_hcx(split=True))
        source[HEADER_SIZE + 2 * NODE_SIZE + 18 + 7] ^= 1
        with self.assertRaisesRegex(FormatError, "separator"):
            HCX(bytes(source))

    def test_secondary_index_corruption_is_rejected(self) -> None:
        source = bytearray(make_hcx())
        source[HEADER_SIZE + 18 + 7 + 1] ^= 1
        with self.assertRaisesRegex(FormatError, "secondary index"):
            HCX(bytes(source))

    def test_bad_tag_checksum_nonfinite_and_truncation_are_rejected(self) -> None:
        with self.assertRaisesRegex(FormatError, "unknown"):
            HCX(make_hcx(extra=(9, 1)))
        with self.assertRaisesRegex(FormatError, "finite"):
            HCX(make_hcx(rate=float("nan")))
        source = bytearray(make_hcx())
        # Locate the tagged payload through the decoded physical record.
        hcx = HCX(bytes(source))
        entry = next(entry for entry in hcx.index_records if entry.index_number == 49)
        payload_start = HEADER_SIZE + entry.node_offset + 8
        source[payload_start + len(entry.payload) - 3] ^= 1
        with self.assertRaisesRegex(FormatError, "checksum"):
            HCX(bytes(source))
        with self.assertRaisesRegex(FormatError, "size"):
            HCX(make_hcx()[:-1])

    def test_entry_and_free_space_must_fit_exactly(self) -> None:
        for offset, value in [(HEADER_SIZE + 18, 255), (HEADER_SIZE + NODE_SIZE - 1, 1)]:
            with self.subTest(offset=offset):
                source = bytearray(make_hcx())
                source[offset] = value
                with self.assertRaises(FormatError):
                    HCX(bytes(source))


if __name__ == "__main__":
    unittest.main()
