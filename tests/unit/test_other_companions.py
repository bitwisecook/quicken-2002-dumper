"""C-Index online-object reassembly and bounded index-cache extraction."""

import hashlib
import json
import struct
import unittest
from pathlib import Path
from typing import TypedDict, cast

from quicken_qdf.format import FormatError
from quicken_qdf.idx import IDX
from quicken_qdf.qel import QEL
from tests.unit.test_hcx import make_hcx, make_index_entry, make_index_node


class Segment(TypedDict):
    offset: int
    hex: str


class Fixture(TypedDict):
    format: str
    byte_count: int
    sha256: str
    segments: list[Segment]


def make_qel(*, broken_parts: bool = False) -> bytes:
    header = bytearray(make_hcx(populated=False)[:1024])
    header[0x5C:0x64] = b"QEL TEST"
    struct.pack_into("<I", header, 0x44, 1)
    header[0xC1:0xC4] = bytes([5, 0, 0])
    payload = b"\x12\x34\0\xa5\0" + b"opaque online object" * 14 + b"\xff\xff"
    checksum = 0
    for value in payload[4:]:
        checksum = ((checksum + value) * 2) & 255
    payload = payload[:2] + bytes([checksum]) + payload[3:]
    part1 = bytearray(make_index_entry(49, b"\0", payload[:200]))
    part2 = bytearray(make_index_entry(49, b"\0", payload[200:]))
    part1[2] = 1 if broken_parts else 0
    part2[2] = 0x81
    entries = [
        make_index_entry(1, struct.pack("<I", 99)),
        make_index_entry(2, b"SYNTHETIC\0"),
        bytes(part1),
        bytes(part2),
    ]
    return bytes(header) + make_index_node(entries) + bytes(2048)


def make_idx() -> bytes:
    index_header = bytearray(32)
    struct.pack_into("<I", index_header, 4, 5)
    struct.pack_into("<I", index_header, 12, 2)
    master_header = bytearray(32)
    struct.pack_into("<I", master_header, 8, 4)
    struct.pack_into("<I", master_header, 12, 3)
    directory = struct.pack("<8I", 32, 32, 64, 10, 74, 32, 106, 12)
    return directory + bytes(index_header) + b"abcdefghij" + bytes(master_header) + b"master-array"


class OtherCompanionTests(unittest.TestCase):
    def test_frozen_formats(self) -> None:
        path = Path(__file__).resolve().parents[1] / "vectors" / "other_companions.json"
        cases = cast(list[Fixture], json.loads(path.read_text()))
        for case in cases:
            with self.subTest(format=case["format"]):
                source = bytearray(case["byte_count"])
                for segment in case["segments"]:
                    data = bytes.fromhex(segment["hex"])
                    source[segment["offset"] : segment["offset"] + len(data)] = data
                self.assertEqual(hashlib.sha256(source).hexdigest(), case["sha256"])
                if case["format"] == "qel":
                    qel = QEL(bytes(source))
                    self.assertEqual(len(qel.records), 1)
                    self.assertEqual(len(qel.records[0].parts), 2)
                else:
                    idx = IDX(bytes(source))
                    self.assertEqual(len(idx.segments), 4)
                    self.assertEqual(idx.header + b"".join(s.data for s in idx.segments), source)

    def test_qel_reassembles_continued_objects(self) -> None:
        qel = QEL(make_qel())
        record = qel.records[0]
        self.assertEqual((record.record_number, record.index2_key), (42, b"SYNTHETIC\0"))
        self.assertIn(b"opaque online object", record.payload)
        self.assertEqual(record.payload, b"".join(p.payload for p in record.parts))
        with self.assertRaisesRegex(FormatError, "fragments"):
            QEL(make_qel(broken_parts=True))

    def test_qel_payload_checksum_and_count_are_checked(self) -> None:
        original = make_qel()
        for mutation in ("count", "checksum"):
            source = bytearray(original)
            if mutation == "count":
                source[0x44] = 2
            else:
                entry = QEL(original).records[0].parts[-1]
                offset = 1024 + entry.node_offset + 8 + len(entry.payload) - 3
                source[offset] ^= 1
            with self.assertRaises(FormatError):
                QEL(bytes(source))

    def test_idx_bounds_and_capacities_are_checked(self) -> None:
        original = make_idx()
        for offset, value in [(0, 31), (8, 32), (32 + 12, 999), (24, 9999)]:
            source = bytearray(original)
            struct.pack_into("<I", source, offset, value)
            with self.subTest(offset=offset), self.assertRaises(FormatError):
                IDX(bytes(source))
