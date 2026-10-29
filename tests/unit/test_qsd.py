"""Synthetic sequential settings containers; no personal or vendor records."""

from __future__ import annotations

import hashlib
import json
import struct
import unittest
from pathlib import Path
from typing import TypedDict, cast

from quicken_qdf.format import FormatError
from quicken_qdf.qsd import HEADER_SIZE, QSD, RECORD_HEADER_SIZE


class Segment(TypedDict):
    offset: int
    hex: str


class Fixture(TypedDict):
    byte_count: int
    sha256: str
    segments: list[Segment]
    record_count: int
    active_count: int


def _record(kind: int, reference: int, name: str, payload: bytes, *, deleted: int = 0) -> bytes:
    header = bytearray(RECORD_HEADER_SIZE)
    struct.pack_into("<HIHHH", header, 0, 0xFFFF, len(payload), kind, reference, deleted)
    encoded = name.encode("cp1252")
    header[12 : 12 + len(encoded)] = encoded
    return bytes(header) + payload + b"\xff\xff"


def make_qsd() -> bytes:
    header = bytearray(HEADER_SIZE)
    text = b"QW Ver. 3.00.00 + TEST.QSD"
    header[: len(text)] = text
    header[32:35] = b"\x03\0\0"
    header[40] = 3
    return (
        bytes(header)
        + _record(576, 7, "Example preferences", b"old value", deleted=1)
        + _record(576, 7, "Example preferences", b"current value\0\xff")
        + _record(65000, 99, "Unknown setting", b"\x80\0\x01\xff")
        + _record(1, 0, "EOF RECORD TYPE", b"\0\0")
    )


class QSDTests(unittest.TestCase):
    def test_frozen_fixture(self) -> None:
        path = Path(__file__).resolve().parents[1] / "vectors" / "qsd_format3.json"
        fixture = cast(Fixture, json.loads(path.read_text()))
        source = bytearray(fixture["byte_count"])
        for segment in fixture["segments"]:
            data = bytes.fromhex(segment["hex"])
            source[segment["offset"] : segment["offset"] + len(data)] = data
        self.assertEqual(hashlib.sha256(source).hexdigest(), fixture["sha256"])
        parsed = QSD(bytes(source))
        self.assertEqual(len(parsed.records), fixture["record_count"])
        self.assertEqual(len(parsed.active_records), fixture["active_count"])
        self.assertEqual(
            parsed.header + b"".join(r.header + r.payload + r.trailer for r in parsed.records),
            source,
        )

    def test_deleted_versions_and_unknown_bodies_are_lossless(self) -> None:
        original = make_qsd()
        parsed = QSD(original)
        self.assertEqual([r.number for r in parsed.active_records], [1, 2])
        self.assertEqual(parsed.records[0].legacy_id, parsed.records[1].legacy_id)
        self.assertTrue(parsed.records[0].deleted)
        self.assertEqual(parsed.records[2].record_type, 65000)
        self.assertEqual(parsed.records[2].payload, b"\x80\0\x01\xff")
        self.assertEqual(parsed.records[-1].file_offset + 68, len(original))
        self.assertEqual(parsed.original, original)

    def test_diagnostic_filename_does_not_need_to_match_input(self) -> None:
        source = bytearray(make_qsd())
        source[18:26] = b"ELSE.QSD"
        parsed = QSD(bytes(source))
        self.assertEqual(len(parsed.active_records), 2)

    def test_rejects_damaged_boundaries_and_deletion_state(self) -> None:
        changes = [
            (128, b"\0\0"),
            (130, struct.pack("<I", 0xFFFFFFFF)),
            (138, b"\x02\0"),
            (128 + 64 + len(b"old value"), b"\0\0"),
            (128 + 12, b"x" * 32),
        ]
        for offset, value in changes:
            with self.subTest(offset=offset):
                source = bytearray(make_qsd())
                source[offset : offset + len(value)] = value
                with self.assertRaises(FormatError):
                    QSD(bytes(source))

    def test_missing_eof_truncation_and_trailing_bytes_fail(self) -> None:
        original = make_qsd()
        for source in [original[:127], original[:-1], original[:-68], original + b"\0"]:
            with self.subTest(size=len(source)), self.assertRaises(FormatError):
                QSD(source)

    def test_encrypted_and_other_versions_fail_explicitly(self) -> None:
        for offset, value in [(32, 4), (32, 2), (40, 9)]:
            with self.subTest(offset=offset, value=value):
                source = bytearray(make_qsd())
                source[offset] = value
                with self.assertRaises(FormatError):
                    QSD(bytes(source))


if __name__ == "__main__":
    unittest.main()
