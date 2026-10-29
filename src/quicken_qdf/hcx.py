"""Decode native currency-history records after verifying their C-Index tree."""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass

from .cindex import HEADER_SIZE as HEADER_SIZE
from .cindex import NODE_SIZE as NODE_SIZE
from .cindex import CIndex
from .cindex import CIndexEntry as HCXIndexRecord
from .cindex import CIndexNode as HCXNode
from .format import FormatError
from .format import u32 as _u32

__all__ = ["HCX", "HEADER_SIZE", "NODE_SIZE", "HCXIndexRecord", "HCXNode", "HCXRecord"]


@dataclass(frozen=True, slots=True)
class HCXRecord:
    record_number: int
    currency_ref: int
    packed_date: int
    rate: float
    flags: int
    payload: bytes
    page_number: int
    page_offset: int


class HCX(CIndex):
    """Validate a supported history image, retaining its complete original bytes."""

    def __init__(self, original: bytes) -> None:
        try:
            super().__init__(original)
            self.records: list[HCXRecord] = []
            self._decode_records()
        except FormatError as error:
            raise FormatError(f"HCX: {error}") from error

    def _decode_records(self) -> None:
        leaves = [entry for entry in self.index_records if self.nodes[entry.node_number].level == 0]
        by_index: dict[int, dict[int, HCXIndexRecord]] = {}
        for entry in leaves:
            if entry.index_number not in (1, 2, 3, 49):
                continue
            indexed = by_index.setdefault(entry.index_number, {})
            if entry.record_number in indexed:
                raise FormatError("HCX duplicate/continued history records are unsupported")
            indexed[entry.record_number] = entry
        data_entries = by_index.get(49, {})
        if len(data_entries) != self.record_count:
            raise FormatError("HCX history record count disagrees with header")
        primary_keys: set[tuple[int, int]] = set()
        for number, entry in sorted(data_entries.items()):
            if entry.key != b"\0" or entry.duplicate != 0x80:
                raise FormatError("Unsupported HCX history key or continuation encoding")
            payload = entry.payload
            if len(payload) < 7:
                raise FormatError("HCX history payload is truncated")
            fields: dict[int, int] = {}
            checksum = 0
            for value in payload[4:]:
                checksum = ((checksum + value) * 2) & 0xFF
            if checksum != payload[2]:
                raise FormatError("HCX history payload checksum mismatch")
            position = 5
            previous_tag = -1
            while True:
                if position + 2 > len(payload):
                    raise FormatError("HCX tagged payload has no terminator")
                tag = struct.unpack_from("<H", payload, position)[0]
                position += 2
                if tag == 0xFFFF:
                    break
                if tag not in (0, 1, 2, 3, 4) or tag <= previous_tag:
                    raise FormatError("HCX tagged payload has an unknown or unordered field")
                previous_tag = tag
                if tag == 0:
                    continue
                if position + 4 > len(payload):
                    raise FormatError("HCX tagged field is truncated")
                fields[tag] = _u32(payload, position)
                position += 4
            if position != len(payload) or not {1, 2} <= fields.keys():
                raise FormatError(
                    "HCX tagged payload has trailing bytes or missing required fields"
                )
            rate = struct.unpack("<f", struct.pack("<I", fields.get(3, 0)))[0]
            if not math.isfinite(rate):
                raise FormatError("HCX exchange rate is not finite")
            record = HCXRecord(
                number,
                fields[1],
                fields[2],
                rate,
                fields.get(4, 0),
                payload,
                entry.node_number,
                entry.node_offset,
            )
            primary_key = (record.currency_ref, record.packed_date)
            if primary_key in primary_keys:
                raise FormatError("HCX unique currency/date key is duplicated")
            primary_keys.add(primary_key)
            self.records.append(record)
            expected = {
                1: bytes([8]) + struct.pack("<II", record.currency_ref, record.packed_date),
                2: struct.pack("<I", record.currency_ref),
                3: struct.pack("<I", record.packed_date),
            }
            for index, key in expected.items():
                other = by_index.get(index, {}).get(number)
                if other is None or other.key != key or other.payload:
                    raise FormatError("HCX history values disagree with their secondary index")
        for index in (1, 2, 3):
            if set(by_index.get(index, {})) != set(data_entries):
                raise FormatError("HCX index references missing history records")
