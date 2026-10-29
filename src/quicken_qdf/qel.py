"""Recover QEL's C-Index logical objects without guessing their financial fields."""

from dataclasses import dataclass

from .cindex import CIndex, CIndexEntry
from .format import FormatError


@dataclass(frozen=True, slots=True)
class QELRecord:
    record_number: int
    index1_key: bytes
    index2_key: bytes
    payload: bytes
    parts: tuple[CIndexEntry, ...]


class QEL(CIndex):
    """Join native continuation fragments and verify each serialized object.

    The application descriptor needed to interpret QEL's heterogeneous tagged
    values is not established. Keys and complete objects remain explicit bytes.
    """

    def __init__(self, original: bytes) -> None:
        try:
            super().__init__(original)
            self.records: list[QELRecord] = []
            self._decode_objects()
        except FormatError as error:
            raise FormatError(f"QEL: {error}") from error

    def _decode_objects(self) -> None:
        if not self.header[0x5C:0x60] == b"QEL ":
            raise FormatError("Unsupported QEL application header")
        parts: dict[int, list[CIndexEntry]] = {}
        indexes: dict[int, dict[int, CIndexEntry]] = {1: {}, 2: {}}
        for entry in self.index_records:
            if self.nodes[entry.node_number].level:
                continue
            if entry.index_number == 49:
                if entry.key != b"\0":
                    raise FormatError("Unsupported QEL data-record key")
                parts.setdefault(entry.record_number, []).append(entry)
            elif entry.index_number in indexes:
                index = indexes[entry.index_number]
                if entry.record_number in index or entry.payload or entry.duplicate != 0x80:
                    raise FormatError("QEL lookup index has duplicate or invalid entries")
                index[entry.record_number] = entry
            else:
                raise FormatError(f"Unsupported QEL index {entry.index_number}")
        if len(parts) != self.record_count or any(set(i) != set(parts) for i in indexes.values()):
            raise FormatError("QEL data count or lookup indexes disagree")
        for number, fragments in sorted(parts.items()):
            fragments.sort(key=lambda entry: entry.duplicate & 0x7F)
            flags = [entry.duplicate for entry in fragments]
            expected = [*range(len(fragments) - 1), 0x80 | (len(fragments) - 1)]
            if len(fragments) > 128 or flags != expected:
                raise FormatError("QEL record has missing, duplicate or unterminated fragments")
            payload = b"".join(entry.payload for entry in fragments)
            if len(payload) < 7 or payload[-2:] != b"\xff\xff":
                raise FormatError("QEL serialized object is truncated or unterminated")
            checksum = 0
            for value in payload[4:]:
                checksum = ((checksum + value) * 2) & 0xFF
            if checksum != payload[2]:
                raise FormatError("QEL serialized object checksum mismatch")
            self.records.append(
                QELRecord(
                    number,
                    indexes[1][number].key,
                    indexes[2][number].key,
                    payload,
                    tuple(fragments),
                )
            )
