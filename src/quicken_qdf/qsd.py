"""Read the unencrypted, sequential settings container used by legacy QSD.

Record bodies are settings-specific and remain opaque. Native ST readers use
the type, reference and name to find them; deleted versions and EOF remain in
the physical archive, rather than becoming current settings.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .format import FormatError

HEADER_SIZE = 128
RECORD_HEADER_SIZE = 64
_MARKER = b"\xff\xff"


@dataclass(frozen=True, slots=True)
class QSDRecord:
    number: int
    file_offset: int
    record_type: int
    legacy_id: int
    deleted: bool
    name: str
    name_bytes: bytes
    header: bytes
    payload: bytes
    trailer: bytes

    @property
    def is_eof(self) -> bool:
        return self.record_type == 1


class QSD:
    """Decode an immutable QW version-3 settings image without repairing it.

    Version-4 ST payload encryption exists in the native reader and is not
    implemented here. Unsupported versions, missing EOF, corrupt boundaries
    and noncanonical deletion states fail explicitly.
    """

    def __init__(self, original: bytes) -> None:
        self.original = bytes(original)
        if len(original) < HEADER_SIZE:
            raise FormatError("QSD file header is truncated")
        self.header = original[:HEADER_SIZE]
        if not self.header.startswith(b"QW Ver. "):
            raise FormatError("QSD header identification string is invalid")
        self.identification = self.header[:32].split(b"\0", 1)[0].decode("cp1252", errors="replace")
        self.major_version, self.minor_version, self.revision = self.header[32:35]
        if self.major_version == 4:
            raise FormatError("Encrypted QSD version-4 payloads are unsupported")
        if self.major_version != 3 or self.header[40] != 3:
            raise FormatError("Unsupported QSD sequential settings version")
        self.records: list[QSDRecord] = []
        position = HEADER_SIZE
        while position < len(original):
            if len(original) - position < RECORD_HEADER_SIZE + 2:
                raise FormatError("QSD record header or trailer is truncated")
            header = original[position : position + RECORD_HEADER_SIZE]
            if header[:2] != _MARKER:
                raise FormatError("QSD record header marker mismatch")
            size, kind, legacy_id, deleted = struct.unpack_from("<IHHH", header, 2)
            if deleted not in (0, 1):
                raise FormatError("Unsupported QSD deletion state")
            payload_start = position + RECORD_HEADER_SIZE
            payload_end = payload_start + size
            if payload_end + 2 > len(original):
                raise FormatError("QSD payload length exceeds file bounds")
            trailer = original[payload_end : payload_end + 2]
            if trailer != _MARKER:
                raise FormatError("QSD record trailer marker mismatch")
            name_bytes = header[12:44]
            if b"\0" not in name_bytes:
                raise FormatError("QSD record name has no terminator")
            record = QSDRecord(
                len(self.records),
                position,
                kind,
                legacy_id,
                bool(deleted),
                name_bytes.split(b"\0", 1)[0].decode("cp1252", errors="replace"),
                name_bytes,
                header,
                original[payload_start:payload_end],
                trailer,
            )
            self.records.append(record)
            position = payload_end + 2
            if record.is_eof:
                if record.deleted or record.payload != b"\0\0" or position != len(original):
                    raise FormatError("QSD EOF record is invalid or has trailing data")
                break
        if not self.records or not self.records[-1].is_eof:
            raise FormatError("QSD settings file has no EOF record")

    @property
    def active_records(self) -> list[QSDRecord]:
        """Current physical settings records, with deleted versions and EOF excluded."""
        return [record for record in self.records if not record.deleted and not record.is_eof]
