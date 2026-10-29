"""Recover the QDF index cache's directory and raw array segments."""

import struct
from dataclasses import dataclass

from .format import FormatError


@dataclass(frozen=True, slots=True)
class IDXSegment:
    number: int
    offset: int
    data: bytes


class IDX:
    """Decode bounded offset/length pairs, preserving opaque cache arrays.

    Index-array meanings depend on QDF schema metadata. These bytes are cache
    evidence, not independently recovered transactions or share prices.
    """

    def __init__(self, original: bytes) -> None:
        if len(original) < 32:
            raise FormatError("IDX directory is truncated")
        directory_size = struct.unpack_from("<I", original)[0]
        if directory_size < 32 or directory_size % 16 or directory_size > len(original):
            raise FormatError("Unsupported IDX directory extent")
        self.header = original[:directory_size]
        self.segments: list[IDXSegment] = []
        for number, (offset, length) in enumerate(struct.iter_unpack("<II", self.header)):
            if offset < directory_size or offset + length > len(original):
                raise FormatError("IDX segment exceeds file bounds")
            self.segments.append(IDXSegment(number, offset, original[offset : offset + length]))
        count = (len(self.segments) - 2) // 2
        for index in range(count):
            header, body = self.segments[index], self.segments[index + count]
            if len(header.data) != 32:
                raise FormatError("IDX index-array header is not 32 bytes")
            item_size = struct.unpack_from("<I", header.data, 4)[0]
            capacity = struct.unpack_from("<I", header.data, 12)[0]
            if item_size * capacity != len(body.data):
                raise FormatError("IDX index-array capacity disagrees with its segment")
        header, body = self.segments[-2:]
        if len(header.data) != 32:
            raise FormatError("IDX master-array header is not 32 bytes")
        item_size = struct.unpack_from("<I", header.data, 8)[0]
        capacity = struct.unpack_from("<I", header.data, 12)[0]
        if item_size * capacity != len(body.data):
            raise FormatError("IDX master-array capacity disagrees with its segment")
        end = directory_size
        for segment in sorted(self.segments, key=lambda segment: segment.offset):
            if segment.offset != end:
                raise FormatError("IDX segments overlap or leave an unexplained gap")
            end += len(segment.data)
        if end != len(original):
            raise FormatError("IDX has unexplained trailing bytes")
