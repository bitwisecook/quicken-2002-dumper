"""Immutable C-Index container shared by Quicken HCX and QEL readers."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .format import FormatError

HEADER_SIZE = 1024
NODE_SIZE = 2048
NODE_HEADER_SIZE = 18
_SIGNATURE = {
    4: 0x56,
    0x10: 0x41,
    0x14: 0x4C,
    0x18: 0x49,
    0x20: 0x44,
    0x28: 0x41,
    0x30: 0x54,
    0x38: 0x31,
}


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


@dataclass(frozen=True, slots=True)
class CIndexNode:
    number: int
    file_offset: int
    level: int
    left_child: int
    next_node: int
    previous_node: int
    entry_count: int
    free_bytes: int
    data: bytes
    active: bool


@dataclass(frozen=True, slots=True)
class CIndexEntry:
    node_number: int
    node_offset: int
    index_number: int
    duplicate: int
    record_number: int
    key: bytes
    payload: bytes
    child_node: int | None
    raw: bytes


class CIndex:
    """Decode one immutable little-endian C-Index image, failing on damaged links.

    ``header`` and every physical node include their original bytes. Only
    reachable B-tree nodes contribute logical entries; free/preallocated nodes
    are retained with ``active=False`` rather than interpreted as live history.
    """

    def __init__(self, original: bytes) -> None:
        self.original = bytes(original)
        if len(original) < HEADER_SIZE + NODE_SIZE or (len(original) - HEADER_SIZE) % NODE_SIZE:
            raise FormatError("C-Index size is not a header plus complete 2048-byte nodes")
        self.header = original[:HEADER_SIZE]
        if any(_u32(self.header, offset) != value for offset, value in _SIGNATURE.items()):
            raise FormatError("C-Index C-Index VALIDAT1 signature mismatch")
        if _u32(self.header, 8) != 1:
            raise FormatError("C-Index byte order is unsupported (expected little endian)")
        self.root_node = _u32(self.header, 0x0C)
        self.allocated_nodes = _u32(self.header, 0x24)
        self.capacity_nodes = _u32(self.header, 0x34)
        self.record_count = _u32(self.header, 0x44)
        physical_count = (len(original) - HEADER_SIZE) // NODE_SIZE
        if self.capacity_nodes != physical_count or not 1 <= self.allocated_nodes <= physical_count:
            raise FormatError("C-Index node counts disagree with physical file size")
        self.index_types = self.header[0xC0:0xF4]
        self.index_records: list[CIndexEntry] = []
        active: set[int] = set()
        raw_nodes: list[tuple[int, int, int, int, int, int]] = []
        for number in range(physical_count):
            offset = HEADER_SIZE + number * NODE_SIZE
            raw_nodes.append(struct.unpack_from("<IiiHHH", original, offset))

        def walk(number: int, expected_level: int | None = None) -> CIndexEntry | None:
            if not 0 <= number < self.allocated_nodes:
                raise FormatError("C-Index child points outside allocated nodes")
            if number in active:
                raise FormatError("C-Index node is cyclic or has multiple parents")
            active.add(number)
            left, following, previous, level, count, free = raw_nodes[number]
            if expected_level is not None and level != expected_level:
                raise FormatError("C-Index child level does not descend by one")
            if level >= self.allocated_nodes:
                raise FormatError("C-Index node level exceeds possible tree height")
            if free > NODE_SIZE - NODE_HEADER_SIZE or count > (NODE_SIZE - NODE_HEADER_SIZE) // 7:
                raise FormatError("C-Index node count/free-space header is invalid")
            for sibling in (following, previous):
                if sibling != -1 and not 0 <= sibling < self.allocated_nodes:
                    raise FormatError("C-Index sibling points outside allocated nodes")
            data = original[
                HEADER_SIZE + number * NODE_SIZE : HEADER_SIZE + (number + 1) * NODE_SIZE
            ]
            end = NODE_SIZE - free
            position = NODE_HEADER_SIZE
            children = [left] if level else []
            entries: list[CIndexEntry] = []
            for _ in range(count):
                if position + 7 > end:
                    raise FormatError("C-Index entry header overruns occupied node bytes")
                length = data[position] + 1
                if length < 7 or position + length > end:
                    raise FormatError("C-Index entry length overruns occupied node bytes")
                raw = data[position : position + length]
                index = raw[1]
                if not 1 <= index <= 50:
                    raise FormatError("C-Index entry has an invalid index number")
                key_length = self._key_length(self.index_types[index], raw[7:])
                payload_end = length - (4 if level else 0)
                if 7 + key_length > payload_end:
                    raise FormatError("C-Index key overruns its entry")
                child = _u32(raw, length - 4) if level else None
                entry = CIndexEntry(
                    number,
                    position,
                    index,
                    raw[2],
                    _u32(raw, 3),
                    raw[7 : 7 + key_length],
                    raw[7 + key_length : payload_end],
                    child,
                    raw,
                )
                self.index_records.append(entry)
                entries.append(entry)
                if child is not None:
                    children.append(child)
                position += length
            if position != end:
                raise FormatError("C-Index entry lengths disagree with node free space")
            if any(data[end:]):
                raise FormatError("C-Index node free space contains nonzero bytes")
            last: CIndexEntry | None = None
            for index, child in enumerate(children):
                last = walk(child, level - 1)
                if index < len(entries):
                    separator = entries[index]
                    if (
                        last is None
                        or separator.payload
                        or (
                            separator.index_number,
                            separator.record_number,
                            separator.duplicate,
                            separator.key,
                        )
                        != (last.index_number, last.record_number, last.duplicate, last.key)
                    ):
                        raise FormatError("C-Index internal separator disagrees with its child")
            return last if level else (entries[-1] if entries else None)

        height = _u32(self.header, 0x1C)
        if not 1 <= height <= self.allocated_nodes:
            raise FormatError("C-Index tree height is invalid")
        try:
            walk(self.root_node, height - 1)
        except RecursionError as error:
            raise FormatError("C-Index tree exceeds the decoder traversal limit") from error
        free_nodes: set[int] = set()
        free_node = struct.unpack_from("<i", self.header, 0x3C)[0]
        while free_node != -1:
            if not 0 <= free_node < self.allocated_nodes:
                raise FormatError("C-Index free list points outside allocated nodes")
            if free_node in active or free_node in free_nodes:
                raise FormatError("C-Index free list is cyclic or overlaps the live tree")
            free_nodes.add(free_node)
            free_node = raw_nodes[free_node][1]
        if len(active) + len(free_nodes) != self.allocated_nodes:
            raise FormatError("C-Index allocated nodes are orphaned from tree and free list")
        self.nodes: list[CIndexNode] = []
        for number, (left, following, previous, level, count, free) in enumerate(raw_nodes):
            offset = HEADER_SIZE + number * NODE_SIZE
            self.nodes.append(
                CIndexNode(
                    number,
                    offset,
                    level,
                    left,
                    following,
                    previous,
                    count,
                    free,
                    original[offset : offset + NODE_SIZE],
                    number in active,
                )
            )
        self._validate_siblings(active)

    @staticmethod
    def _key_length(kind: int, data: bytes) -> int:
        kind &= 0x1F
        if kind in (0, 1):
            position = data.find(b"\0")
            if position < 0:
                raise FormatError("C-Index string key has no terminator")
            return position + 1
        if kind in (2, 8, 16, 17, 18, 19, 20):
            if not data:
                raise FormatError("C-Index counted key has no length")
            return data[0] + 1
        sizes = {3: 4, 4: 2, 5: 4, 6: 4, 7: 8, 9: 6, 10: 2}
        if kind not in sizes:
            raise FormatError(f"Unsupported C-Index key type {kind}")
        return sizes[kind]

    def _validate_siblings(self, active: set[int]) -> None:
        for number in active:
            node = self.nodes[number]
            for target, direction in (
                (node.next_node, "previous_node"),
                (node.previous_node, "next_node"),
            ):
                if target == -1:
                    continue
                if target not in active:
                    raise FormatError("C-Index sibling is outside the live tree")
                other = self.nodes[target]
                if other.level != node.level or getattr(other, direction) != number:
                    raise FormatError("C-Index sibling links are not reciprocal")
