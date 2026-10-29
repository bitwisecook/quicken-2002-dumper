"""Strict reader for the observed QDF v3 page, fragment and primary-index layouts."""

import hashlib
import hmac
from dataclasses import dataclass
from typing import TypeAlias

from .rc5 import decrypt_cbc

Buffer: TypeAlias = bytes | bytearray
FragmentKey: TypeAlias = tuple[int, int]
RecordIdentity: TypeAlias = tuple[int, int]

BLOCK_SIZE = 4104
MAGIC = bytes.fromhex("ac9ebd8f00000300")
FIXED_KEY = b"!-!-!-!-Copyright 2000 Intuit Inc.  All rights reserved.-!-!-!-!"


class FormatError(ValueError):
    """The source fails a supported-layout or integrity requirement."""


def _bounded(data: Buffer, offset: int, size: int) -> Buffer:
    if offset < 0 or offset + size > len(data):
        raise FormatError(f"Truncated integer at offset {offset}")
    return data[offset : offset + size]


def u16(data: Buffer, offset: int = 0) -> int:
    return int.from_bytes(_bounded(data, offset, 2), "little")


def u32(data: Buffer, offset: int = 0) -> int:
    return int.from_bytes(_bounded(data, offset, 4), "little")


def derive_page_key(seed: bytes) -> bytes:
    """Mix the stored digest and nonce into the fixed 64-byte application key."""
    if len(seed) != 32:
        raise FormatError("Page seed must contain exactly 32 bytes")
    key = bytearray(FIXED_KEY)
    for i in range(16):
        key[i] ^= seed[i]
        key[i + 16] ^= (seed[i] + 1) & 255
        key[i + 32] ^= seed[i + 16]
        key[i + 48] ^= (seed[i + 16] + 3) & 255
    return bytes(key)


def decrypt_page(block: bytes, page_number: int) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise FormatError(f"Page {page_number}: truncated block")
    if page_number < 0:
        raise FormatError("Page number must be nonnegative")
    page = bytearray(block)
    start = 8 if page_number == 0 else 0
    if page_number == 0:
        if bytes(page[:8]) != MAGIC:
            raise FormatError("Only legacy QDF database version 0x00030000 is supported")
    else:
        # Quicken changes eight ciphertext bytes after encryption. Undo in
        # reverse order because the chosen byte positions can overlap.
        for offset in range(14, -1, -2):
            index = u32(page, offset) % 0xFD7 + 0x30
            page[index] ^= page[index + 1]
    seed = bytes(page[start : start + 32])
    page[start + 32 :] = decrypt_cbc(bytes(page[start + 32 :]), derive_page_key(seed), seed[16:24])
    digest = hashlib.md5(page[start + 16 :], usedforsecurity=False).digest()
    if not hmac.compare_digest(digest, seed[:16]):
        raise FormatError(f"Page {page_number}: MD5 integrity check failed")
    if page_number and u32(page, 32) != page_number:
        raise FormatError(f"Page {page_number}: embedded page number disagrees")
    return bytes(page)


@dataclass(frozen=True)
class Fragment:
    page: int
    offset: int
    kind: int
    next_pointer: int
    payload: bytes

    @property
    def record_type(self) -> int:
        return self.kind & 0x7FFF


@dataclass(frozen=True)
class Record:
    record_type: int
    legacy_id: int
    index_page: int
    index_slot: int
    payload: bytes
    parts: tuple[FragmentKey, ...]


class QDF:
    def __init__(self, original: bytes) -> None:
        if not original or len(original) % BLOCK_SIZE:
            raise FormatError("QDF size is not a nonzero multiple of 4,104 bytes")
        self.pages = tuple(
            decrypt_page(original[o : o + BLOCK_SIZE], o // BLOCK_SIZE)
            for o in range(0, len(original), BLOCK_SIZE)
        )
        if u32(self.pages[0], 0x3C) != BLOCK_SIZE or u32(self.pages[0], 0x40) != len(self.pages):
            raise FormatError("Database header block size or page count disagrees")
        self.fragments: dict[FragmentKey, Fragment] = {}
        for number, page in enumerate(self.pages[1:], 1):
            if u16(page, 36) not in (6, 9):
                continue
            offset = 48
            while offset + 8 <= BLOCK_SIZE:
                kind, size, next_pointer = (
                    u16(page, offset),
                    u16(page, offset + 2),
                    u32(page, offset + 4),
                )
                if not (kind or size or next_pointer):
                    break
                if size > BLOCK_SIZE - offset - 8:
                    raise FormatError(f"Page {number}:{offset}: record fragment exceeds page")
                self.fragments[(number, offset)] = Fragment(
                    number, offset, kind, next_pointer, page[offset + 8 : offset + 8 + size]
                )
                offset += (size + 15) // 8 * 8
        self.records: list[Record] = []
        used_fragments: set[FragmentKey] = set()
        identities: set[RecordIdentity] = set()
        for number, page in enumerate(self.pages[1:], 1):
            if u16(page, 36) != 8:
                continue
            width, count = u32(page, 48), u16(page, 52)
            if width != 12 or count > (BLOCK_SIZE - 54) // width:
                raise FormatError(f"Page {number}: unsupported record index layout")
            for slot in range(count):
                entry = 54 + slot * 12
                pointer, size, legacy_id = (
                    u32(page, entry),
                    u32(page, entry + 4),
                    u32(page, entry + 8),
                )
                parts = self.follow(pointer)
                head = self.fragments[parts[0]]
                if not head.kind & 0x8000 or head.kind == 0xFFFF:
                    raise FormatError(f"Page {number}: index points to an inactive record")
                if any(self.fragments[p].record_type != head.record_type for p in parts):
                    raise FormatError("Continuation record type mismatch")
                payload = b"".join(self.fragments[p].payload for p in parts)
                if len(payload) != size:
                    raise FormatError(f"Index {number}:{slot}: logical record size mismatch")
                identity = (head.record_type, legacy_id)
                if identity in identities or used_fragments.intersection(parts):
                    raise FormatError("Duplicate logical record or shared continuation")
                identities.add(identity)
                used_fragments.update(parts)
                self.records.append(Record(*identity, number, slot, payload, parts))
        self.by_identity = {(r.record_type, r.legacy_id): r for r in self.records}
        self.unindexed_heads = [
            f
            for key, f in self.fragments.items()
            if f.page
            and u16(self.pages[f.page], 36) == 9
            and f.kind & 0x8000
            and f.kind != 0xFFFF
            and key not in used_fragments
        ]
        if self.unindexed_heads:
            raise FormatError("Active data records exist outside the decoded primary indexes")

    def follow(self, pointer: int) -> tuple[FragmentKey, ...]:
        parts: list[FragmentKey] = []
        seen: set[FragmentKey] = set()
        while pointer & 0xFFFFF:
            key = (pointer & 0xFFFFF, (pointer >> 20) + 48)
            if key in seen or key not in self.fragments:
                raise FormatError("Broken or cyclic record continuation chain")
            seen.add(key)
            fragment = self.fragments[key]
            if fragment.kind == 0xFFFF:
                raise FormatError("Record chain points to free space")
            parts.append(key)
            pointer = fragment.next_pointer
        if pointer or not parts:
            raise FormatError("Invalid record pointer")
        return tuple(parts)
