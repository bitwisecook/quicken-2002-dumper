"""Synthetic, nonfinancial archive builder for container and exporter tests.

Encryption here is test scaffolding, not an independent crypto oracle. RC5
correctness is tested separately against published RFC known-answer vectors.
"""

import hashlib
import struct
from collections import defaultdict
from collections.abc import Sequence
from typing import TypeAlias

from quicken_qdf.format import BLOCK_SIZE, MAGIC, derive_page_key
from quicken_qdf.rc5 import MASK, key_schedule, rol

RecordSpec: TypeAlias = tuple[int, int, bytes]


def _encrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    schedule = key_schedule(key)
    output = bytearray()
    previous = iv
    for offset in range(0, len(data), 8):
        plain = bytes(a ^ b for a, b in zip(data[offset : offset + 8], previous, strict=True))
        x = (int.from_bytes(plain[:4], "little") + schedule[0]) & MASK
        y = (int.from_bytes(plain[4:], "little") + schedule[1]) & MASK
        for i in range(1, 13):
            x = (rol(x ^ y, y) + schedule[2 * i]) & MASK
            y = (rol(x ^ y, x) + schedule[2 * i + 1]) & MASK
        previous = struct.pack("<II", x, y)
        output.extend(previous)
    return bytes(output)


def _seal(page: bytearray, number: int) -> bytes:
    start = 8 if number == 0 else 0
    page[start + 16 : start + 32] = hashlib.sha256(str(number).encode()).digest()[:16]
    page[start : start + 16] = hashlib.md5(page[start + 16 :], usedforsecurity=False).digest()
    seed = bytes(page[start : start + 32])
    page[start + 32 :] = _encrypt_cbc(bytes(page[start + 32 :]), derive_page_key(seed), seed[16:24])
    if number:
        for offset in range(0, 16, 2):
            index = int.from_bytes(page[offset : offset + 4], "little") % 0xFD7 + 48
            page[index] ^= page[index + 1]
    return bytes(page)


def _page(number: int, kind: int) -> bytearray:
    result = bytearray(BLOCK_SIZE)
    struct.pack_into("<IH", result, 32, number, kind)
    return result


def make_archive(records: Sequence[RecordSpec]) -> bytes:
    """Build one primary index per record type and aligned fragment chains."""
    groups: dict[int, list[tuple[int, bytes]]] = defaultdict(list)
    for kind, key, payload in records:
        groups[kind].append((key, payload))
    pages = [_page(0, 0)] + [_page(i, 8) for i in range(1, len(groups) + 1)]
    pages[0][:8] = MAGIC
    for index_number, (kind, group) in enumerate(groups.items(), 1):
        index = pages[index_number]
        struct.pack_into("<IH", index, 48, 12, len(group))
        for slot, (key, payload) in enumerate(group):
            first_page = len(pages)
            struct.pack_into("<III", index, 54 + 12 * slot, first_page, len(payload), key)
            chunks = [payload[o : o + 4048] for o in range(0, len(payload), 4048)] or [b""]
            for part, chunk in enumerate(chunks):
                number = len(pages)
                page = _page(number, 9)
                following = number + 1 if part + 1 < len(chunks) else 0
                struct.pack_into(
                    "<HHI", page, 48, kind | (0x8000 if part == 0 else 0), len(chunk), following
                )
                page[56 : 56 + len(chunk)] = chunk
                remaining = BLOCK_SIZE - ((56 + len(chunk) + 7) // 8 * 8)
                if remaining >= 8:
                    struct.pack_into("<HHI", page, BLOCK_SIZE - remaining, 0xFFFF, remaining - 8, 0)
                pages.append(page)
    struct.pack_into("<II", pages[0], 60, BLOCK_SIZE, len(pages))
    return b"".join(_seal(page, number) for number, page in enumerate(pages))


def financial_records() -> list[RecordSpec]:
    """One fabricated purchase, one account and two hierarchical categories."""
    result: list[RecordSpec] = []
    for key, text in [(1, "Example shop"), (2, "Fabricated test purchase")]:
        result.append((0, key, struct.pack("<IIH", key, 0, 0) + text.encode() + b"\0"))
    for key, kind, name in [
        (1, 3, "Test account"),
        (4200, 1, "Household"),
        (4201, 1, "Household:Food"),
    ]:
        header = bytearray(702)
        struct.pack_into("<IB", header, 0, key, kind)
        header[5 : 5 + len(name)] = name.encode()
        result.append((128, key, bytes(header)))
    transaction = bytearray(133)
    struct.pack_into("<IHBBH", transaction, 0, 100, 1, 1, 7, 126)
    struct.pack_into("<q", transaction, 36, -12345)
    struct.pack_into("<H", transaction, 78, 4201)
    struct.pack_into("<II", transaction, 99, 1, 2)
    result.append((175, 100, bytes(transaction)))
    mapping = bytearray(34)
    struct.pack_into("<IIH", mapping, 0, 500, 100, 175)
    result.append((150, 500, bytes(mapping)))
    return result


def replace_payload(
    records: Sequence[RecordSpec], kind: int, key: int, payload: bytes
) -> list[RecordSpec]:
    return [(t, i, payload if (t, i) == (kind, key) else p) for t, i, p in records]
