"""Small dependency-free RC5-32 CBC decryptor (RFC 2040)."""

import struct

MASK = 0xFFFFFFFF


def rol(value: int, count: int) -> int:
    count &= 31
    return ((value << count) | (value >> (32 - count))) & MASK


def key_schedule(key: bytes, rounds: int = 12) -> list[int]:
    if not key or len(key) > 255 or not 0 <= rounds <= 255:
        raise ValueError("Invalid RC5 key or round count")
    count = (len(key) + 3) // 4
    words = [int.from_bytes(key[i : i + 4], "little") for i in range(0, count * 4, 4)]
    schedule = [(0xB7E15163 + i * 0x9E3779B9) & MASK for i in range(2 * (rounds + 1))]
    a = b = i = j = 0
    for _ in range(3 * max(len(schedule), len(words))):
        a = schedule[i] = rol((schedule[i] + a + b) & MASK, 3)
        b = words[j] = rol((words[j] + a + b) & MASK, a + b)
        i = (i + 1) % len(schedule)
        j = (j + 1) % len(words)
    return schedule


def decrypt_cbc(data: bytes, key: bytes, iv: bytes, rounds: int = 12) -> bytes:
    """Decrypt complete blocks without adding/removing padding."""
    if len(data) % 8 or len(iv) != 8:
        raise ValueError("RC5 CBC needs complete 8-byte blocks and an 8-byte IV")
    schedule = key_schedule(key, rounds)
    output = bytearray()
    previous = iv
    for offset in range(0, len(data), 8):
        x = int.from_bytes(data[offset : offset + 4], "little")
        y = int.from_bytes(data[offset + 4 : offset + 8], "little")
        for i in range(rounds, 0, -1):
            y = rol((y - schedule[2 * i + 1]) & MASK, -(x & 31)) ^ x
            x = rol((x - schedule[2 * i]) & MASK, -(y & 31)) ^ y
        plain = struct.pack("<II", (x - schedule[0]) & MASK, (y - schedule[1]) & MASK)
        output.extend(a ^ b for a, b in zip(plain, previous, strict=True))
        previous = data[offset : offset + 8]
    return bytes(output)
