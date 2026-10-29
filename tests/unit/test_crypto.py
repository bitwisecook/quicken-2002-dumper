"""Independent known-answer cipher tests; vector data lives outside test code."""

import json
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict, cast

from quicken_qdf.rc5 import decrypt_cbc


class VectorJSON(TypedDict):
    rounds: int
    key_hex: str
    iv_hex: str
    plaintext_hex: str
    ciphertext_hex: str


class VectorFile(TypedDict):
    source: str
    mode: str
    vectors: list[VectorJSON]


@dataclass(frozen=True)
class Vector:
    rounds: int
    key: bytes
    iv: bytes
    plaintext: bytes
    ciphertext: bytes


def load_vectors() -> tuple[Vector, ...]:
    path = Path(__file__).resolve().parents[1] / "vectors" / "rc5_cbc.json"
    document = cast(VectorFile, json.loads(path.read_text()))
    return tuple(
        Vector(
            row["rounds"],
            bytes.fromhex(row["key_hex"]),
            bytes.fromhex(row["iv_hex"]),
            bytes.fromhex(row["plaintext_hex"]),
            bytes.fromhex(row["ciphertext_hex"]),
        )
        for row in document["vectors"]
    )


class CryptoTests(unittest.TestCase):
    def test_rfc2040_known_answers(self) -> None:
        vectors = load_vectors()
        self.assertGreaterEqual(len(vectors), 6)
        for vector in vectors:
            with self.subTest(
                rounds=vector.rounds, key=vector.key.hex(), cipher=vector.ciphertext.hex()
            ):
                self.assertEqual(
                    decrypt_cbc(vector.ciphertext, vector.key, vector.iv, vector.rounds),
                    vector.plaintext,
                )

    def test_invalid_parameters(self) -> None:
        for data, key, iv, rounds in [
            (b"123", b"key", bytes(8), 12),
            (bytes(8), b"key", b"123", 12),
            (bytes(8), b"", bytes(8), 12),
            (bytes(8), bytes(256), bytes(8), 12),
            (bytes(8), b"key", bytes(8), -1),
            (bytes(8), b"key", bytes(8), 256),
        ]:
            with self.subTest(key_length=len(key), rounds=rounds), self.assertRaises(ValueError):
                decrypt_cbc(data, key, iv, rounds)
