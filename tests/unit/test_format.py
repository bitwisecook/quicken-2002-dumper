"""Portable structural and corruption tests using fabricated, nonfinancial data."""

import copy
import unittest
from dataclasses import replace

from quicken_qdf.format import BLOCK_SIZE, QDF, FormatError, decrypt_page, u16, u32
from tests.support import make_archive


class FormatTests(unittest.TestCase):
    def test_reassembles_chained_fragments(self) -> None:
        payload = bytes(range(256)) * 20
        qdf = QDF(make_archive([(201, 1, payload)]))
        self.assertEqual(len(qdf.records), 1)
        self.assertEqual(qdf.records[0].payload, payload)
        self.assertEqual(len(qdf.records[0].parts), 2)
        self.assertEqual(qdf.unindexed_heads, [])

    def test_rejects_truncation_and_unknown_version(self) -> None:
        data = make_archive([(201, 1, b"test")])
        for changed in (b"", data[:-1], b"badmagic" + data[8:]):
            with self.subTest(size=len(changed)), self.assertRaises(FormatError):
                QDF(changed)

    def test_detects_corruption_in_header_and_data(self) -> None:
        data = make_archive([(201, 1, bytes(5000))])
        for number in range(len(data) // BLOCK_SIZE):
            page = bytearray(data[number * BLOCK_SIZE : (number + 1) * BLOCK_SIZE])
            page[300] ^= 1
            with self.subTest(page=number), self.assertRaisesRegex(FormatError, "MD5"):
                decrypt_page(bytes(page), number)

    def test_rejects_missing_fragments_and_cycles(self) -> None:
        qdf = copy.copy(QDF(make_archive([(201, 1, bytes(5000))])))
        first = qdf.records[0].parts[0]
        pointer = first[0] | ((first[1] - 48) << 20)
        qdf.fragments = dict(qdf.fragments)
        qdf.fragments[first] = replace(qdf.fragments[first], next_pointer=pointer)
        with self.assertRaisesRegex(FormatError, "cyclic"):
            qdf.follow(pointer)
        with self.assertRaisesRegex(FormatError, "Broken"):
            qdf.follow(99999)

    def test_integer_reads_are_bounded(self) -> None:
        for function in (u16, u32):
            for offset in (-1, 2):
                with self.subTest(offset=offset), self.assertRaises(FormatError):
                    function(b"\0\0", offset)
