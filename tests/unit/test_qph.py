"""Fabricated QPH versions and independently specified numeric word encodings."""

from __future__ import annotations

import hashlib
import json
import struct
import unittest
from pathlib import Path
from typing import TypedDict, cast

from quicken_qdf.format import FormatError
from quicken_qdf.qph import HEADER_SIZE, QPH, QUOTE_SIZE, SYMBOL_SIZE, native_value


class Segment(TypedDict):
    offset: int
    hex: str


class Fixture(TypedDict):
    name: str
    byte_count: int
    sha256: str
    segments: list[Segment]
    version: int
    symbol: str | None
    exchange: int | None
    quote_count: int


class FixtureFile(TypedDict):
    cases: list[Fixture]


def _quote(*, following: int = 0, date: int = 0x0068070B, kind: int = 0, mask: int = 15) -> bytes:
    raw = bytearray(QUOTE_SIZE)
    struct.pack_into("<4I", raw, 0, following, date, 60, kind)
    if kind == 0:
        struct.pack_into("<H", raw, 16, mask)
        # close=12.5, high=13.25, low=-2.0; not IEEE doubles.
        struct.pack_into("<II", raw, 18, 12, 0x80000000 | 50_000_000)
        struct.pack_into("<II", raw, 26, 13, 25_000_000)
        struct.pack_into("<II", raw, 34, 0x80000002, 0)
        struct.pack_into("<III", raw, 42, 0xFFFFFFFF, 2, 4)
    elif kind == 1:
        struct.pack_into("<4I", raw, 16, 3, 0x80000000, 2, 0)
    else:
        raw[16:] = bytes(range(QUOTE_SIZE - 16))
    return bytes(raw)


def make_qph(
    *,
    version: int = 3,
    identity_type: int = 1,
    long_symbol: bool = False,
    recycled: bool = False,
    mask: int = 15,
    unknown: bool = False,
) -> bytes:
    quote_offset = HEADER_SIZE + SYMBOL_SIZE
    split_offset = quote_offset + QUOTE_SIZE
    symbol = bytearray(SYMBOL_SIZE)
    struct.pack_into("<II", symbol, 0, 0, identity_type)
    if identity_type == 1:
        name = b"SYNTHETIC-LONG-TICKER" if long_symbol else b"SYNTH"
        symbol[8 : 8 + len(name)] = name
        if version == 2:
            struct.pack_into("<I", symbol, 21, 17)
        elif version == 3:
            struct.pack_into("<I", symbol, 41, 19)
    elif identity_type == 2:
        name = b"C:\\SYNTHETIC\\LEDGER"
        symbol[8 : 8 + len(name)] = name
        struct.pack_into("<H", symbol, 269, 73)
    struct.pack_into("<I", symbol, 271, quote_offset)
    header = bytearray(HEADER_SIZE)
    struct.pack_into("<II", header, 0, version, HEADER_SIZE)
    quote = _quote(following=split_offset, kind=9 if unknown else 0, mask=mask)
    split = _quote(date=0x0068070A, kind=1)
    body = bytes(symbol) + quote + split
    if recycled:
        free_symbol_offset = HEADER_SIZE + len(body)
        free_quote_offset = free_symbol_offset + SYMBOL_SIZE
        struct.pack_into("<II", header, 8, free_symbol_offset, free_quote_offset)
        free_symbol = bytearray([0x91] * SYMBOL_SIZE)
        free_quote = bytearray([0x92] * QUOTE_SIZE)
        struct.pack_into("<I", free_symbol, 0, 0)
        struct.pack_into("<I", free_quote, 0, 0)
        body += bytes(free_symbol) + bytes(free_quote) + b"opaque trailing bytes"
    return bytes(header) + body


class QPHTests(unittest.TestCase):
    def test_frozen_historical_format_fixtures(self) -> None:
        path = Path(__file__).resolve().parents[1] / "vectors" / "qph_formats.json"
        document = cast(FixtureFile, json.loads(path.read_text()))
        self.assertGreaterEqual(len(document["cases"]), 4)
        for fixture in document["cases"]:
            with self.subTest(fixture=fixture["name"]):
                source = bytearray(fixture["byte_count"])
                for segment in fixture["segments"]:
                    content = bytes.fromhex(segment["hex"])
                    start = segment["offset"]
                    source[start : start + len(content)] = content
                self.assertEqual(hashlib.sha256(source).hexdigest(), fixture["sha256"])
                qph = QPH(bytes(source))
                self.assertEqual(qph.version, fixture["version"])
                self.assertEqual(len(qph.quotes), fixture["quote_count"])
                if qph.symbols:
                    self.assertEqual(qph.symbols[0].symbol, fixture["symbol"])
                    self.assertEqual(qph.symbols[0].exchange_code, fixture["exchange"])

    def test_three_versions_and_long_historical_symbol(self) -> None:
        for version, exchange in [(1, 0), (2, 17), (3, 19)]:
            with self.subTest(version=version):
                qph = QPH(make_qph(version=version, long_symbol=version == 1))
                (symbol,) = qph.symbols
                self.assertEqual(symbol.exchange_code, exchange)
                self.assertEqual(
                    symbol.symbol, "SYNTHETIC-LONG-TICKER" if version == 1 else "SYNTH"
                )
                self.assertEqual(len(symbol.raw), SYMBOL_SIZE)
                self.assertEqual(qph.quotes[0].close, 12.5)

    def test_numeric_flags_sign_and_fraction(self) -> None:
        for low, high, expected in [
            (0, 0x80000000, 0.0),
            (12, 50_000_000, 12.5),
            (0xC0000002, 0xF8000000 | 25_000_000, -2.25),
        ]:
            with self.subTest(low=low, high=high):
                self.assertEqual(native_value(struct.pack("<II", low, high)), expected)
        with self.assertRaises(FormatError):
            native_value(bytes(7))

    def test_prices_volume_and_split_have_distinct_layouts(self) -> None:
        qph = QPH(make_qph())
        quote, split = qph.quotes
        self.assertEqual((quote.close, quote.high, quote.low), (12.5, 13.25, -2.0))
        self.assertEqual(
            (quote.volume_base, quote.volume_multiplier, quote.volume), (0xFFFFFFFF, 2, 0xFFFFFFFE)
        )
        self.assertEqual((quote.priority, quote.status), (60, 4))
        self.assertEqual((split.split_numerator, split.split_denominator), (3.0, 2.0))
        self.assertIsNone(split.field_mask)
        self.assertIsNone(split.close)
        self.assertIsNone(split.volume)

    def test_mask_controls_absence_and_unknown_kinds_remain_raw(self) -> None:
        quote = QPH(make_qph(mask=0)).quotes[0]
        self.assertEqual(
            (quote.close, quote.high, quote.low, quote.volume), (None, None, None, None)
        )
        unknown = QPH(make_qph(unknown=True)).quotes[0]
        self.assertEqual(unknown.kind, 9)
        self.assertIsNone(unknown.field_mask)
        self.assertIsNone(unknown.close)
        self.assertEqual(unknown.raw[16:], bytes(range(QUOTE_SIZE - 16)))

    def test_local_security_identity(self) -> None:
        (symbol,) = QPH(make_qph(identity_type=2)).symbols
        self.assertEqual((symbol.file_identity, symbol.security_ref), ("C:\\SYNTHETIC\\LEDGER", 73))
        self.assertIsNone(symbol.symbol)
        self.assertIsNone(symbol.exchange_code)

    def test_recycled_records_and_unknown_regions_preserve_every_byte(self) -> None:
        source = make_qph(recycled=True)
        qph = QPH(source)
        pieces = [(0, qph.header)]
        pieces += [(row.offset, row.raw) for row in qph.symbols]
        pieces += [(row.offset, row.raw) for row in qph.quotes]
        pieces += [(row.offset, row.raw) for row in qph.free_symbols + qph.free_quotes]
        pieces += [(row.offset, row.data) for row in qph.unclaimed_regions]
        self.assertEqual(b"".join(data for _, data in sorted(pieces)), source)
        self.assertEqual(len(qph.free_symbols), 1)
        self.assertEqual(len(qph.free_quotes), 1)
        self.assertEqual(qph.unclaimed_regions[0].data, b"opaque trailing bytes")

    def test_corrupt_pointers_cycles_and_shared_records_are_rejected(self) -> None:
        for name, offset, pointer in [
            ("header", 4, 4),
            ("outside", 4, 0xFFFFFF00),
            ("symbol cycle", HEADER_SIZE, HEADER_SIZE),
            ("quote cycle", HEADER_SIZE + SYMBOL_SIZE, HEADER_SIZE + SYMBOL_SIZE),
            ("free/live overlap", 12, HEADER_SIZE + SYMBOL_SIZE),
        ]:
            with self.subTest(name=name):
                source = bytearray(make_qph())
                struct.pack_into("<I", source, offset, pointer)
                with self.assertRaises(FormatError):
                    QPH(bytes(source))

    def test_native_quote_order_and_unique_date_kind_are_checked(self) -> None:
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate):
                source = bytearray(make_qph())
                second = HEADER_SIZE + SYMBOL_SIZE + QUOTE_SIZE
                struct.pack_into("<I", source, second + 4, 0x0068070B if duplicate else 0x0068070C)
                if duplicate:
                    struct.pack_into("<I", source, second + 12, 0)
                with self.assertRaises(FormatError):
                    QPH(bytes(source))

    def test_empty_truncated_unsupported_and_unterminated_inputs(self) -> None:
        self.assertEqual(QPH(struct.pack("<I", 1) + bytes(28)).quotes, [])
        for source in (bytes(31), struct.pack("<I", 9) + bytes(28), make_qph()[:-1]):
            with self.subTest(size=len(source)), self.assertRaises(FormatError):
                QPH(source)
        source = bytearray(make_qph())
        source[HEADER_SIZE + 8 : HEADER_SIZE + 41] = b"X" * 33
        with self.assertRaisesRegex(FormatError, "terminated"):
            QPH(bytes(source))


if __name__ == "__main__":
    unittest.main()
