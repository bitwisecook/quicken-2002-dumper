"""Read-only historical Quicken QPH price and stock-split linked lists.

QPH versions 1/2/3 use the same physical record sizes. The historical symbol
adapters reproduce the native v1/v2-to-v3 conversion without modifying input.
All raw records, recycled records and unclaimed ranges remain available.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .format import FormatError

HEADER_SIZE = 32
SYMBOL_SIZE = 275
QUOTE_SIZE = 54


def _u32(data: bytes, offset: int = 0) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _text(data: bytes) -> str:
    end = data.find(b"\0")
    if end < 0:
        raise FormatError("QPH identity string is not terminated within its field")
    return data[:end].decode("cp1252", errors="replace")


def native_value(data: bytes) -> float:
    """Decode the native price/share value while retaining flags in raw records."""
    if len(data) != 8:
        raise FormatError("QPH price/share value must have eight bytes")
    low, high = struct.unpack("<II", data)
    result = (low & 0x3FFFFFFF) + (high & 0x07FFFFFF) / 100_000_000
    return -result if low & 0x80000000 else result


@dataclass(frozen=True, slots=True)
class QPHSymbol:
    offset: int
    next_offset: int
    identity_type: int
    symbol: str | None
    exchange_code: int | None
    file_identity: str | None
    security_ref: int | None
    quote_head: int
    raw: bytes
    stored_exchange_code: int | None


@dataclass(frozen=True, slots=True)
class QPHQuote:
    offset: int
    symbol_offset: int
    next_offset: int
    packed_date: int
    priority: int
    kind: int
    field_mask: int | None
    close: float | None
    high: float | None
    low: float | None
    volume: int | None
    volume_base: int | None
    volume_multiplier: int | None
    split_numerator: float | None
    split_denominator: float | None
    status: int | None
    raw: bytes


@dataclass(frozen=True, slots=True)
class QPHFreeRecord:
    offset: int
    next_offset: int
    raw: bytes


@dataclass(frozen=True, slots=True)
class QPHRegion:
    offset: int
    data: bytes


class QPH:
    """Decode live QPH chains and preserve the complete immutable source image."""

    def __init__(self, original: bytes) -> None:
        self.original = bytes(original)
        if len(original) < HEADER_SIZE:
            raise FormatError("QPH header is truncated")
        self.header = original[:HEADER_SIZE]
        self.version = _u32(self.header)
        if self.version not in (1, 2, 3):
            raise FormatError(f"Unsupported QPH version {self.version}")
        self.symbol_head = _u32(self.header, 4)
        self.free_symbol_head = _u32(self.header, 8)
        self.free_quote_head = _u32(self.header, 12)
        self.symbols: list[QPHSymbol] = []
        self.quotes: list[QPHQuote] = []
        self.free_symbols: list[QPHFreeRecord] = []
        self.free_quotes: list[QPHFreeRecord] = []
        self.unclaimed_regions: list[QPHRegion] = []
        claimed: dict[int, int] = {}

        def read_record(offset: int, size: int) -> bytes:
            if offset < HEADER_SIZE or offset + size > len(original):
                raise FormatError("QPH record pointer is outside the file")
            if offset in claimed:
                raise FormatError("QPH chains are cyclic or share a record")
            claimed[offset] = size
            return original[offset : offset + size]

        offset = self.symbol_head
        while offset:
            raw = read_record(offset, SYMBOL_SIZE)
            following = _u32(raw)
            identity_type = _u32(raw, 4)
            symbol: str | None = None
            exchange: int | None = None
            stored_exchange: int | None = None
            identity: str | None = None
            security_ref: int | None = None
            if identity_type == 1:
                symbol_end = {1: 269, 2: 21, 3: 41}[self.version]
                symbol = _text(raw[8:symbol_end])
                if self.version != 1:
                    stored_exchange = _u32(raw, 41 if self.version == 3 else 21)
                exchange = 0 if self.version == 1 else stored_exchange
            elif identity_type == 2:
                identity = _text(raw[8:269])
                security_ref = struct.unpack_from("<H", raw, 269)[0]
            head = _u32(raw, 271)
            self.symbols.append(
                QPHSymbol(
                    offset,
                    following,
                    identity_type,
                    symbol,
                    exchange,
                    identity,
                    security_ref,
                    head,
                    raw,
                    stored_exchange,
                )
            )
            quote_offset = head
            previous_date: int | None = None
            identities: set[tuple[int, int]] = set()
            while quote_offset:
                quote_raw = read_record(quote_offset, QUOTE_SIZE)
                quote = self._quote(quote_offset, offset, quote_raw)
                if previous_date is not None and quote.packed_date > previous_date:
                    raise FormatError("QPH quote dates are not in native descending order")
                identity_key = (quote.packed_date, quote.kind)
                if identity_key in identities:
                    raise FormatError("QPH symbol repeats a date/record-kind pair")
                identities.add(identity_key)
                previous_date = quote.packed_date
                self.quotes.append(quote)
                quote_offset = quote.next_offset
            offset = following
        for head, size, destination in (
            (self.free_symbol_head, SYMBOL_SIZE, self.free_symbols),
            (self.free_quote_head, QUOTE_SIZE, self.free_quotes),
        ):
            offset = head
            while offset:
                raw = read_record(offset, size)
                following = _u32(raw)
                destination.append(QPHFreeRecord(offset, following, raw))
                offset = following
        previous_end = HEADER_SIZE
        for offset, size in sorted(claimed.items()):
            if offset < previous_end:
                raise FormatError("QPH physical records overlap")
            if offset > previous_end:
                self.unclaimed_regions.append(
                    QPHRegion(previous_end, original[previous_end:offset])
                )
            previous_end = offset + size
        if previous_end < len(original):
            self.unclaimed_regions.append(QPHRegion(previous_end, original[previous_end:]))

    @staticmethod
    def _quote(offset: int, symbol_offset: int, raw: bytes) -> QPHQuote:
        following, packed_date, priority, kind = struct.unpack_from("<4I", raw)
        mask: int | None = None
        close: float | None = None
        high: float | None = None
        low: float | None = None
        volume: int | None = None
        base: int | None = None
        multiplier: int | None = None
        numerator: float | None = None
        denominator: float | None = None
        status: int | None = None
        if kind == 0:
            mask = struct.unpack_from("<H", raw, 16)[0]
            close = native_value(raw[18:26]) if mask & 1 else None
            high = native_value(raw[26:34]) if mask & 2 else None
            low = native_value(raw[34:42]) if mask & 4 else None
            if mask & 8:
                base, multiplier = struct.unpack_from("<II", raw, 42)
                volume = (base * multiplier) & 0xFFFFFFFF
            status = _u32(raw, 50)
        elif kind == 1:
            numerator = native_value(raw[16:24])
            denominator = native_value(raw[24:32])
        return QPHQuote(
            offset,
            symbol_offset,
            following,
            packed_date,
            priority,
            kind,
            mask,
            close,
            high,
            low,
            volume,
            base,
            multiplier,
            numerator,
            denominator,
            status,
            raw,
        )
