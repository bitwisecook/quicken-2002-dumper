# Quicken companion files: QPH, QSD, QEL and IDX

These decoders complement [QDF v3](file-format.md) and [HCX](hcx-format.md).
Pass existing companions with repeated `--companion` options. Every original
file remains in `source_files`; decoded objects retain source-file IDs,
physical offsets and raw bytes. Companion data is never added to the bank
ledger as inferred transactions.

The investigation used REA, the `reverse-engineer-anything` workflow and Ghidra,
with original Quicken 2002 media, the official US 2004 converter and Canadian
2006 media. Their provenance is recorded in the HCX note. All addresses below
are preferred-image addresses, not file offsets. Additional artifact identities:

| Artifact | SHA-256 |
| --- | --- |
| 2002 `QACCES32.DLL` | `f535390263d82bb93c405f25b121af26259c985cea0f03c8f6e3126da176d05c` |
| 2002 `QWUTIL7.DLL` | `0d077e3fa7fa199bf259de789a5a0a9a053834070bb996ad29df1e1c27b19f8a` |
| 2006 vendor `SAMPLE.QPH` | `e1161d9fe12452830b31ee2262a0dd8b3adc07787b649ed93e54c87ada04763d` |
| 2006 vendor `SAMPLE.QEL` | `9d404c8505700f0a04e6760a1ef6e6d7344d60dba2660a10c7a22b60f54979f0` |
| 2006 vendor `SAMPLE.IDX` | `19daf04591f07c43ea42a0eb2d431549e551b94d281121cabd93fb8b9b1bf682` |

No original media, binary, vendor sample, private fixture or decompilation dump
is distributed. Frozen fixtures in `tests/vectors` are synthetic, static byte
images represented by sparse segments and checked SHA-256 values. Tests load
them independently of the current fixture-building helpers. Historical fixtures
must not be regenerated to accommodate a changed decoder.

## QPH: security prices and stock splits

QPH is separate from HCX currency history. Its outer layout is **not** C-Index
and does not use the QDF page cipher. A 32-byte header links fixed-size records
using absolute file offsets. Zero is the end-of-list sentinel.

| Header offset | Encoding | Meaning |
| --- | --- | --- |
| 0 | u32 | Storage version, 1–3 supported |
| 4 | u32 | First live security/symbol record |
| 8 | u32 | Recycled symbol-list head |
| 12 | u32 | Recycled quote-list head |
| 16–31 | Raw bytes | Retained without invented meanings |

A symbol record is **275 bytes**. Its next offset is u32 at 0, identity type
u32 at 4, and quote-list head u32 at 271. Identity type 1 identifies a ticker;
type 2 identifies a local security using a 261-byte filename field at 8 and a
u16 security reference at 269. The stored filename is identity data, not a path
that the exporter opens or requires to exist. Unknown identity types retain
their type and raw record with nullable interpreted identity columns.

The ticker layouts need explicit historical adapters:

| Version | Ticker at offset 8 | Exchange interpretation |
| --- | --- | --- |
| 1 | Original 2002 reader uses the full 261-byte identity buffer | Effective exchange 0; bytes at 21 are not treated as an exchange field |
| 2 | 13-byte NUL-terminated field | u32 at offset 21 |
| 3 | 33-byte NUL-terminated field | u32 at offset 41 |

The 2004 converter's v1/v2 upgrade reads the old identity as a C string, writes
the newer symbol layout and forces v1 exchange to zero. Its `lstrcpyA` call
does not establish a 13-byte copy limit. This exporter uses the original 2002
reader's larger identity buffer for v1 and retains its longer symbols. Source
version, original identity bytes and stored exchange values remain available
separately; the input is never upgraded in place.

Each quote record is **54 bytes**:

| Quote offset | Encoding | Meaning |
| --- | --- | --- |
| 0 | u32 | Next quote offset |
| 4 | u32 | Date: day:u8, month:u8, year-since-1900:u16 |
| 8 | u32 | Native priority |
| 12 | u32 | Kind: 0 price/volume, 1 stock split |
| 16 | u16, kind 0 | Field-presence mask |
| 18 / 26 / 34 | Eight-byte native values | Close / high / low, only present for mask bits 1 / 2 / 4 |
| 42 / 46 | u32, kind 0 | Volume base and multiplier; mask bit 8 controls presence |
| 50 | u32, kind 0 | Native status, retained without naming individual bits |
| 16 / 24 | Eight-byte native values, kind 1 | Split numerator / denominator |

Missing price or volume fields become SQL NULL. They are different from a
stored zero. Unknown quote kinds retain their dates, kinds and original bytes;
their value columns remain NULL. The exporter does not select a winning quote
for a date, merge priorities, apply splits or adjust historical prices.

### Price and share-value encoding

These eight-byte values are **not IEEE doubles** and are not scaled integer
cents. Let `L` and `H` be their two little-endian u32 words:

```text
whole    = L & 0x3fffffff
fraction = H & 0x07ffffff
value    = whole + fraction / 100000000
if L & 0x80000000: value = -value
```

Other word bits are metadata excluded by the native numeric conversion.
Raw quote bytes preserve them. SQLite numeric columns follow native conversion;
the raw words retain the exact original representation.

Volume uses a separate encoding. The native reader multiplies the two u32
values with 32-bit arithmetic: `(base * multiplier) & 0xffffffff`. The export
keeps both factors and that native result. It does not reinterpret volume as a
price/share value or silently replace wrapping behavior with a larger product.

### Native evidence and validation

Exact 2002 `QACCES32.DLL` creates version 1 at `0x1003D760`, opens a 32-byte
header at `0x1003D7C0`, reads 275-byte symbols at `0x1003EFD0` and 54-byte
quotes at `0x1003F010`. The split reader is `0x1003EE50`.
Exact 2002 `QWUTIL7.DLL` converts prices at `0x1002914D` and share values at
`0x1002905B`. In 2004 `qaccess.dll`, the historical adapter is `0x00F48FBA`,
field-mask extraction is `0x00F49150`, and native volume multiplication is
visible at `0x00F49361`.

The decoder checks bounds, list cycles and overlapping live/free records.
It retains recycled records and unclaimed byte ranges rather than treating
them as active quotes or discarding them. The independently supplied 2006 sample
contains 24 symbols and 3,929 live quote records: 3,915 prices and 14 splits.
No trusted Quicken price report was available for end-to-end comparison.

SQLite tables are `qph_files`, `qph_symbols`, `qph_quotes` and
`qph_unused_regions`; the `share_prices` view joins live price quotes to their
security identities. For example:

```sql
SELECT symbol, exchange_code, quote_date, close, high, low, volume
FROM share_prices ORDER BY source_file_id, symbol_offset, quote_date;

SELECT source_file_id, symbol_offset, quote_date,
       split_numerator, split_denominator
FROM qph_quotes WHERE kind = 1;
```

## QSD: named settings records

The supported QSD is the unencrypted sequential settings format 3. Its
128-byte header includes an identification banner, version bytes at 32–34,
and storage-format byte 3 at offset 40. A stored filename in the banner is
diagnostic; renaming a file does not invalidate it. The native encrypted
variant identified by major-version byte 4 is explicitly unsupported, rather
than being mistaken for an empty settings file.

Records are sequential: a 64-byte header, exactly the declared payload length,
then a two-byte `ff ff` trailer.

| Record-header offset | Encoding | Meaning |
| --- | --- | --- |
| 0 | u16 | `0xffff` marker |
| 2 | u32 | Payload byte count, excluding trailer |
| 6 | u16 | Record type |
| 8 | u16 | Legacy reference ID |
| 10 | u16 | Deleted state, 0 or 1 |
| 12–43 | 32-byte NUL-terminated string | Record name |
| 44–63 | Raw bytes | Additional metadata, retained |

Type 1 is EOF: the native creator writes a two-byte zero payload and the normal
trailer. It terminates the file. Native lookup uses type, ID and name; ordinary
iteration skips deleted records. The exporter retains deleted physical versions
and EOF in `qsd_records`; `qsd_current_records` excludes those two categories.
It does not flatten records into a name/value dictionary that could hide
duplicates or make up field schemas.

The private sample has 25 physical records: 21 active settings, three deleted
versions and EOF. Native record names support macro, preference, navigation,
snapshot and report-filter uses. Their type-specific payloads remain opaque.

Exact 2002 native evidence: header load `0x10001800`, record-directory builder
`0x10008940`, lookup `0x10001E10`, record writer `0x10006A30`, deletion-state
toggle `0x10006EB0`, and encrypted-variant predicate `0x10006700`.
The native library can attempt file repair; this decoder instead rejects broken
boundaries, trailers and EOF without modifying its input. Reassembling
`qsd_files.header_bytes` and every record's header, payload and trailer produces
the exact source image.

## QEL: online objects in a C-Index database

QEL is associated with the native online module and its `EBValidateQELFile`
entry point. Its outer container uses the same sparse `VALIDAT1` marker,
1024-byte header, 2048-byte nodes and entry layout as HCX. Its application
objects and lookup indexes differ; it must not be passed through the currency
history decoder. The observed application header begins `QEL ` at offset `0x5c`.

The supported layout has lookup indexes 1 and 2 and data index 49. Index 49
can split one serialized object over multiple entries with the same record
number. The entry flag's low seven bits are the zero-based fragment number;
bit `0x80` marks the final fragment. The decoder requires a contiguous sequence
beginning at zero, one final fragment, matching lookup-record sets and the
declared object count. It preserves each part's node and entry location.

Native qindex routine `0x00EAEE3A` writes consecutive fragments and sets the
final bit. The shared serialization reader checks the low-byte rolling checksum
described in the HCX note. The decoder verifies that checksum over the joined
object, retains its descriptor signature and state, and does not infer a field's
length or financial meaning from a plausible-looking tag. QEL descriptors vary
from HCX's descriptor. Objects can contain online configuration, messages and
transaction-like content; no object is automatically promoted to a bank entry.

The vendor sample has 207 logical objects in 376 data fragments. All 207 pass
the native checksum and have corresponding entries in both lookup indexes.
SQLite tables are `qel_files`, `qel_nodes`, `qel_index_entries`, `qel_records`
and `qel_record_parts`. Application fields remain explicitly unparsed.

## IDX: a QDF index cache

The observed IDX stores serialized index-cache arrays, not another independent
ledger. In 2004 `qdb.dll`, `QDBSaveIndexFile` at `0x0101AE88` writes the cache
through `0x0103BCC9`, which builds an offset/length directory, writes 32-byte
array headers and writes their backing arrays. The index-array count depends
on QDF schema metadata. The 2004 writer uses an 80-byte directory; the 2006
sample uses 96 bytes. The parser derives the directory extent from the first
payload offset rather than hard-coding one application release's array count.

The directory consists of little-endian `(u32 offset, u32 length)` pairs. For
`n` index arrays, it contains `n` array-header entries, `n` backing-array entries,
then the master-array header and body. Each array header is 32 bytes. Native
backing-array lengths are capacity at header offset 12 times element size at
offset 4 for index arrays, or offset 8 for the master array. Header fields not
established by those writes remain raw.

The decoder checks directory bounds, header sizes, backing-array capacities,
overlaps and complete coverage. `idx_files` keeps the directory and
`idx_segments` keeps each exact segment and source offset. The vendor sample
has 12 segments covering its 166,168 bytes. Array-entry meanings require
additional QDF schema linkage and are not inferred here.

## Other discovered extensions and limits

The 2004 application's backup-associated resource list includes `EML`, `QTX`,
`QTO`, `QEL`, `NPC`, `QPH`, `ABD`, `IDX`, `CRT` and `HCX` (resource IDs
`0x4615`–`0x4621`, with gaps). This establishes extension handling, not the
content schema of every extension. In particular, the observed spelling is
**ABD**, not ADB. EML/QTX/QTO/NPC/ABD/CRT layouts are not decoded in this pass.
The tool retains such companions unchanged and records an `opaque_companion`
information issue. QIN and HIM were not in that specific resource list or the
two media's sample-file inventories; no decoder is claimed for them.

The vendor 2006 QDF is database version `0x00040000`, outside the existing QDF3
reader. This investigation does not silently broaden QDF support based on the
application's year. Unknown storage versions fail explicitly. Checksums and
structural consistency establish recovered bytes and links; they do not prove
that every financial field or Quicken reporting behavior has been reproduced.
