# HCX: historical currency exchange rates

HCX is Quicken's **historical currency exchange-rate companion database**. It
belongs to the enhanced multi-currency feature implemented by `EMC.DLL`.
It is separate from the QDF account/transaction database and from the QPH
security-price history. It contains dated rates keyed by Quicken currency
reference numbers, rather than another copy of the bank ledger.

This note describes the little-endian layout read by the Quicken 2002 Canadian
module and corroborated with Quicken XG 2006 Canadian binaries and their vendor
sample. It is not a specification of every file ever given an `.HCX` extension.
The dumper decodes this layout when a file is passed with `--companion file.HCX`.

## Evidence and method

The investigation used the
[`reverse-engineer-anything` skill](https://github.com/morluto/rea/tree/main/.agents/skills/reverse-engineer-anything),
REA 6.8.0 and Ghidra 12.1.4, including native function decompilation, PE resource
and export inspection, and independent byte-level checks. Static analysis does
not establish that a particular Quicken UI or report was executed.

The native artifacts are from original installation media, extracted without
executing the installer or application:

| Artifact | Source / SHA-256 |
| --- | --- |
| Quicken Deluxe 2002 ISO | [Archived original media](https://archive.org/details/quicken-deluxe-2002); `0f46cf7986961e0aa4e2e2dc178f60050a8d2be0591aca98242e2921976c9fe0` |
| 2002 `CanProg/EMC.DLL` | `e747f987199d48b8c9a97c73c42c43bd2158ae2d4c9a310e5c45e39750c8e541` |
| 2002 `ProgDlls/QDBBASE.DLL` | `553087ce367d342c9dbc42127cb94198884658617328e5f44caa63225ccbee6b` |
| Quicken XG 2006 Canadian ISO | [Archived original media](https://archive.org/details/cdrom-quicken-xg-2006); `392bff57d9f272e35921bdac38c6c41d184028df0e974ebbcee27b8fddc602bd` |
| 2006 `EMC.DLL` | `d5d79186e0c0d3cb54bad8b6b63762f9836b6e5a1dfeb02d4751e729f051bf20` |
| 2006 `qindex.dll` | `dcf3e13372e2eb31bf03be52c107387404e9f0c55cf1007602e29221f531b238` |
| 2006 vendor `SAMPLE.HCX` | `8f1bcb3dae00c60fa6a6368c8463f0678d98d79303ed2a1e1dfa80bb8a47d12a` |

The US 2004 conversion download used for the QDF work supplies useful dispatch
evidence but lacks the regional `EMC.DLL`. `qwmain.dll` at `0x013DE9B9` replaces
the data filename extension with resource string 17953 (`HCX`), then calls
`DLL_EMC_QWStatus`. The dispatch is conditional on a feature/version flag.
Its PE resource inventory has REA evidence ID
`ev_d2f0f2f131edd90b316b3fea11b778778459dc8b7a576e66bfbeea90552d1894`;
the native function analysis has ID
`ev_20a51e3b0be6e3675db805d12aba044a29914416a2ea57ef341419ba93cbebbb`.
Complete analysis output remains in the private investigation workspace.

Addresses in the following table use each DLL's preferred image base:

| Binary / address | Evidence |
| --- | --- |
| 2002 EMC `0x100059E3` | `DLL_EMC_QWStatus`: opens, creates and closes the companion through the database library |
| 2002 EMC `0x10005B1A` | `DLL_EMC_GetExchangeRateForDate`: tries history, then the current currency rate |
| 2002 EMC `0x10002051` | Inserts currency reference, packed date, float rate and flag word |
| 2002 EMC file offset `0xC3F8` | Five-field record descriptor: `X`, `L`, `L`, `F`, `L`; same descriptor in 2006 |
| 2002 QDBBASE `0x1000D000` | Checks the interleaved `VALIDAT1` header bytes |
| 2002 QDBBASE `0x1001A4D1` | Node read at `1024 + node_number * 2048` |
| 2002 QDBBASE `0x1001710E` | Empty node: sibling links -1, count 0, free space 2030 |
| 2002 QDBBASE `0x100110D7` | Walks entries from byte 18 using stored length + 1 |
| 2002 QDBBASE `0x10011B63` | Decodes entry index, flags, record number and key |
| 2006 qindex `0x00EA30A3` | Deserializes ordered tagged fields and checks the record checksum |
| 2006 qindex `0x00EABC4E` | Serializes typed fields, omitting nullable zero values |
| 2006 qindex `0x00EA304F` | Validates the low byte of the rolling record checksum |

The database libraries contain the Trio Systems copyright and C-index-style
API names (`copen`, `cfind`, `dbopen`, `checkdlist`). This identifies the observed
storage implementation; it does not imply that an arbitrary version of that
library reads every HCX variant.

No vendor binary, vendor sample, personal file, recovered financial database or
decompilation dump is distributed in this project. Test fixtures are synthetic.

## Outer container

Integers are little-endian. HCX uses a 1,024-byte header followed by 2,048-byte
node slots. Node zero starts at `0x400`; node `n` starts at
`1024 + 2048*n`. The node capacity includes preallocated space, so trailing zero
slots are not additional logical records. HCX does not use the QDF RC5 page
envelope. The supported structure and rate records are directly readable.

The validation marker is **interleaved with mutable fields**, not a contiguous
ASCII string. The bytes at `0x04, 0x10, 0x14, 0x18, 0x20, 0x28, 0x30, 0x38`
spell `VALIDAT1`. A generic file-identification utility can mistake the opening
integers for a MATLAB file; that is not its actual format.

| Header offset | Encoding | Meaning |
| --- | --- | --- |
| `0x00` | u32 | Write-generation counter, not a record count |
| `0x0C` | u32 | Root node number |
| `0x1C` | u32 | Tree height; an empty root has height 1 |
| `0x24` | u32 | Allocated node extent / next node number |
| `0x2C` | u32 | Next record-number state |
| `0x34` | u32 | Node-slot capacity |
| `0x44` | u32 | Application-maintained data-record count; native database add/delete updates it |
| `0xC0 + index_number` | u8 | Key type for the corresponding index |

The full header is retained. Undocumented fields are not assigned meanings.
The apparent u16 value 2048 at `0xC0` is incidental: its bytes are index-0 and
index-1 type codes, not a node-size declaration. The native node addressing
establishes the fixed 2048-byte node size. In the 2006 library, `dadd` at
`0x00EACAF4` increments the application count and `ddelete` at `0x00EACEA7`
decrements it; the generic library also exposes a count setter.

## B-tree nodes and entries

Each used node begins with an 18-byte header:

| Node offset | Encoding | Meaning |
| --- | --- | --- |
| `0` | u32 | Leftmost child for an internal node |
| `4` | i32 | Next node at this level; -1 means none |
| `8` | i32 | Previous node at this level; -1 means none |
| `12` | u16 | Level; zero is a leaf |
| `14` | u16 | Number of entries |
| `16` | u16 | Unused bytes in the node |
| `18` | variable | Packed entries |

An empty leaf has zero entries and `2048 - 18 = 2030` free bytes. A tree can be
empty even when its file contains several allocated-capacity slots.

An entry has this prefix:

```text
u8  length             # excludes this length byte
u8  index_number
u8  duplicate_flags
u32 record_number
key bytes
optional payload / child pointer
```

Advance by `length + 1`, never by searching for a plausible next record.
An internal separator has a final four-byte child node number. It is navigation
data and must not be counted as a second copy of a rate record. The supported
HCX key types are a NUL-terminated string (type 0), a four-byte integer (type 5),
and a length-prefixed byte sequence (type 8). The file header determines the
key boundary; bytes after it are payload, not part of the currency/date key.

The same logical record appears in several indexes:

| Index | Key | Purpose |
| --- | --- | --- |
| 1 | Length 8, then u32 currency reference and u32 packed date | Currency/date lookup |
| 2 | u32 currency reference | History for one currency |
| 3 | u32 packed date | Date lookup |
| 49 (`0x31`) | Empty NUL-terminated key | Serialized data payload |

The vendor sample has 259 logical rates and 259 leaf entries in each of these
four indexes. Counting every index entry as a rate would multiply the history
by four; counting internal separators would add further false records.

## Serialized rate records

The data payload attached to a leaf index-49 entry begins with:

```text
u16 descriptor_signature
u16 stored_checksum
u8  record_state
repeated tagged fields
u16 0xffff terminator
```

The descriptor signature is diagnostic metadata. The reader retains it in the
payload rather than identifying an application release from it. Field tags
are ascending u16 values. The native descriptor establishes their types:

| Tag | Encoding | Meaning |
| --- | --- | --- |
| 0 | No value bytes | Descriptor/control field `X` |
| 1 | u32 | Quicken currency reference, supplied as a 16-bit reference by EMC |
| 2 | u32 | Packed date |
| 3 | IEEE 754 binary32 | Exchange rate |
| 4 | u32 | Legacy flags; complete bit meanings remain undecoded |

Dates store `[day:u8, month:u8, year_since_1900:u16]`. For example a fabricated
date of 2002-12-31 is `1f 0c 66 00`. EMC's insertion path accepts a full-year
input and subtracts 1900 before storage where needed. These are calendar dates,
not Unix timestamps or day counts.

Rates have no integer cents scale. SQLite `REAL` represents any finite binary32
value exactly after promotion to binary64; the original four bytes remain
available in the serialized payload. Nullable zero rate and flag fields can be
omitted by the native writer. The native reader clears destinations first, so
those omissions encode zero. They are different from truncated field values.

The text-file importer in EMC reads five columns with `%d%d%d%d%f`, constructs
the packed month/day/year date, and inserts a float rate with flag value 8.
The installed `EMC.IMP` provides additional evidence for decimal source rates.
It is an importer input, not the HCX container format.

### Checksum compatibility

The native serializer calculates a rolling sum over payload bytes from offset 4
through the terminator. Starting with zero, each byte updates:

```text
checksum = ((checksum + byte) * 2) & 0xff
```

The native reader compares this result with the **low byte** of the stored
checksum word. That distinction matters: all 259 vendor records pass the low-byte
check, whereas only 148 match a full 16-bit calculation. The supported decoder
follows the native validation boundary. This small checksum detects some
corruption; it is not cryptographic authentication or proof of financial meaning.
After eight further byte updates, an earlier byte's contribution is lost; the
three lookup-index comparisons provide additional consistency checks.

## SQLite export and confidence boundary

The original HCX remains a `source_files.original_bytes` BLOB with its SHA-256.
SQLite schema version 2 adds:

| Table | Content |
| --- | --- |
| `hcx_files` | Source link, complete header, node size, root and declared rate count |
| `hcx_nodes` | All physical slots, source offsets, complete bytes and an `active` marker for live tree nodes |
| `hcx_index_entries` | Leaf and internal keys, payloads, flags, child links and original entries |
| `hcx_exchange_rates` | Logical record number, currency reference, ISO date, packed date, rate, flags and source location |

`source_file_id` is part of every HCX primary key. Multiple companions can
reuse node numbers and record numbers without collision. Currency IDs remain
legacy references; the exporter does not label them as ISO codes or guess the
home currency. The rates are exported separately and do not alter QDF amounts.

The decoder checks structural bounds, tree links, entry lengths, record counts,
tag ordering, the native checksum and agreement between the data records and
their three lookup indexes. Unsupported layouts and inconsistent records stop
conversion, including when the apparent rate count is zero. Existing outputs
are never overwritten and failed conversions remove their partial database.

The private 7,168-byte HCX is a valid empty tree: its root contains no entries
and its logical count is zero. This is an observed empty history, not a failed
decode converted into an empty result. The populated vendor sample exercises
the actual record layout independently of that private file.

Unresolved areas include complete flag meanings, currency-name mapping,
rate direction and home-currency relationships, report valuation behavior,
and other historical/regional storage variants. Native fallback to current
rates does not mean the HCX contains those rates. No trusted Quicken report
export has yet established end-to-end financial equivalence.
