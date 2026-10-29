# Legacy Quicken QDF v3: file format and encryption

This is a reverse-engineered specification of the **0x00030000 QDF database
layout** found in Quicken 2002 data. It covers the complete outer
container and decryption, physical pages, fragments and indexed records, and
all currently decoded financial layouts. Undecoded regions are explicitly
identified; this is not a claim that every Quicken record type or regional
variant is understood. The year on the application and the database version
number are different identifiers.

## Method and attribution

This reader and note were reverse engineered using `reverse-engineer-anything`
and AI assistance for binary analysis, implementation and documentation.
Findings were checked through native reader analysis, page checksums, pointer
and record validation, synthetic tests and independent RFC 2040 cipher vectors.
AI assistance does not establish the meaning of undecoded fields or replace
comparison with a trusted Quicken export.

## Evidence and confidence

The reader was derived from `qdb.dll` and `qaccess.dll` in Quicken's official
[2004 conversion download](https://www.quicken.com/support/how-and-when-use-intermediate-version-convert-older-versions-quicken/),
then checked against a private QDF sample. Analysis artifacts and user files
are kept outside this distributable project.
Nothing in the converter loads or executes those binaries.

| Artifact | SHA-256 |
| --- | --- |
| `QW04DLX.exe` | `f10c1cd38c19c1daced4e4e06447432e299a4bc2ee48d2882384986c52ff9b7b` |
| `qdb.dll` | `0016441075580a2ac51e4b1886579352594f34ad964ed955f15b331c39dd2077` |
| `qaccess.dll` | `181d584afe998e055e9566fb92bba5ba681143dadcfcac6a6e75a2f2c7da08b3` |

Addresses below use `qdb.dll`'s preferred image base, `0x01010000`:

| Address | Relevant operation |
| --- | --- |
| `0x01036155` | Read a v3 page, undo scrambling, RC5 decrypt, compare MD5 |
| `0x01035DC7` | Corresponding v3 write/encryption path |
| `0x01035B62` | Obtain resource string 401 and derive the page key |
| `0x01035BC2` | Undo ciphertext scrambling, in descending order |
| `0x010375A8` | Apply ciphertext scrambling, in ascending order |
| `0x01035C57` | Native v3 file-header checks |
| `0x01036DA2` | Decode a packed pointer and read a fragment |
| `0x01036E15` | Concatenate a chain of fragments |
| `0x01046630` | Select the RC5 algorithm information |
| `0x01047890` | Validate RC5 version, rounds, word size and IV parameters |

The block layout and cipher are strongly supported: stored MD5 checksums match after decryption, and primary-index entries resolve,
including records crossing page boundaries. The SQL export also passes
SQLite integrity and foreign-key checks.

Financial interpretation has a narrower confidence claim. Amount/date/string
positions are supported by reader analysis and consistent links in this file,
but no trusted Quicken QIF/report export was available to compare every field.
A checksum match establishes recovered bytes, not their financial meaning.

## Conventions

- All offsets are zero-based; ranges below use inclusive endpoints.
- Unless stated otherwise, integers are unsigned and **little-endian**.
- `u16(p,o)` and `u32(p,o)` read two/four bytes at offset `o`.
- A physical page is `0x1008` = **4,104 bytes**.
- Page number `n` starts at file offset `n * 4104`.
- Fragment and record offsets refer to decrypted bytes. No decompression occurs.
- File size must be a positive multiple of 4,104; there is no separate trailer.

## Physical encryption envelope

The first page retains the eight-byte file signature. Every other page has
its own envelope beginning at byte zero.

| Region | Page 0 offsets | Other-page offsets | Stored representation |
| --- | --- | --- | --- |
| Magic | 0–3 | — | `AC 9E BD 8F` |
| Database version | 4–7 | — | `00 00 03 00`, or integer `0x00030000` |
| Expected MD5 | 8–23 | 0–15 | Clear 16-byte digest |
| Per-page material | 24–39 | 16–31 | Clear 16 bytes; first eight form the CBC IV |
| Encrypted body | 40–4103 | 32–4103 | RC5 CBC ciphertext |
| Additional scrambling | None | Eight byte changes | Applied after CBC encryption |

Let `s = 8` for page zero, and `s = 0` otherwise. Define:

```text
D = page[s : s+16]       # expected MD5, 16 bytes
N = page[s+16 : s+32]    # stored per-page material, 16 bytes
IV = N[0:8]             # eight-byte CBC IV
E = page[s+32 : 4104]    # 4,064 or 4,072 ciphertext bytes
```

Both ciphertext lengths are multiples of eight. Decryption does **not** add or
remove padding: these are fixed-size database pages, including slack bytes.

### 1. Undo the extra ciphertext scrambling

Skip this step for page zero. For all other pages, work on a mutable copy of
the stored page, before CBC decryption:

```text
for o in [14, 12, 10, 8, 6, 4, 2, 0]:
    j = u32(page, o) % 0xFD7 + 0x30
    page[j] = page[j] XOR page[j+1]
```

`0xFD7` is 4,055. Therefore `j` is between 48 and 4,102, and `j+1` is inside the
page. The source words at offsets 0 through 17 remain outside the scrambled
region. Reverse order matters when chosen positions overlap. The native writer
applies the same XOR operation in ascending order, 0 through 14.

### 2. Derive the 64-byte RC5 key

Quicken resource string **401** is 64 bytes in the analyzed DLL. The native
reader first XORs byte `i` of that resource with `i` for `i = 0..63`, yielding:

```text
!-!-!-!-Copyright 2000 Intuit Inc.  All rights reserved.-!-!-!-!
```

The converter stores that already-decoded application constant, `C`. Start
with `K = bytearray(C)`, then for `i = 0..15` perform:

```text
K[i]      = C[i]      XOR D[i]
K[i+16]   = C[i+16]   XOR ((D[i] + 1) modulo 256)
K[i+32]   = C[i+32]   XOR N[i]
K[i+48]   = C[i+48]   XOR ((N[i] + 3) modulo 256)
```

The resulting `K` is exactly **64 bytes**, or 512 bits. The notation below uses
RC5's conventional key-length unit of bytes. The key length does not imply
512 bits of secrecy: all derivation inputs are either stored in the page or
constant in the application.

### 3. RC5-32/12/64 CBC decryption

The parameters are:

| Parameter | Value |
| --- | --- |
| Word size `w` | 32 bits |
| Rounds `r` | 12 |
| Key length `b` | 64 bytes |
| Block size | Two words = 64 bits = eight bytes |
| Mode | CBC |
| IV | First eight bytes of `N` |
| Byte order | Little-endian words |
| Padding | None |

These are the algorithms specified in [RFC 2040](https://www.rfc-editor.org/rfc/rfc2040.html).
The native BSAFE parameter tuple `(0x10, 12, 32, iv_pointer)` means algorithm
**version 1.0**, round count, word size and IV. Its first value is not a key
length. The version convention is documented in the
[BSAFE algorithm reference](https://datatracker.ietf.org/doc/html/draft-baldwin-bsafe-00#section-2.81).

For implementers, key expansion uses `P32 = 0xB7E15163` and
`Q32 = 0x9E3779B9`. Parse `K` into 16 little-endian words `L`. Initialize 26
schedule words, `S[i] = P32 + i*Q32`, modulo `2^32`. With `A=B=i=j=0`, repeat
`3*max(26,16)` times:

```text
A = S[i] = ROL32(S[i] + A + B, 3)
B = L[j] = ROL32(L[j] + A + B, A + B)
i = (i + 1) modulo 26
j = (j + 1) modulo 16
```

Additions are modulo `2^32`; rotation counts are modulo 32. For each ciphertext
block parsed as words `(A,B)`, for `i = 12..1`:

```text
B = ROR32(B - S[2*i+1], A) XOR A
A = ROR32(A - S[2*i], B) XOR B
A = A - S[0]                 # after the loop
B = B - S[1]                 # after the loop
```

Serialize `(A,B)` as eight little-endian bytes and XOR with the previous
ciphertext block; use the IV for the first block. Keep the original current
ciphertext block for the next CBC step. The implementation exposes only
decryption; test-only encryption builds fabricated container fixtures.

### 4. Verify the decrypted body

After replacing `E` with its plaintext `P`, calculate:

```text
actual_digest = MD5(N || P)
require constant_time_equal(actual_digest, D)
```

This is precisely `MD5(page[s+16:4104])`. The stored MD5 itself is excluded;
the complete stored 16-byte `N`, plaintext body and slack are included.
Python's `hashlib.md5(..., usedforsecurity=False)` expresses required legacy
format compatibility; `hmac.compare_digest` compares digests. It is an unkeyed
checksum, not authenticated encryption or proof of origin.

The converter retains the stored digest and per-page material in its decrypted
page BLOBs. The original native reader zeroes those scratch regions after use;
retaining them makes the archive more reproducible.

### Password relationship

The above derivation does not use a user password. It is sufficient to decrypt
all pages in this particular file. No user passwords are included or needed by this page decoder. This
finding does not establish the Quicken UI password, any transaction password,
or how other QDF database versions protect their contents. Possible password
fields in private settings records remain semantically undecoded.

## Decrypted file header: page zero

| Offset | Size | Interpretation / observed value |
| --- | ---: | --- |
| `0x00` | 4 | Magic `AC 9E BD 8F` |
| `0x04` | 4 | Database version `0x00030000` |
| `0x08` | 16 | Stored expected digest |
| `0x18` | 16 | Stored per-page material |
| `0x28` | 16 | Undecoded; zero in the examined format |
| `0x38` | 4 | Native header flag word; observed zero; flags not fully interpreted |
| `0x3C` | 4 | Physical page size, `0x1008` |
| `0x40` | 4 | Physical page count, read from the header |
| `0x44` | 4 | Two zero words required by the native v3 header checker |
| `0x48` | 4 | Native header/list field; observed 1; meaning not established |
| `0x4C` | 4 | Native header/list field; observed 1; meaning not established |
| `0x50` | 4 | Native header/list field; observed 1; meaning not established |
| `0x54` | 4 | Native header/list field; observed 2; meaning not established |
| `0x58`–`0x1007` | Remainder | Undecoded header/reserved area; preserved in full |

The converter checks magic, version, size, count, checksum, and nonzero pages'
embedded identities. It does not reproduce every native header flag check.

## Ordinary page header and page types

After the 32-byte envelope, ordinary pages begin with:

| Offset | Size | Field |
| --- | ---: | --- |
| `0x20` | 4 | Embedded physical page number |
| `0x24` | 2 | Page type |
| `0x26` | 2 | Native page/list flags, preserved without full interpretation |
| `0x28` | 4 | Native link/list metadata, not fully interpreted |
| `0x2C` | 4 | Additional native page metadata, not fully interpreted |
| `0x30` | Varies | Type-specific data |

Observed page inventory, excluding page zero:

| Type | Interpretation |
| ---: | --- |
| 1 | Directory/list metadata; partial understanding |
| 3 | Directory/list metadata; partial understanding |
| 4 | Directory/list metadata; partial understanding |
| 5 | Private-resource index/list metadata; partial understanding |
| 6 | Private-resource fragment page |
| 7 | List/index metadata associated with ordinary record indexes |
| 8 | Primary-index pages |
| 9 | Ordinary record-fragment pages |

Types 1/3/4/5/7 and undecoded metadata fields remain lossless page BLOBs. The
reader discovers type-8 pages by scanning the verified physical pages; it does
not reconstruct the entire native root-directory traversal. Empty index pages
are allowed. Unsupported/orphaned active records are not silently discarded.

## Record fragments on types 6 and 9

Fragment storage begins at page offset `0x30` = 48. Every fragment begins with
an eight-byte header:

| Relative offset | Size | Field |
| --- | ---: | --- |
| 0 | 2 | Kind word: low 15 bits are record type; high bit marks a first fragment |
| 2 | 2 | Payload size of this fragment, excluding its header and alignment |
| 4 | 4 | Packed continuation pointer; zero terminates the chain |
| 8 | `payload_size` | Payload bytes |
| Following bytes | 0–7 | Alignment/slack |

The next physical fragment starts at:

```text
next_offset = current_offset + align_up(8 + payload_size, 8)
```

Maximum payload at offset 48 is 4,048 bytes. Kind `0xFFFF` marks free space;
it is handled before masking the low 15 bits. A zero header terminates the
page's initialized fragment area. Free fragments, private resources, padding
and whole pages are retained, but only primary-indexed logical records feed
financial tables.

### Packed pointers and record reconstruction

For 32-bit pointer `v`:

```text
physical_page = v & 0x000FFFFF
page_offset = 48 + (v >> 20)
```

The low 20 bits are the page number, and the high 12 bits are a byte offset
relative to 48, not an absolute file offset. Page zero is not a valid record
location. A zero pointer terminates; a pointer with zero low bits but nonzero
high bits is invalid. Logical payloads are the ordered concatenation of their
fragment payloads, excluding all headers and padding.

The reader rejects missing fragments, loops, pointers into free space, changed
record types across fragments, shared fragments, duplicate logical identities,
and total lengths that disagree with the index.

## Primary-index pages: type 8

| Offset | Size | Field |
| --- | ---: | --- |
| `0x30` | 4 | Entry width, 12 bytes in the supported layout |
| `0x34` | 2 | Number of entries on this page |
| `0x36` | `12 * count` | Entries |
| Following bytes | Remainder | Slack, preserved in the page BLOB |

Each entry is three little-endian `u32` values:

```text
first_fragment_pointer, total_logical_payload_bytes, legacy_id
```

At most 337 entries fit. Multiple primary-index pages can contain the same
record type; a string dictionary is spread across two pages. The
logical identity is **(record_type, legacy_id)**, never `legacy_id` alone.
The SQLite archive uses a separate integer `record_id` to join these records.

Private type-6 resources are not type-8-indexed; their physical fragments and
complete source bytes are still retained. The converter verifies that every
active first fragment on type-9 pages belongs to exactly one indexed record.

## Logical record inventory

The examined format has these indexed logical types. Descriptions marked opaque
are not promoted to interpreted financial fields.

| Hex type | Decimal | Interpretation |
| --- | ---: | --- |
| `00` | 0 | String dictionary |
| `38` | 56 | Opaque |
| `4F` | 79 | Opaque |
| `55` | 85 | Opaque |
| `56` | 86 | Opaque |
| `5B` | 91 | Opaque |
| `67` | 103 | Opaque |
| `68` | 104 | Opaque |
| `79` | 121 | Opaque |
| `80` | 128 | Account and category headers |
| `96` | 150 | QUID identifier mappings |
| `9B` | 155 | Saved-report-like payloads; opaque |
| `9C` | 156 | Opaque |
| `A0` | 160 | UI-label-like payloads; opaque |
| `A3` | 163 | Opaque |
| `A6` | 166 | Opaque |
| `A7` | 167 | Opaque |
| `AC` | 172 | Opaque |
| `AF` | 175 | Ledger entries |
| `B0` | 176 | Transaction auxiliary records; opaque |
| `C4` | 196 | Security/name-like payloads; opaque |
| `C9` | 201 | View/settings-like payloads; opaque, 5,760 bytes each |

Human-readable labels alone are insufficient to identify a record's complete
semantics. Types `B1`–`B6` are grouped with transactions by the native metadata;
none occur here. They are not assumed to be fully understood split/investment
layouts. A future file containing them gets an explicit warning, with raw
payloads retained. The absence of those subtypes is not a universal statement
about every way Quicken represents splits.

## Decoded logical payloads

Offsets in this section begin at the logical payload, after fragment headers
have been removed. Only these known layouts receive semantic decoding.

### `00`: shared strings, variable length

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 4 | Legacy ID, must match index key |
| 4 | 4 | Stored legacy hash; algorithm not established |
| 8 | 2 | Legacy flags; not interpreted |
| 10 | Remainder | NUL-terminated byte string and possible trailing bytes |

The reader uses Windows cp1252 for display, based on the observed Windows
file. This is not a universal encoding guarantee for all regional editions.
Undefined bytes display as U+FFFD. The complete original text bytes, including
NUL and trailing bytes, remain in `strings.original_text_bytes`; the full
payload also remains in `legacy_records`.

### `80`: account/category headers, 702 bytes

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 4 | Legacy ID, must match index key |
| 4 | 1 | Kind: observed 0 income, 1 expense, 3 bank account |
| 5 | 256 | NUL-terminated name field in the supported layout |
| 261–701 | 441 | Undecoded fields, preserved |

Kinds other than 0, 1 and 3 fail semantic conversion. Category IDs and
account IDs share this record type. Parent category links are inferred only
from a colon-delimited name with a unique matching parent header; this is a
conversion rule, not a decoded on-disk parent pointer. Original full names and
spelling are unchanged. Currency fields are not understood; SQL currency codes
remain NULL.

### `96`: QUID mappings, 34 bytes

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 4 | Quicken QUID; index key |
| 4 | 4 | Target legacy record ID |
| 8 | 2 | Target record type |
| 10–33 | 24 | Undecoded fields |

These are distinct from per-type IDs. All target links must resolve. Observed target types include `AF`, `80`, and `A3`. The archive preserves all
mappings, and `ledger` exposes transaction QUIDs.

### `AF`: ledger entries, 133 bytes

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 4 | Legacy entry ID; index key |
| 4 | 2 | Account ID |
| 6 | 1 | Calendar day |
| 7 | 1 | Calendar month |
| 8 | 2 | Year minus 1900 in this layout |
| 10–35 | 26 | Undecoded transaction fields |
| 36 | 8 | Signed little-endian integer amount, legacy cents |
| 44–77 | 34 | Undecoded transaction fields |
| 78 | 2 | Category/account reference; zero means absent |
| 80 | 2 | Class reference; all zero in the examined entries |
| 82–98 | 17 | Undecoded fields/flags |
| 99 | 4 | Payee dictionary reference |
| 103 | 4 | Memo dictionary reference |
| 107 | 4 | Additional dictionary slot; meaning unverified |
| 111 | 4 | Additional dictionary slot; meaning unverified |
| 115 | 4 | Additional dictionary slot; meaning unverified |
| 119 | 4 | Additional dictionary slot; meaning unverified |
| 123 | 4 | Additional dictionary slot; meaning unverified |
| 127 | 4 | Additional dictionary slot; meaning unverified |
| 131–132 | 2 | Undecoded trailing bytes |

All eight nonzero dictionary references must resolve. Zero references map to
SQL NULL. The memo may contain imported bank wording; payee and memo are
separate fields. ISO dates are
validated with `datetime.date`. Monetary values remain signed integers with
scale 100; no binary floating-point conversion is involved.

References to actual category headers become `category_id`. References to a
different account become `transfer_account_id`. An entry referencing its own
account with the source payee exactly `Opening Balance` is classified as an
opening balance. That is a deliberate semantic inference using two pieces of
source evidence, not an independent disk flag. The original numeric reference
is always retained.

A missing nonzero category reference remains numeric and generates a warning;
it is not replaced by a payee-based guess. Nonzero class references are retained
with an unparsed-class warning. Reconciliation status, check numbers, tax,
investment and other flags remain undecoded.

### `B0`: auxiliary transaction data

Each observed payload has 102 bytes and its first `u32` matches the entry ID.
The remainder contains UUID-like and other fields, but their exact meanings
have not been established. The converter links the entire auxiliary record to
the entry without assigning unsupported semantic column names.

## Companion files

These files are archived byte-for-byte in `source_files`. HCX history also has
a decoded export, separate from QDF transactions:

| Extension | Observation |
| --- | --- |
| `.QSD` | May begin with a `QW Ver. 3.00.00` marker and filename; settings-like content |
| `.HCX` | Historical currency exchange-rate database; see the [HCX specification](hcx-format.md) |
| `.QPH` | Security prices, volume and splits; versions 1–3 supported |
| `.QEL` | Online objects: validated C-Index tree and reassembled serialized records |
| `.IDX` | QDF index cache: offset/length directory and array segments |

The HCX decoder follows Quicken 2002's enhanced multi-currency module and its
index library, corroborated by a later vendor sample. It exports native currency
references, dates, binary32 rates and flags, with raw nodes and index entries.
It does not infer currency names or apply historical rates to ledger amounts.
QSD format-3 record boundaries, names, IDs and deleted versions are decoded;
settings-specific bodies remain opaque. See [companion details](companion-formats.md).
The reader never regenerates or modifies companions.

## SQLite mapping and validation boundary

[The packaged schema](../src/quicken_qdf/schema.sql) defines STRICT tables,
foreign keys and a `ledger` view. Raw sources → verified pages → physical
fragments → indexed logical records → interpreted tables form the provenance
chain. Unknown page types, fields, free fragments and opaque payloads remain
available. The `ledger` view joins interpreted transaction fields; `source_files`,
`pages`, `record_fragments`, `legacy_records` and `record_parts` retain raw evidence.
SQLite `user_version=2` adds the `hcx_*`, `qph_*`, `qsd_*`, `qel_*` and `idx_*` tables;
the existing QDF tables
retain their columns and meaning. The exporter still creates a new database
and does not migrate existing exports.

The converter builds a **new** database, enforces foreign keys, writes in one
data transaction, checks `integrity_check` and `foreign_key_check`, and verifies
that input snapshots are unchanged. It never upgrades an existing export;
`O_EXCL` rejects existing output paths. Failed conversion removes its partial
output. Exported data is plaintext SQLite, including the original source BLOBs.

Tests are divided by evidence:

- Independent RFC vectors establish RC5 correctness, including CBC chaining,
  rotation edge cases, different key lengths and retained padding bytes.
- Fabricated archives exercise pointers, page checksums, continued records,
  SQL types/links, unresolved categories and failed-output cleanup. Their
  encryption helper is test setup, not an independent cipher oracle.
- Private-file regression manifests and financial exports are not distributed.

## Crypto library assessment

The [Python standard library's crypto modules](https://docs.python.org/3/library/crypto.html)
provide hashing and digest comparison, but no RC5 block cipher.
[`cryptography`'s cipher API](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/)
and [PyCryptodome's supported primitives](https://www.pycryptodome.org/src/features)
do not expose RC5. They cannot replace this decryptor without changing the
algorithm, which would make the legacy data unreadable.

[OpenSSL documents RC5](https://docs.openssl.org/master/man7/EVP_CIPHER-RC5/) as
an optional legacy-provider cipher. The installed OpenSSL default/legacy cipher
inventory does not include it. Depending on a custom OpenSSL build plus a new
binding would add deployment and maintenance work. Consequently the converter
keeps its small typed RC5 decryptor and uses standard-library MD5 and digest
comparison. No unrelated or obsolete crypto package is added solely to avoid
this implementation.
