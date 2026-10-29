# Quicken 2002 dumper

A typed Python reader for the legacy **QDF database version 3** layout used by
Quicken 2002. It exports normalized ledger tables and a complete SQLite archive
of the source bytes, pages and records. Quicken, Wine, Ghidra and a file password
are not required at runtime for this supported database layout.

Reverse engineered using `reverse-engineer-anything` and AI assistance for
binary analysis, implementation and documentation. The format note records
the supporting evidence and the limits of the recovered interpretation.

Requires Python 3.11+ and SQLite 3.37+. There are no runtime dependencies.

```sh
python -m pip install .
quicken-qdf /path/to/input.QDF /path/to/new-export.sqlite --companion /path/to/input.QSD --companion /path/to/input.HCX --report /path/to/new-report.json
```

Companions and the JSON report are optional. Output paths must be new: existing
files are never overwritten. Inputs remain unchanged. Exports contain plaintext
financial data, including source-file BLOBs; keep them private.

An `.HCX` companion is also decoded into `hcx_exchange_rates`: historical
currency references, dates, floating-point rates and legacy flags. The export
retains its header, B-tree nodes and index entries in `hcx_files`, `hcx_nodes`
and `hcx_index_entries`, as well as the complete original file. Currency names
and conversion direction are not inferred. A valid empty HCX has zero rate rows;
an invalid or unsupported HCX stops the conversion. See the
[HCX format note](docs/hcx-format.md) for native-reader evidence and limitations.

Other supported companions have their own SQLite tables:

| File | Extraction |
| --- | --- |
| QPH versions 1–3 | Securities, dated close/high/low prices, volume, stock splits; query the `share_prices` view |
| QSD settings format 3 | Named settings records, deleted versions and EOF; bodies remain opaque |
| QEL C-Index | Reassembled, checksummed online objects and their raw indexes; application fields remain opaque |
| IDX cache | Validated directory and array segments; no additional transactions inferred |

See [companion format notes](docs/companion-formats.md) for encodings, historical
adapters, evidence, queries and unsupported variants. Pass each existing file
with another `--companion` option. Other extensions are retained byte-for-byte
and explicitly identified as opaque; the tool does not manufacture missing files.

From a source checkout without installation:

```sh
PYTHONPATH=src python -m quicken_qdf /path/to/input.QDF /path/to/new-export.sqlite
```

Read the [reverse-engineering note](docs/file-format.md) for encryption,
byte layouts, validation, evidence and unresolved fields. The reader is
experimental and specific to this format; financial interpretation has not been
validated against a trusted Quicken export. Unknown fields remain available as
raw records, and unresolved category references remain explicit.

## Development

```sh
uv sync
uv run ruff check src tests/unit tests/support.py
uv run pyright
uv run python -m unittest discover -s tests/unit -t . -v
```

Tests use fabricated archives and independent RFC 2040 crypto vectors. No user
transactions, original Quicken files, recovered databases, logs, vendor binaries
or private-file regression manifests are included in this repository.

## License

The original reader code, tests and reverse-engineering note are dedicated to
the public domain under the [Unlicense](LICENSE). Quicken and Intuit names and
format-identification constants remain the property of their respective owners;
no vendor binaries are distributed.
