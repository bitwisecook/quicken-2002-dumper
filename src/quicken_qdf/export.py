"""Build a new SQLite archive with typed financial tables and lossless raw records."""

import hashlib
import os
import sqlite3
from collections import Counter
from collections.abc import Sequence
from datetime import date
from importlib.resources import files
from pathlib import Path
from typing import Literal, TypeAlias, cast

from .cindex import NODE_SIZE, CIndex
from .format import QDF, FormatError, FragmentKey, RecordIdentity, u16, u32
from .hcx import HCX
from .idx import IDX
from .qel import QEL
from .qph import QPH
from .qsd import QSD
from .report import AccountCount, RecoveryReport, RecoveryWarning

SourceRole: TypeAlias = Literal["qdf", "companion"]
Snapshot: TypeAlias = tuple[Path, SourceRole, bytes]
RecordIDs: TypeAlias = dict[RecordIdentity, int]
SQLRow: TypeAlias = tuple[object, ...]


def cstring(data: bytes) -> str:
    """Decode the observed cp1252 text, retaining exact source bytes separately."""
    return data.split(b"\0", 1)[0].decode("cp1252", errors="replace")


def _issue(
    db: sqlite3.Connection,
    code: str,
    detail: str,
    record: int | None = None,
    severity: Literal["info", "warning"] = "warning",
) -> None:
    db.execute(
        "INSERT INTO recovery_issues(severity,code,record_id,detail) VALUES(?,?,?,?)",
        (severity, code, record, detail),
    )


def _write_sources(db: sqlite3.Connection, snapshots: Sequence[Snapshot], qdf: QDF) -> None:
    for source_id, (path, role, data) in enumerate(snapshots, 1):
        db.execute(
            "INSERT INTO source_files VALUES(?,?,?,?,?,?)",
            (source_id, path.name, role, len(data), hashlib.sha256(data).hexdigest(), data),
        )
    for number, page in enumerate(qdf.pages):
        start = 8 if number == 0 else 0
        db.execute(
            "INSERT INTO pages VALUES(?,?,?,?,?,?)",
            (number, 1, u16(page, 36) if number else None, page[start : start + 16], 1, page),
        )


def _write_cindex(
    db: sqlite3.Connection, source_id: int, container: CIndex, prefix: Literal["hcx", "qel"]
) -> None:
    db.execute(
        f"INSERT INTO {prefix}_files VALUES(?,?,?,?,?)",
        (source_id, container.header, NODE_SIZE, container.root_node, container.record_count),
    )
    db.executemany(
        f"INSERT INTO {prefix}_nodes VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (
            (
                source_id,
                n.number,
                n.file_offset,
                n.level,
                n.left_child,
                n.next_node,
                n.previous_node,
                n.entry_count,
                n.free_bytes,
                n.data,
                int(n.active),
            )
            for n in container.nodes
        ),
    )
    db.executemany(
        f"INSERT INTO {prefix}_index_entries VALUES(?,?,?,?,?,?,?,?,?,?)",
        (
            (
                source_id,
                r.node_number,
                r.node_offset,
                r.index_number,
                int(r.duplicate),
                r.record_number,
                r.key,
                r.payload,
                r.child_node,
                r.raw,
            )
            for r in container.index_records
        ),
    )


def _write_hcx(db: sqlite3.Connection, snapshots: Sequence[Snapshot]) -> None:
    for source_id, (path, role, data) in enumerate(snapshots, 1):
        if role != "companion" or path.suffix.lower() != ".hcx":
            continue
        hcx = HCX(data)
        _write_cindex(db, source_id, hcx, "hcx")
        for record in hcx.records:
            packed = record.packed_date
            try:
                rate_date = date((packed >> 16) + 1900, (packed >> 8) & 255, packed & 255)
            except ValueError as error:
                raise FormatError(f"HCX record {record.record_number}: invalid date") from error
            db.execute(
                "INSERT INTO hcx_exchange_rates VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    source_id,
                    record.record_number,
                    record.currency_ref,
                    rate_date.isoformat(),
                    packed,
                    record.rate,
                    record.flags,
                    record.page_number,
                    record.page_offset,
                    record.payload,
                ),
            )
        if hcx.records:
            _issue(
                db,
                "hcx_currency_identity",
                f"{path.name}: currency references are legacy IDs; currency names and "
                "rate direction are not inferred and rates are not applied to ledger amounts",
                severity="info",
            )


def _legacy_date(packed: int, context: str) -> str:
    try:
        return date((packed >> 16) + 1900, (packed >> 8) & 255, packed & 255).isoformat()
    except ValueError as error:
        raise FormatError(f"{context}: invalid date") from error


def _write_other_companions(db: sqlite3.Connection, snapshots: Sequence[Snapshot]) -> None:
    for source_id, (path, role, data) in enumerate(snapshots, 1):
        if role != "companion":
            continue
        suffix = path.suffix.lower()
        if suffix == ".qph":
            qph = QPH(data)
            db.execute("INSERT INTO qph_files VALUES(?,?,?)", (source_id, qph.version, qph.header))
            db.executemany(
                "INSERT INTO qph_symbols VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    (
                        source_id,
                        s.offset,
                        s.next_offset,
                        s.identity_type,
                        s.symbol,
                        s.exchange_code,
                        s.stored_exchange_code,
                        s.file_identity,
                        s.security_ref,
                        s.quote_head,
                        s.raw,
                    )
                    for s in qph.symbols
                ),
            )
            db.executemany(
                "INSERT INTO qph_quotes VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    (
                        source_id,
                        q.offset,
                        q.symbol_offset,
                        q.next_offset,
                        _legacy_date(q.packed_date, f"QPH quote at {q.offset}"),
                        q.packed_date,
                        q.priority,
                        q.kind,
                        q.field_mask,
                        q.close,
                        q.high,
                        q.low,
                        q.volume,
                        q.volume_base,
                        q.volume_multiplier,
                        q.split_numerator,
                        q.split_denominator,
                        q.status,
                        q.raw,
                    )
                    for q in qph.quotes
                ),
            )
            for kind, records in (
                ("free_symbol", qph.free_symbols),
                ("free_quote", qph.free_quotes),
            ):
                db.executemany(
                    "INSERT INTO qph_unused_regions VALUES(?,?,?,?,?)",
                    ((source_id, r.offset, kind, r.next_offset, r.raw) for r in records),
                )
            db.executemany(
                "INSERT INTO qph_unused_regions VALUES(?,?,?,NULL,?)",
                ((source_id, r.offset, "unclaimed", r.data) for r in qph.unclaimed_regions),
            )
            unknown_symbols = sorted({s.identity_type for s in qph.symbols} - {1, 2})
            unknown_quotes = sorted({q.kind for q in qph.quotes} - {0, 1})
            if unknown_symbols or unknown_quotes:
                _issue(
                    db,
                    "qph_unparsed_kinds",
                    f"{path.name}: symbol kinds {unknown_symbols}, quote kinds {unknown_quotes} "
                    "retain raw bytes with nullable interpreted values",
                )
        elif suffix == ".qsd":
            qsd = QSD(data)
            db.execute(
                "INSERT INTO qsd_files VALUES(?,?,?,?,?,?)",
                (
                    source_id,
                    qsd.identification,
                    qsd.major_version,
                    qsd.minor_version,
                    qsd.revision,
                    qsd.header,
                ),
            )
            db.executemany(
                "INSERT INTO qsd_records VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    (
                        source_id,
                        r.number,
                        r.file_offset,
                        r.record_type,
                        r.legacy_id,
                        int(r.deleted),
                        int(r.is_eof),
                        r.name,
                        r.name_bytes,
                        r.header,
                        r.payload,
                        r.trailer,
                    )
                    for r in qsd.records
                ),
            )
            _issue(
                db,
                "qsd_payloads_uninterpreted",
                f"{path.name}: settings record bodies "
                "remain opaque; physical deleted versions and EOF are retained",
                severity="info",
            )
        elif suffix == ".qel":
            qel = QEL(data)
            _write_cindex(db, source_id, qel, "qel")
            for record in qel.records:
                db.execute(
                    "INSERT INTO qel_records VALUES(?,?,?,?,?,?,?,?)",
                    (
                        source_id,
                        record.record_number,
                        record.index1_key,
                        record.index2_key,
                        u16(record.payload),
                        u16(record.payload, 2),
                        record.payload[4],
                        record.payload,
                    ),
                )
                db.executemany(
                    "INSERT INTO qel_record_parts VALUES(?,?,?,?,?)",
                    (
                        (source_id, record.record_number, i, p.node_number, p.node_offset)
                        for i, p in enumerate(record.parts)
                    ),
                )
            _issue(
                db,
                "qel_payloads_uninterpreted",
                f"{path.name}: online objects are reassembled "
                "and checksummed; application fields remain opaque",
                severity="info",
            )
        elif suffix == ".idx":
            idx = IDX(data)
            db.execute("INSERT INTO idx_files VALUES(?,?)", (source_id, idx.header))
            db.executemany(
                "INSERT INTO idx_segments VALUES(?,?,?,?)",
                ((source_id, r.number, r.offset, r.data) for r in idx.segments),
            )
            _issue(
                db,
                "idx_cache_only",
                f"{path.name}: QDF index-cache segments are preserved "
                "as cache evidence, not additional ledger transactions",
                severity="info",
            )
        elif suffix != ".hcx":
            _issue(
                db,
                "opaque_companion",
                f"{path.name}: no decoder; complete original bytes are retained in source_files",
                severity="info",
            )


def _write_records(db: sqlite3.Connection, qdf: QDF) -> RecordIDs:
    fragment_ids: dict[FragmentKey, int] = {}
    for fragment_id, (key, f) in enumerate(qdf.fragments.items(), 1):
        fragment_ids[key] = fragment_id
        db.execute(
            "INSERT INTO record_fragments VALUES(?,?,?,?,?,?,?,?)",
            (
                fragment_id,
                f.page,
                f.offset,
                f.record_type,
                f.kind & 0x8000,
                int(f.kind == 0xFFFF),
                f.next_pointer,
                f.payload,
            ),
        )
    record_ids: RecordIDs = {}
    for record_id, record in enumerate(qdf.records, 1):
        record_ids[(record.record_type, record.legacy_id)] = record_id
        db.execute(
            "INSERT INTO legacy_records VALUES(?,?,?,?,?,?)",
            (
                record_id,
                record.record_type,
                record.legacy_id,
                record.index_page,
                record.index_slot,
                record.payload,
            ),
        )
        db.executemany(
            "INSERT INTO record_parts VALUES(?,?,?)",
            ((record_id, i, fragment_ids[key]) for i, key in enumerate(record.parts)),
        )

    return record_ids


def _write_references(
    db: sqlite3.Connection,
    qdf: QDF,
    record_ids: RecordIDs,
) -> tuple[dict[int, str], dict[int, str], dict[int, str]]:
    strings: dict[int, str] = {}
    accounts: dict[int, str] = {}
    categories: dict[int, str] = {}
    for record in qdf.records:
        kind, legacy_id, payload = record.record_type, record.legacy_id, record.payload
        record_id = record_ids[(kind, legacy_id)]
        if kind in (0, 128, 150, 175, 176) and u32(payload) != legacy_id:
            raise FormatError(f"Record {kind}:{legacy_id}: primary ID mismatch")
        if kind == 0:
            if len(payload) < 11 or b"\0" not in payload[10:]:
                raise FormatError("Invalid dictionary string record")
            strings[legacy_id] = cstring(payload[10:])
            db.execute(
                "INSERT INTO strings VALUES(?,?,?,?,?,?)",
                (
                    legacy_id,
                    record_id,
                    u32(payload, 4),
                    u16(payload, 8),
                    strings[legacy_id],
                    payload[10:],
                ),
            )
        elif kind == 128:
            if len(payload) != 702:
                raise FormatError("Unsupported account/category record layout")
            name, legacy_type = cstring(payload[5:261]), payload[4]
            if legacy_type in (0, 1):
                categories[legacy_id] = name
                db.execute(
                    "INSERT INTO categories VALUES(?,?,?,?,?,NULL)",
                    (
                        legacy_id,
                        record_id,
                        name,
                        name.rsplit(":", 1)[-1],
                        "income" if legacy_type == 0 else "expense",
                    ),
                )
            elif legacy_type == 3:
                accounts[legacy_id] = name
                db.execute(
                    "INSERT INTO accounts VALUES(?,?,?,?,NULL,100)",
                    (legacy_id, record_id, name, legacy_type),
                )
            else:
                raise FormatError(f"Unsupported account type {legacy_type}")
    by_name: dict[str, list[int]] = {}
    for legacy_id, name in categories.items():
        by_name.setdefault(name, []).append(legacy_id)
    for legacy_id, name in categories.items():
        if ":" in name:
            parent_name = name.rsplit(":", 1)[0]
            parents = by_name.get(parent_name, [])
            if len(parents) == 1:
                db.execute("UPDATE categories SET parent_id=? WHERE id=?", (parents[0], legacy_id))
            else:
                _issue(
                    db,
                    "unresolved_category_parent",
                    f"Parent name {parent_name!r} is absent or ambiguous",
                    record_ids[(128, legacy_id)],
                )
    return strings, accounts, categories


def _write_identifiers(db: sqlite3.Connection, qdf: QDF, record_ids: RecordIDs) -> None:
    for record in qdf.records:
        if record.record_type == 150:
            p = record.payload
            if len(p) != 34:
                raise FormatError("Unsupported QUID mapping record")
            target_type, target_id = u16(p, 8), u32(p, 4)
            target = record_ids.get((target_type, target_id))
            if target is None:
                raise FormatError("QUID mapping refers to a missing record")
            db.execute(
                "INSERT INTO legacy_identifiers VALUES(?,?,?,?,?)",
                (
                    record.legacy_id,
                    record_ids[(150, record.legacy_id)],
                    target_type,
                    target_id,
                    target,
                ),
            )


def _write_transactions(
    db: sqlite3.Connection,
    qdf: QDF,
    record_ids: RecordIDs,
    strings: dict[int, str],
    accounts: dict[int, str],
    categories: dict[int, str],
) -> None:
    for record in qdf.records:
        if record.record_type != 175:
            continue
        p, legacy_id = record.payload, record.legacy_id
        record_id = record_ids[(175, legacy_id)]
        if len(p) != 133:
            raise FormatError("Unsupported transaction record layout")
        account = u16(p, 4)
        if account not in accounts:
            raise FormatError(f"Transaction {legacy_id}: missing account {account}")
        posted = date(1900 + u16(p, 8), p[7], p[6]).isoformat()
        amount = int.from_bytes(p[36:44], "little", signed=True)
        category_ref, class_ref = u16(p, 78), u16(p, 80)
        category = category_ref if category_ref in categories else None
        transfer = category_ref if category_ref in accounts and category_ref != account else None
        if class_ref:
            _issue(
                db,
                "unparsed_class",
                f"Class reference {class_ref} is preserved without an interpreted label",
                record_id,
            )
        slots = [(offset, u32(p, offset)) for offset in range(99, 131, 4)]
        for offset, ref in slots:
            if ref and ref not in strings:
                raise FormatError(
                    f"Transaction {legacy_id}: missing string {ref} at offset {offset}"
                )
        payee, memo = slots[0][1] or None, slots[1][1] or None
        # Quicken opening balances reference their own account. Require
        # both that link and the actual source label before interpreting it.
        entry_kind = (
            "opening_balance"
            if category_ref == account and strings.get(payee or 0) == "Opening Balance"
            else "transaction"
        )
        if (
            category_ref
            and category is None
            and transfer is None
            and entry_kind != "opening_balance"
        ):
            _issue(
                db,
                "unresolved_category",
                f"Legacy category reference {category_ref} has no resolved category/transfer",
                record_id,
            )
        auxiliary = record_ids.get((176, legacy_id))
        db.execute(
            "INSERT INTO transactions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                legacy_id,
                record_id,
                account,
                posted,
                amount,
                payee,
                memo,
                category,
                transfer,
                category_ref,
                class_ref,
                auxiliary,
                entry_kind,
            ),
        )
        db.executemany(
            "INSERT INTO transaction_string_slots VALUES(?,?,?,?)",
            ((legacy_id, offset, ref or None, ref) for offset, ref in slots),
        )


def _write_limitations(db: sqlite3.Connection, qdf: QDF) -> None:
    # These grouped transaction subtypes are absent in this source.
    # Keep any future occurrences losslessly but make incomplete decoding visible.
    extra_financial = sorted({r.record_type for r in qdf.records} & set(range(177, 183)))
    if extra_financial:
        _issue(
            db,
            "unparsed_transaction_subtypes",
            f"Raw transaction subtypes {extra_financial} need decoding",
        )
    _issue(
        db,
        "currency_unresolved",
        "Account currency codes are not decoded; amounts retain integer legacy cents",
        severity="info",
    )
    _issue(
        db,
        "semantic_validation",
        "Financial fields are reverse engineered; "
        "no trusted Quicken export was available for comparison",
        severity="info",
    )


def _rows(db: sqlite3.Connection, query: str) -> list[SQLRow]:
    """Isolate sqlite3's dynamically typed boundary; validate used cells below."""
    return cast(list[SQLRow], db.execute(query).fetchall())


def _integer(value: object) -> int:
    if not isinstance(value, int):
        raise FormatError(f"Expected SQLite integer, received {type(value).__name__}")
    return value


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise FormatError(f"Expected SQLite text, received {type(value).__name__}")
    return value


def _optional_text(value: object) -> str | None:
    return None if value is None else _text(value)


def _build_report(
    db: sqlite3.Connection,
    qdf: QDF,
    original: bytes,
    output_path: Path,
) -> RecoveryReport:
    tables = (
        "accounts",
        "categories",
        "strings",
        "transactions",
        "legacy_identifiers",
        "hcx_files",
        "hcx_nodes",
        "hcx_index_entries",
        "hcx_exchange_rates",
        "qph_files",
        "qph_symbols",
        "qph_quotes",
        "qph_unused_regions",
        "qsd_files",
        "qsd_records",
        "qel_files",
        "qel_records",
        "qel_record_parts",
        "idx_files",
        "idx_segments",
    )
    counts = {table: _integer(_rows(db, f"SELECT count(*) FROM {table}")[0][0]) for table in tables}
    dates = _rows(db, "SELECT min(posted_date),max(posted_date) FROM transactions")[0]
    accounts: list[AccountCount] = [
        {"account": _text(row[0]), "transactions": _integer(row[1])}
        for row in _rows(
            db,
            "SELECT a.name,count(*) FROM transactions t "
            "JOIN accounts a ON a.id=t.account_id GROUP BY a.id",
        )
    ]
    warnings: list[RecoveryWarning] = [
        {
            "code": _text(row[0]),
            "detail": _text(row[1]),
            "record_id": None if row[2] is None else _integer(row[2]),
        }
        for row in _rows(
            db,
            "SELECT code,detail,record_id FROM recovery_issues "
            "WHERE severity='warning' ORDER BY id",
        )
    ]
    return {
        "format": "Quicken legacy QDF database v3",
        "output": str(output_path),
        "source_sha256": hashlib.sha256(original).hexdigest(),
        "sources_unchanged": True,
        "password_needed_for_block_decryption": False,
        "password_hint_tested": False,
        "pages_verified": len(qdf.pages),
        "indexed_records": len(qdf.records),
        "physical_fragments": len(qdf.fragments),
        "record_type_counts": dict(sorted(Counter(r.record_type for r in qdf.records).items())),
        "counts": counts,
        "date_range": [_optional_text(cell) for cell in dates],
        "account_transaction_counts": accounts,
        "entry_kind_counts": {
            _text(row[0]): _integer(row[1])
            for row in _rows(db, "SELECT entry_kind,count(*) FROM transactions GROUP BY entry_kind")
        },
        "warnings": warnings,
        "sqlite_integrity": "ok",
        "foreign_key_violations": 0,
    }


def convert(
    qdf_path: Path,
    output_path: Path,
    companion_paths: Sequence[Path] = (),
) -> RecoveryReport:
    """Create an exclusive SQLite export; remove it on any conversion failure.

    Input paths are never opened for writing. No existing export is overwritten.
    The returned report is JSON-serializable and includes all interpretation warnings.
    """
    if sqlite3.sqlite_version_info < (3, 37, 0):
        raise FormatError("SQLite 3.37 or newer is required for STRICT tables")
    snapshots: list[Snapshot] = [(qdf_path, "qdf", qdf_path.read_bytes())]
    snapshots.extend((p, "companion", p.read_bytes()) for p in companion_paths)
    qdf = QDF(snapshots[0][2])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    db: sqlite3.Connection | None = None
    try:
        db = sqlite3.connect(output_path)
        db.executescript(files("quicken_qdf").joinpath("schema.sql").read_text(encoding="utf-8"))
        with db:
            _write_sources(db, snapshots, qdf)
            _write_hcx(db, snapshots)
            _write_other_companions(db, snapshots)
            record_ids = _write_records(db, qdf)
            strings, accounts, categories = _write_references(db, qdf, record_ids)
            _write_identifiers(db, qdf, record_ids)
            _write_transactions(db, qdf, record_ids, strings, accounts, categories)
            _write_limitations(db, qdf)
            db.execute("PRAGMA application_id = 1213285963")
        if _rows(db, "PRAGMA integrity_check") != [("ok",)]:
            raise FormatError("SQLite integrity check failed")
        if _rows(db, "PRAGMA foreign_key_check"):
            raise FormatError("SQLite foreign-key validation failed")
        for path, _, data in snapshots:
            if path.read_bytes() != data:
                raise FormatError(f"Source changed during recovery: {path.name}")
        return _build_report(db, qdf, snapshots[0][2], output_path)
    except BaseException:
        # Also clean up on cancellation; never leave a partial export presented as complete.
        if db is not None:
            db.close()
            db = None
        output_path.unlink(missing_ok=True)
        raise
    finally:
        if db is not None:
            db.close()
