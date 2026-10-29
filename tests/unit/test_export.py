"""Portable SQL semantics and export safety tests, independent of personal files."""

import sqlite3
import struct
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from quicken_qdf import FormatError, convert
from tests.support import financial_records, make_archive, replace_payload
from tests.unit.test_hcx import make_hcx
from tests.unit.test_other_companions import make_idx, make_qel
from tests.unit.test_qph import make_qph
from tests.unit.test_qsd import make_qsd


class ExportTests(unittest.TestCase):
    def test_unknown_qph_kinds_are_preserved_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target, companion = root / "test.qdf", root / "test.sqlite", root / "test.qph"
            source.write_bytes(make_archive(financial_records()))
            original = make_qph(unknown=True)
            companion.write_bytes(original)
            report = convert(source, target, [companion])
            self.assertEqual([w["code"] for w in report["warnings"]], ["qph_unparsed_kinds"])
            with closing(sqlite3.connect(target)) as db:
                self.assertEqual(
                    db.execute("SELECT kind,close FROM qph_quotes WHERE kind=9").fetchone(),
                    (9, None),
                )
                self.assertEqual(
                    db.execute("SELECT original_bytes FROM source_files WHERE id=2").fetchone(),
                    (original,),
                )

    def test_other_companions_have_typed_rows_and_complete_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "test.qdf", root / "test.sqlite"
            source.write_bytes(make_archive(financial_records()))
            images = {"qph": make_qph(), "qsd": make_qsd(), "qel": make_qel(), "idx": make_idx()}
            paths = [root / f"history.{kind}" for kind in images]
            for path, data in zip(paths, images.values(), strict=True):
                path.write_bytes(data)
            report = convert(source, target, paths)
            self.assertEqual(report["warnings"], [])
            with closing(sqlite3.connect(target)) as db:
                self.assertEqual(db.execute("PRAGMA integrity_check").fetchone(), ("ok",))
                self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
                self.assertEqual(
                    db.execute(
                        "SELECT symbol,quote_date,close,high,low,volume FROM share_prices"
                    ).fetchone(),
                    ("SYNTH", "2004-07-11", 12.5, 13.25, -2.0, 4294967294),
                )
                self.assertEqual(
                    db.execute(
                        "SELECT split_numerator,split_denominator FROM qph_quotes WHERE kind=1"
                    ).fetchone(),
                    (3.0, 2.0),
                )
                self.assertEqual(
                    db.execute("SELECT count(*) FROM qsd_current_records").fetchone(), (2,)
                )
                self.assertEqual(
                    db.execute("SELECT count(*) FROM qel_record_parts").fetchone(), (2,)
                )
                self.assertEqual(db.execute("SELECT count(*) FROM idx_segments").fetchone(), (4,))
                for name, original in db.execute("SELECT name,original_bytes FROM source_files"):
                    self.assertEqual((root / name).read_bytes(), original)
                header = db.execute("SELECT header_bytes FROM qsd_files").fetchone()[0]
                rows = db.execute(
                    "SELECT header_bytes,payload,trailer_bytes FROM qsd_records "
                    "ORDER BY record_number"
                ).fetchall()
                self.assertEqual(header + b"".join(h + p + t for h, p, t in rows), images["qsd"])
            for path, original in zip(paths, images.values(), strict=True):
                self.assertEqual(path.read_bytes(), original)

    def test_bad_decoded_companions_never_become_empty_successful_exports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "test.qdf"
            source.write_bytes(make_archive(financial_records()))
            for kind in ("qph", "qsd", "qel", "idx"):
                with self.subTest(kind=kind):
                    companion, target = root / f"bad.{kind}", root / f"{kind}.sqlite"
                    companion.write_bytes(b"invalid")
                    with self.assertRaises(FormatError):
                        convert(source, target, [companion])
                    self.assertFalse(target.exists())
                    self.assertEqual(companion.read_bytes(), b"invalid")

    def test_hcx_rates_and_raw_provenance_are_exported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "test.qdf", root / "test.sqlite"
            companion = root / "history.HcX"
            original = make_archive(financial_records())
            history = make_hcx(split=True, flags=8)
            source.write_bytes(original)
            companion.write_bytes(history)
            report = convert(source, target, [companion])
            self.assertEqual(report["counts"]["hcx_exchange_rates"], 1)
            self.assertEqual(report["warnings"], [])
            with closing(sqlite3.connect(target)) as db:
                self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (2,))
                self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
                self.assertEqual(
                    db.execute(
                        "SELECT currency_ref,rate_date,exchange_rate,legacy_flags "
                        "FROM hcx_exchange_rates"
                    ).fetchone(),
                    (7, "2004-07-11", 1.25, 8),
                )
                header = db.execute("SELECT header_bytes FROM hcx_files").fetchone()
                assert header is not None
                nodes = db.execute(
                    "SELECT node_bytes FROM hcx_nodes ORDER BY node_number"
                ).fetchall()
                self.assertEqual(header[0] + b"".join(row[0] for row in nodes), history)
                self.assertEqual(
                    db.execute("SELECT sum(active),count(*) FROM hcx_nodes").fetchone(), (3, 4)
                )
                self.assertEqual(
                    db.execute("SELECT DISTINCT duplicate FROM hcx_index_entries").fetchall(),
                    [(128,)],
                )
                self.assertEqual(
                    db.execute("SELECT original_bytes FROM source_files WHERE id=2").fetchone(),
                    (history,),
                )
                self.assertEqual(db.execute("SELECT count(*) FROM ledger").fetchone(), (1,))
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(companion.read_bytes(), history)

    def test_multiple_hcx_sources_and_empty_history_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "test.qdf", root / "test.sqlite"
            companions = [root / "first.hcx", root / "second.hcx", root / "empty.hcx"]
            source.write_bytes(make_archive(financial_records()))
            companions[0].write_bytes(make_hcx())
            companions[1].write_bytes(make_hcx(rate=2.5))
            companions[2].write_bytes(make_hcx(populated=False))
            report = convert(source, target, companions)
            self.assertEqual(report["counts"]["hcx_files"], 3)
            self.assertEqual(report["counts"]["hcx_exchange_rates"], 2)
            with closing(sqlite3.connect(target)) as db:
                self.assertEqual(
                    db.execute(
                        "SELECT source_file_id,record_number,exchange_rate "
                        "FROM hcx_exchange_rates ORDER BY source_file_id"
                    ).fetchall(),
                    [(2, 42, 1.25), (3, 42, 2.5)],
                )
                self.assertEqual(
                    db.execute(
                        "SELECT declared_record_count FROM hcx_files WHERE source_file_id=4"
                    ).fetchone(),
                    (0,),
                )

    def test_invalid_hcx_removes_partial_export_and_preserves_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target, companion = root / "test.qdf", root / "test.sqlite", root / "bad.hcx"
            original = make_archive(financial_records())
            source.write_bytes(original)
            history = make_hcx()[:-1]
            companion.write_bytes(history)
            with self.assertRaisesRegex(FormatError, "HCX"):
                convert(source, target, [companion])
            self.assertFalse(target.exists())
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(companion.read_bytes(), history)

    def test_schema_and_lossless_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "test.qdf", root / "test.sqlite"
            original = make_archive(financial_records())
            source.write_bytes(original)
            report = convert(source, target)
            self.assertEqual(report["counts"]["transactions"], 1)
            self.assertEqual(report["counts"]["categories"], 2)
            self.assertEqual(report["warnings"], [])
            with closing(sqlite3.connect(target)) as db:
                self.assertEqual(db.execute("PRAGMA integrity_check").fetchone(), ("ok",))
                self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
                self.assertEqual(
                    db.execute("SELECT original_bytes FROM source_files").fetchone(), (original,)
                )
                self.assertEqual(
                    db.execute(
                        "SELECT posted_date,amount_minor,payee,memo,category,quid FROM ledger"
                    ).fetchone(),
                    (
                        "2026-07-01",
                        -12345,
                        "Example shop",
                        "Fabricated test purchase",
                        "Household:Food",
                        500,
                    ),
                )
                self.assertEqual(
                    db.execute("SELECT parent_id FROM categories WHERE id=4201").fetchone(), (4200,)
                )
            before = target.read_bytes()
            with self.assertRaises(FileExistsError):
                convert(source, target)
            self.assertEqual(target.read_bytes(), before)
            self.assertEqual(source.read_bytes(), original)

    def test_missing_category_is_preserved_and_flagged(self) -> None:
        records = financial_records()
        payload = bytearray(next(p for t, _, p in records if t == 175))
        struct.pack_into("<H", payload, 78, 9999)
        records = replace_payload(records, 175, 100, bytes(payload))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "test.qdf", root / "test.sqlite"
            source.write_bytes(make_archive(records))
            report = convert(source, target)
            self.assertEqual([w["code"] for w in report["warnings"]], ["unresolved_category"])
            with closing(sqlite3.connect(target)) as db:
                self.assertEqual(
                    db.execute(
                        "SELECT category_legacy_ref,unresolved_category FROM ledger"
                    ).fetchone(),
                    (9999, 1),
                )

    def test_failed_conversion_removes_partial_output(self) -> None:
        for offset, value in [(4, 99), (99, 9999)]:
            records = financial_records()
            payload = bytearray(next(p for t, _, p in records if t == 175))
            struct.pack_into("<I" if offset == 99 else "<H", payload, offset, value)
            records = replace_payload(records, 175, 100, bytes(payload))
            with self.subTest(offset=offset), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, target = root / "test.qdf", root / "test.sqlite"
                source.write_bytes(make_archive(records))
                with self.assertRaises(FormatError):
                    convert(source, target)
                self.assertFalse(target.exists())
                self.assertEqual(source.read_bytes(), make_archive(records))
