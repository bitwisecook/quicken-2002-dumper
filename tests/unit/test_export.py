"""Portable SQL semantics and export safety tests, independent of personal files."""

import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path

from quicken_qdf import FormatError, convert
from tests.support import financial_records, make_archive, replace_payload


class ExportTests(unittest.TestCase):
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
            with sqlite3.connect(target) as db:
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
            with sqlite3.connect(target) as db:
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
