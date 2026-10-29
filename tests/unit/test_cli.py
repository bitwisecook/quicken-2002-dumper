"""CLI behavior exercised without a subprocess or an installed command."""

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from quicken_qdf.cli import main
from tests.support import financial_records, make_archive


class CLITests(unittest.TestCase):
    def test_writes_report_and_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target, report = root / "test.qdf", root / "test.sqlite", root / "report.json"
            source.write_bytes(make_archive(financial_records()))
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = main([str(source), str(target), "--report", str(report)])
            self.assertEqual(status, 0)
            self.assertTrue(target.exists())
            self.assertEqual(report.read_text(), stdout.getvalue())

    def test_invalid_input_has_clean_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "invalid.qdf", root / "test.sqlite"
            source.write_bytes(b"broken")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                status = main([str(source), str(target)])
            self.assertEqual(status, 1)
            self.assertIn("Recovery failed:", stderr.getvalue())
            self.assertFalse(target.exists())
