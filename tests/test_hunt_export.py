"""Getting results out, and the one way an export can hurt somebody.

A cell beginning ``=`` is executed as a formula when a spreadsheet opens the
file, and every cell here holds text that something else wrote into a log. So
the CSV export is the one that gets the most attention.
"""

from __future__ import annotations

import csv
import io
import json
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .support import qt_application  # noqa: F401  - sets sys.path

from clamguard.core.hunt import export  # noqa: E402
from clamguard.core.hunt.model import (  # noqa: E402
    ColumnType,
    QueryStats,
    ResultTable,
)


def sample() -> ResultTable:
    table = ResultTable.of(
        [("Timestamp", ColumnType.DATETIME), ("Level", ColumnType.STRING),
         ("Message", ColumnType.STRING), ("Count", ColumnType.LONG),
         ("Extra", ColumnType.DYNAMIC), ("Gap", ColumnType.TIMESPAN)],
        [(datetime(2026, 9, 21, 14, 30, tzinfo=timezone.utc), "error",
          "something | with a pipe", 3, {"pid": 100}, timedelta(minutes=5)),
         (None, "unknown", "line one\nline two", 0, None, None)])
    table.stats = QueryStats(rows=2, elapsed=0.05, scanned=1000)
    return table


class TestCsv(unittest.TestCase):
    def setUp(self) -> None:
        self.text = export.to_csv(sample())
        self.rows = list(csv.reader(io.StringIO(self.text)))

    def test_the_header_is_the_column_names(self) -> None:
        self.assertEqual(self.rows[0],
                         ["Timestamp", "Level", "Message", "Count", "Extra", "Gap"])

    def test_every_row_is_there(self) -> None:
        self.assertEqual(len(self.rows), 3)

    def test_a_null_is_an_empty_cell_not_the_word_none(self) -> None:
        self.assertEqual(self.rows[2][0], "")
        self.assertEqual(self.rows[2][4], "")

    def test_a_dynamic_value_is_written_as_json(self) -> None:
        self.assertEqual(json.loads(self.rows[1][4]), {"pid": 100})

    def test_a_formula_is_defused(self) -> None:
        """`=cmd|'/c calc'!A1` in a cell attacks whoever opens the export, and
        the text came out of a file somebody else wrote."""
        table = ResultTable.of([("A", ColumnType.STRING)],
                               [("=cmd|'/c calc'!A1",), ("+1",), ("-1",),
                                ("@SUM(1)",), ("ok",)])
        rows = list(csv.reader(io.StringIO(export.to_csv(table))))
        for index in range(1, 5):
            with self.subTest(row=index):
                self.assertTrue(rows[index][0].startswith("\t"),
                                f"{rows[index][0]!r} is still a formula")
        self.assertEqual(rows[5][0], "ok")

    def test_a_newline_inside_a_cell_survives_as_a_quoted_field(self) -> None:
        self.assertIn("line one\nline two", self.rows[2][2])


class TestTsv(unittest.TestCase):
    def test_it_is_tab_separated_with_a_header(self) -> None:
        lines = export.to_tsv(sample()).splitlines()
        self.assertEqual(lines[0].split("\t")[0], "Timestamp")
        self.assertEqual(len(lines), 3)

    def test_newlines_are_flattened_because_this_is_for_pasting(self) -> None:
        self.assertEqual(len(export.to_tsv(sample()).splitlines()), 3)


class TestJson(unittest.TestCase):
    def setUp(self) -> None:
        self.data = json.loads(export.to_json(sample()))

    def test_the_schema_travels_with_the_data(self) -> None:
        self.assertEqual(self.data["columns"][0],
                         {"name": "Timestamp", "type": "datetime"})

    def test_rows_become_objects(self) -> None:
        self.assertEqual(self.data["data"][0]["Level"], "error")
        self.assertEqual(self.data["data"][0]["Count"], 3)

    def test_times_are_iso_and_durations_are_seconds(self) -> None:
        self.assertTrue(self.data["data"][0]["Timestamp"].startswith("2026-09-21"))
        self.assertEqual(self.data["data"][0]["Gap"], 300.0)

    def test_a_dynamic_value_stays_a_real_object(self) -> None:
        self.assertEqual(self.data["data"][0]["Extra"], {"pid": 100})

    def test_it_says_whether_the_result_was_truncated(self) -> None:
        self.assertIn("truncated", self.data)


class TestMarkdown(unittest.TestCase):
    def setUp(self) -> None:
        self.text = export.to_markdown(sample(), query="Logs | take 2")

    def test_the_query_travels_with_the_results(self) -> None:
        self.assertIn("```kql", self.text)
        self.assertIn("Logs | take 2", self.text)

    def test_it_is_a_table(self) -> None:
        self.assertIn("| Timestamp | Level |", self.text)
        self.assertIn("|---|", self.text)

    def test_a_pipe_in_a_cell_is_escaped_so_the_table_survives(self) -> None:
        self.assertIn("something \\| with a pipe", self.text)

    def test_it_says_nothing_left_the_machine(self) -> None:
        self.assertIn("Nothing was sent anywhere", self.text)

    def test_the_statistics_are_included(self) -> None:
        self.assertIn("2 rows", self.text)


class TestWriting(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="clamguard-export-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_every_advertised_format_writes_a_file(self) -> None:
        for name, extension, _description in export.describe_formats():
            with self.subTest(format=name):
                path = export.write(sample(), self.tmp, name)
                self.assertTrue(path.is_file())
                self.assertEqual(path.suffix, f".{extension}")
                self.assertGreater(path.stat().st_size, 20)

    def test_an_unknown_format_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            export.write(sample(), self.tmp, "powerpoint")
        with self.assertRaises(ValueError):
            export.render(sample(), "powerpoint")

    def test_the_filename_carries_the_time(self) -> None:
        path = export.write(sample(), self.tmp, "csv")
        self.assertTrue(path.name.startswith("hunt-"))

    def test_an_empty_result_still_writes_a_header(self) -> None:
        empty = ResultTable.of([("A", ColumnType.STRING)], [])
        self.assertEqual(export.to_csv(empty).strip(), "A")


if __name__ == "__main__":
    unittest.main()
