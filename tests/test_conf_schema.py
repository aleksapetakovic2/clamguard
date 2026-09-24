"""The option catalogue: coverage, types and validation."""

from __future__ import annotations

import re
import shutil
import subprocess
import unittest

from .support import qt_application

from clamguard.core import conf_schema as cs


class TestSchemaShape(unittest.TestCase):
    def setUp(self) -> None:
        qt_application()

    def test_no_duplicate_keys(self) -> None:
        for schema in (cs.CLAMD_SCHEMA, cs.FRESHCLAM_SCHEMA):
            keys = [option.key.lower() for option in schema.options]
            self.assertEqual(len(keys), len(set(keys)), schema.file)

    def test_every_option_belongs_to_a_declared_group(self) -> None:
        for schema in (cs.CLAMD_SCHEMA, cs.FRESHCLAM_SCHEMA):
            for option in schema.options:
                self.assertIn(option.group, schema.groups,
                              f"{option.key} is in an unknown group")

    def test_every_group_has_at_least_one_option(self) -> None:
        for schema in (cs.CLAMD_SCHEMA, cs.FRESHCLAM_SCHEMA):
            for group in schema.groups:
                self.assertTrue(schema.in_group(group), f"{group} is empty")

    def test_enums_declare_their_choices(self) -> None:
        for schema in (cs.CLAMD_SCHEMA, cs.FRESHCLAM_SCHEMA):
            for option in schema.options:
                if option.kind == cs.ENUM:
                    self.assertTrue(option.choices, option.key)

    def test_lookup_is_case_insensitive(self) -> None:
        self.assertIsNotNone(cs.CLAMD_SCHEMA.get("maxthreads"))
        self.assertIsNotNone(cs.CLAMD_SCHEMA.get("MAXTHREADS"))
        self.assertIsNone(cs.CLAMD_SCHEMA.get("NotAnOption"))

    def test_search_matches_key_label_and_group(self) -> None:
        by_key = [o.key for o in cs.CLAMD_SCHEMA.search("MaxThreads")]
        self.assertIn("MaxThreads", by_key)
        by_label = [o.key for o in cs.CLAMD_SCHEMA.search("macro")]
        self.assertIn("AlertOLE2Macros", by_label)
        by_group = cs.CLAMD_SCHEMA.search("bytecode")
        self.assertTrue(by_group)

    def test_search_with_no_terms_returns_everything(self) -> None:
        self.assertEqual(len(cs.CLAMD_SCHEMA.search("   ")),
                         len(cs.CLAMD_SCHEMA.options))


class TestCoverageAgainstClamav(unittest.TestCase):
    """The schema should describe every option the installed ClamAV knows."""

    def test_schema_matches_clamconf(self) -> None:
        if not shutil.which("clamconf"):
            self.skipTest("clamconf is not installed")

        result = subprocess.run(["clamconf"], capture_output=True, text=True,
                                timeout=60, check=False)
        known: dict[str, set[str]] = {cs.CLAMD: set(), cs.FRESHCLAM: set()}
        current = None
        for line in result.stdout.splitlines():
            header = re.match(r"^Config file: (\S+)", line)
            if header:
                current = header.group(1)
                continue
            if line.startswith("Software settings"):
                current = None
            if current in known:
                option = re.match(r"^([A-Za-z][A-Za-z0-9_]*)( disabled| = )", line)
                if option:
                    known[current].add(option.group(1))

        for file, options in known.items():
            if not options:
                continue
            ours = {option.key for option in cs.schema_for(file).options}
            self.assertEqual(options - ours, set(),
                             f"{file}: options ClamAV knows but the schema does not")
            self.assertEqual(ours - options, set(),
                             f"{file}: options in the schema that ClamAV does not know")


class TestSizes(unittest.TestCase):
    def test_parse_size(self) -> None:
        self.assertEqual(cs.parse_size("400M"), 400 * 1024 ** 2)
        self.assertEqual(cs.parse_size("2G"), 2 * 1024 ** 3)
        self.assertEqual(cs.parse_size(" 512k "), 512 * 1024)
        self.assertEqual(cs.parse_size("1024"), 1024)

    def test_parse_size_rejects_nonsense(self) -> None:
        for text in ("", "banana", "40X", "M", "-5M"):
            self.assertIsNone(cs.parse_size(text), text)

    def test_format_size_picks_the_largest_exact_unit(self) -> None:
        self.assertEqual(cs.format_size(400 * 1024 ** 2), "400M")
        self.assertEqual(cs.format_size(1024), "1K")
        self.assertEqual(cs.format_size(1500), "1500")
        self.assertEqual(cs.format_size(0), "0")

    def test_sizes_round_trip(self) -> None:
        for text in ("1K", "100M", "2G"):
            self.assertEqual(cs.format_size(cs.parse_size(text)), text)


class TestValidation(unittest.TestCase):
    def option(self, key: str):
        return cs.CLAMD_SCHEMA.get(key)

    def test_integer_bounds(self) -> None:
        threads = self.option("MaxThreads")
        self.assertIsNone(cs.validate(threads, "10"))
        self.assertIn("at least", cs.validate(threads, "0"))
        self.assertIn("at most", cs.validate(threads, "99999"))
        self.assertIn("whole number", cs.validate(threads, "ten"))

    def test_empty_values_are_allowed(self) -> None:
        """An empty box means "not set", which is always valid."""
        for key in ("MaxThreads", "MaxScanSize", "LogFile", "BytecodeSecurity"):
            self.assertIsNone(cs.validate(self.option(key), ""))

    def test_size_validation(self) -> None:
        size = self.option("MaxScanSize")
        self.assertIsNone(cs.validate(size, "400M"))
        self.assertIn("K, M or G", cs.validate(size, "40X"))

    def test_enum_validation(self) -> None:
        mode = self.option("BytecodeSecurity")
        self.assertIsNone(cs.validate(mode, "Paranoid"))
        self.assertIn("must be one of", cs.validate(mode, "Reckless"))

    def test_paths_must_be_absolute(self) -> None:
        log = self.option("LogFile")
        self.assertIsNone(cs.validate(log, "/var/log/clamav/clamd.log"))
        self.assertIn("absolute", cs.validate(log, "clamd.log"))

    def test_regex_validation(self) -> None:
        exclude = self.option("ExcludePath")
        self.assertIsNone(cs.validate(exclude, r"^/proc/"))
        self.assertIn("regular expression", cs.validate(exclude, "^/proc/["))


if __name__ == "__main__":
    unittest.main()
