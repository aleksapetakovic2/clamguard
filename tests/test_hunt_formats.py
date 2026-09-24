"""Every log format, against lines taken from real files on a real desktop.

The samples here are not invented. They are copied out of Discord's logs,
Chromium's, electron-log's, pacman's, Xorg's and the rest, because a parser
tested against a line somebody made up will pass and then fail on the line
that actually exists.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from .support import qt_application  # noqa: F401  - sets sys.path

from clamguard.core.hunt import formats  # noqa: E402
from clamguard.core.hunt.model import Level  # noqa: E402

CONTEXT = formats.ParseContext(year=2026, month=9)


def parse(format_id: str, line: str, context=CONTEXT):
    return formats.get(format_id).parse(line, context)


def when(event) -> datetime | None:
    return event.when()


class TestJsonLines(unittest.TestCase):
    LINE = ('{"level":"warning","msg":"aihook: ending session",'
            '"reason":"dead-pid","sessionId":"7dda4656",'
            '"time":"2026-08-18T19:42:25.003629+02:00"}')

    def test_it_understands_gitkrakens_line(self) -> None:
        event = parse("jsonl", self.LINE)
        self.assertIsNotNone(event)
        self.assertIs(event.level, Level.WARNING)
        self.assertEqual(event.message, "aihook: ending session")
        self.assertEqual(event.extra["reason"], "dead-pid")

    def test_the_offset_in_the_timestamp_is_honoured(self) -> None:
        event = parse("jsonl", self.LINE)
        self.assertEqual(when(event),
                         datetime(2026, 8, 18, 17, 42, 25, 3629, tzinfo=timezone.utc))

    def test_nested_objects_keep_their_shape(self) -> None:
        """So that `Extra.http.status` in a query finds it. Flattening to an
        `http.status` key made member access silently return null."""
        event = parse("jsonl", '{"msg":"x","http":{"status":404,"path":"/a"}}')
        self.assertEqual(event.extra["http"], {"status": 404, "path": "/a"})

    def test_deep_nesting_survives(self) -> None:
        event = parse("jsonl", '{"msg":"x","a":{"b":{"c":1}}}')
        self.assertEqual(event.extra["a"]["b"]["c"], 1)

    def test_numeric_timestamps_are_recognised_by_magnitude(self) -> None:
        for value, expected in (("1758369600", 1758369600),
                                ("1758369600000", 1758369600),
                                ("1758369600000000", 1758369600)):
            with self.subTest(value=value):
                event = parse("jsonl", '{"msg":"x","ts":%s}' % value)
                self.assertEqual(event.timestamp // 1_000_000, expected)

    def test_a_line_that_is_not_json_is_refused(self) -> None:
        self.assertIsNone(parse("jsonl", "{not json"))
        self.assertIsNone(parse("jsonl", "plain text"))
        self.assertIsNone(parse("jsonl", "[1, 2, 3]"))

    def test_a_json_line_with_no_message_key_keeps_the_whole_object(self) -> None:
        event = parse("jsonl", '{"a":1,"b":2}')
        self.assertIn('"a": 1', event.message.replace('"a":1', '"a": 1'))


class TestLogfmt(unittest.TestCase):
    def test_it_understands_a_logfmt_record(self) -> None:
        event = parse("logfmt",
                      'time=2026-01-01T00:00:00Z level=info msg="request served" status=200')
        self.assertIs(event.level, Level.INFO)
        self.assertEqual(event.message, "request served")
        self.assertEqual(event.extra["status"], "200")

    def test_prose_with_an_equals_sign_is_refused(self) -> None:
        """This rejected Valheim's whole log until the pairs had to start the
        line: `[Vulkan init] extensions: name=VK_KHR_surface [enabled=1]`."""
        self.assertIsNone(parse(
            "logfmt",
            "[Vulkan init] extensions: name=VK_EXT_debug_utils [enabled=0, external=0]"))

    def test_one_pair_is_not_enough(self) -> None:
        self.assertIsNone(parse("logfmt", "x=1"))


class TestLevelFirst(unittest.TestCase):
    LINE = ("INFO  2026-01-31T17:12:33 +73ms service=server method=GET "
            "path=/event request")

    def test_it_understands_opencodes_line(self) -> None:
        event = parse("level-logfmt", self.LINE)
        self.assertIs(event.level, Level.INFO)
        self.assertEqual(event.extra["service"], "server")
        self.assertEqual(event.extra["elapsed"], "+73ms")
        self.assertEqual(event.message, "request")


class TestElectron(unittest.TestCase):
    def test_it_understands_claudes_line(self) -> None:
        event = parse("electron", "2026-08-31 08:20:07 [info] Starting app")
        self.assertIs(event.level, Level.INFO)
        self.assertEqual(event.message, "Starting app")
        self.assertIsNotNone(event.timestamp)

    def test_a_bracketed_word_that_is_not_a_level_is_refused(self) -> None:
        self.assertIsNone(parse("electron", "2026-08-31 08:20:07 [gpu] something"))


class TestBracketLevel(unittest.TestCase):
    def test_it_understands_antigravitys_line(self) -> None:
        event = parse("bracket-level",
                      "[2026-07-14 00:00:25.923] [info]  [IDE Wizard] All conditions met")
        self.assertIs(event.level, Level.INFO)
        self.assertEqual(event.message, "[IDE Wizard] All conditions met")
        self.assertEqual(when(event).microsecond, 923000)


class TestBracketColon(unittest.TestCase):
    def test_it_understands_sunshines_line(self) -> None:
        event = parse("bracket-colon",
                      "[2026-09-21 12:43:26.859]: Info: Sunshine version: 2026.914")
        self.assertIs(event.level, Level.INFO)
        self.assertEqual(event.message, "Sunshine version: 2026.914")


class TestAbseil(unittest.TestCase):
    def test_it_understands_discords_line(self) -> None:
        event = parse("abseil",
                      "[2026-Feb-19 13:40:38.726 +01:00][12469:12470][info ] "
                      "Logging initialized")
        self.assertIs(event.level, Level.INFO)
        self.assertEqual(event.extra["pid"], 12469)
        self.assertEqual(event.extra["tid"], 12470)
        self.assertEqual(when(event),
                         datetime(2026, 2, 19, 12, 40, 38, 726000, tzinfo=timezone.utc))

    def test_a_right_aligned_pid_still_parses(self) -> None:
        """Discord pads the pid, which broke a quarter of its own log."""
        event = parse("abseil",
                      "[2026-Mar-04 08:40:22.682 +01:00][ 4858: 4858][info ] x")
        self.assertIsNotNone(event)
        self.assertEqual(event.extra["pid"], 4858)


class TestChromium(unittest.TestCase):
    LINE = ("[19013:19014:0201/090818.844525:ERROR:viz_main_impl.cc(166)] "
            "Exiting GPU process")

    def test_it_understands_steams_embedded_browser(self) -> None:
        event = parse("chromium", self.LINE)
        self.assertIs(event.level, Level.ERROR)
        self.assertEqual(event.extra["pid"], 19013)
        self.assertEqual(event.extra["origin"], "viz_main_impl.cc(166)")
        self.assertEqual(event.message, "Exiting GPU process")

    def test_the_year_comes_from_the_file_because_the_line_omits_it(self) -> None:
        event = parse("chromium", self.LINE, formats.ParseContext(year=2026, month=9))
        self.assertEqual(when(event).year, 2026)

    def test_a_december_line_in_a_january_file_is_last_year(self) -> None:
        context = formats.ParseContext(year=2026, month=1)
        event = parse("chromium",
                      "[1:1:1224/090818.000000:INFO:x.cc(1)] y", context)
        self.assertEqual(when(event).year, 2025)

    def test_an_impossible_date_is_refused(self) -> None:
        self.assertIsNone(parse("chromium", "[1:1:9999/090818.0:INFO:x.cc(1)] y"))


class TestPacman(unittest.TestCase):
    def test_it_understands_an_alpm_line(self) -> None:
        event = parse("pacman", "[2026-01-31T13:10:07+0000] [ALPM] transaction started")
        self.assertEqual(event.extra["subsystem"], "ALPM")
        self.assertEqual(event.message, "transaction started")
        self.assertEqual(when(event),
                         datetime(2026, 1, 31, 13, 10, 7, tzinfo=timezone.utc))

    def test_a_warning_line_is_a_warning(self) -> None:
        event = parse("pacman", "[2026-01-31T13:10:07+0000] [ALPM] warning: x")
        self.assertIs(event.level, Level.WARNING)


class TestXorg(unittest.TestCase):
    def test_the_number_is_uptime_not_a_timestamp(self) -> None:
        event = parse("xorg", "[    11.303] (EE) Failed to load module")
        self.assertIsNone(event.timestamp)
        self.assertEqual(event.extra["uptime"], 11.303)
        self.assertIs(event.level, Level.ERROR)

    def test_the_marker_decides_the_level(self) -> None:
        self.assertIs(parse("xorg", "[ 1.0] (WW) x").level, Level.WARNING)
        self.assertIs(parse("xorg", "[ 1.0] (II) x").level, Level.INFO)

    def test_an_unknown_marker_is_refused(self) -> None:
        self.assertIsNone(parse("xorg", "[ 1.0] (ZZ) x"))


class TestSyslog(unittest.TestCase):
    def test_it_understands_rfc3164(self) -> None:
        event = parse("syslog", "Sep 21 12:43:26 workstation sshd[1234]: Accepted publickey")
        self.assertEqual(event.extra["host"], "workstation")
        self.assertEqual(event.extra["program"], "sshd")
        self.assertEqual(event.extra["pid"], 1234)
        self.assertEqual(event.message, "Accepted publickey")

    def test_it_understands_rfc5424(self) -> None:
        event = parse("syslog5424",
                      "<34>1 2026-09-21T22:14:15.003Z host app 1234 ID47 - message")
        self.assertIs(event.level, Level.CRITICAL)
        self.assertEqual(event.extra["facility"], 4)
        self.assertEqual(event.message, "message")


class TestPythonAndJava(unittest.TestCase):
    def test_it_understands_clamguards_own_log(self) -> None:
        event = parse("python",
                      "2026-09-21 11:02:03,123 INFO clamguard.scanner: scan started")
        self.assertIs(event.level, Level.INFO)
        self.assertEqual(event.extra["logger"], "clamguard.scanner")
        self.assertEqual(event.message, "scan started")

    def test_a_thread_in_brackets_is_kept(self) -> None:
        event = parse("python",
                      "2026-09-21 11:02:03,123 [main] ERROR app.Thing - broke")
        self.assertEqual(event.extra["thread"], "main")
        self.assertIs(event.level, Level.ERROR)


class TestWebLogs(unittest.TestCase):
    def test_it_understands_a_combined_access_log(self) -> None:
        event = parse("access-log",
                      '127.0.0.1 - alice [21/Sep/2026:11:02:03 +0200] '
                      '"GET /index.html HTTP/1.1" 200 612 "-" "curl/8.0"')
        self.assertEqual(event.extra["status"], 200)
        self.assertEqual(event.extra["method"], "GET")
        self.assertEqual(event.extra["path"], "/index.html")
        self.assertEqual(event.extra["user"], "alice")
        self.assertEqual(event.extra["agent"], "curl/8.0")
        self.assertIs(event.level, Level.INFO)

    def test_the_status_code_sets_the_level(self) -> None:
        for status, level in ((404, Level.WARNING), (500, Level.ERROR),
                              (200, Level.INFO)):
            line = f'1.1.1.1 - - [21/Sep/2026:11:02:03 +0000] "GET / HTTP/1.1" {status} 1'
            with self.subTest(status=status):
                self.assertIs(parse("access-log", line).level, level)

    def test_it_understands_an_nginx_error_line(self) -> None:
        event = parse("nginx-error",
                      "2026/09/21 11:02:03 [error] 1234#0: *1 open() failed")
        self.assertIs(event.level, Level.ERROR)
        self.assertEqual(event.extra["pid"], 1234)


class TestPlain(unittest.TestCase):
    def test_it_never_refuses_a_line(self) -> None:
        for line in ("", "x", "Mono path[0] = '/usr/lib'", "🙂"):
            with self.subTest(line=line):
                self.assertIsNotNone(parse("plain", line))

    def test_a_level_word_near_the_start_is_still_found(self) -> None:
        self.assertIs(parse("plain", "ERROR: could not open").level, Level.ERROR)

    def test_a_level_word_far_into_a_sentence_is_not(self) -> None:
        text = "x" * 100 + " error somewhere"
        self.assertIs(parse("plain", text).level, Level.UNKNOWN)


class TestDetection(unittest.TestCase):
    def sample(self, lines: list[str]) -> formats.Detection:
        return formats.detect(lines, CONTEXT)

    def test_it_picks_the_format_that_understood_the_most(self) -> None:
        found = self.sample(["[2026-09-21 12:43:26.859]: Info: a",
                             "[2026-09-21 12:43:27.000]: Warning: b",
                             "[2026-09-21 12:43:28.000]: Error: c"])
        self.assertEqual(found.format.id, "bracket-colon")
        self.assertEqual(found.confidence, 1.0)

    def test_an_indented_continuation_does_not_count_against_a_format(self) -> None:
        """Claude's log is electron-log with pretty-printed JSON hanging off
        every other line; counting those as failures chose `plain`."""
        found = self.sample([
            "2026-08-31 08:20:07 [info] Starting app {",
            "  appVersion: '1.40609.0',",
            "  isPackaged: true,",
            "}",
            "2026-08-31 08:20:08 [info] Ready",
        ])
        self.assertEqual(found.format.id, "electron")
        self.assertGreater(found.confidence, 0.9)

    def test_nothing_recognisable_falls_back_to_plain(self) -> None:
        found = self.sample(["hello", "world", "nothing here", "at all", "really"])
        self.assertEqual(found.format.id, "plain")

    def test_an_empty_file_is_plain(self) -> None:
        self.assertEqual(self.sample([]).format.id, "plain")
        self.assertEqual(self.sample(["", "  "]).format.id, "plain")

    def test_a_csv_header_is_sniffed(self) -> None:
        found = self.sample(["timestamp,level,message",
                             "2026-01-01T00:00:00Z,error,broke",
                             "2026-01-01T00:00:01Z,info,fine",
                             "2026-01-01T00:00:02Z,info,fine"])
        self.assertEqual(found.format.id, "csv")
        self.assertEqual(found.header, ("timestamp", "level", "message"))

    def test_the_runners_up_are_reported(self) -> None:
        found = self.sample(["2026-09-21 11:02:03,123 INFO a: b"] * 4)
        self.assertTrue(found.runners_up)
        self.assertIn("python", [name for name, _score in found.runners_up])

    def test_a_detection_describes_itself_in_a_sentence(self) -> None:
        self.assertIn("%", self.sample(["[2026-09-21 12:43:26.859]: Info: a"] * 3)
                      .describe())


class TestReadingAWholeFile(unittest.TestCase):
    def test_continuation_lines_join_the_event_before_them(self) -> None:
        lines = ["2026-08-31 08:20:07 [info] Starting app {",
                 "  appVersion: '1.0',",
                 "}",
                 "2026-08-31 08:20:08 [info] Ready"]
        events = list(formats.parse_lines(lines, formats.get("electron"), CONTEXT))
        self.assertEqual(len(events), 2)
        self.assertIn("appVersion", events[0].message)
        self.assertEqual(events[1].message, "Ready")

    def test_a_format_that_does_not_join_leaves_stray_lines_alone(self) -> None:
        lines = ['{"msg":"a"}', "rubbish", '{"msg":"b"}']
        events = list(formats.parse_lines(lines, formats.get("jsonl"), CONTEXT))
        self.assertEqual([event.message for event in events], ["a", "rubbish", "b"])

    def test_line_numbers_are_recorded(self) -> None:
        lines = ['{"msg":"a"}', '{"msg":"b"}']
        events = list(formats.parse_lines(lines, formats.get("jsonl"), CONTEXT))
        self.assertEqual([event.line_number for event in events], [1, 2])

    def test_blank_lines_are_skipped_but_still_counted(self) -> None:
        lines = ['{"msg":"a"}', "", "   ", '{"msg":"b"}']
        events = list(formats.parse_lines(lines, formats.get("jsonl"), CONTEXT))
        self.assertEqual([event.line_number for event in events], [1, 4])

    def test_an_enormous_line_is_truncated_rather_than_held(self) -> None:
        events = list(formats.parse_lines(["x" * (formats.MAX_LINE * 2)],
                                          formats.get("plain"), CONTEXT))
        self.assertLess(len(events[0].message), formats.MAX_LINE + 100)
        self.assertIn("truncated", events[0].message)

    def test_a_runaway_stack_trace_is_capped(self) -> None:
        lines = ["2026-08-31 08:20:07 [error] broke"] + \
                ["  at frame"] * (formats.MAX_CONTINUATION_LINES + 50)
        events = list(formats.parse_lines(lines, formats.get("electron"), CONTEXT))
        self.assertEqual(len(events), 1)
        self.assertIn("more lines", events[0].message)


class TestTheRegistry(unittest.TestCase):
    def test_every_format_documents_itself(self) -> None:
        for item in formats.catalogue():
            with self.subTest(format=item.id):
                self.assertTrue(item.title)
                self.assertTrue(item.description)
                self.assertTrue(item.parse)

    def test_every_format_understands_its_own_example(self) -> None:
        """The example in the Sources dialog has to be a line that parses, or
        it is teaching the user something false."""
        for item in formats.catalogue():
            if not item.example or item.id == "csv":
                continue
            with self.subTest(format=item.id):
                self.assertIsNotNone(item.parse(item.example, CONTEXT),
                                     f"{item.id} cannot parse its own example")

    def test_an_unknown_format_id_falls_back_to_plain(self) -> None:
        self.assertEqual(formats.get("imaginary").id, "plain")

    def test_the_descriptions_are_available_for_the_ui(self) -> None:
        described = formats.describe_formats()
        self.assertEqual(len(described), len(formats.catalogue()))


class TestTimeConversion(unittest.TestCase):
    def test_the_offset_cache_is_keyed_on_the_hour_so_dst_is_exact(self) -> None:
        """Keyed on the day it would be an hour out for part of two days a
        year; keyed on the hour it is never wrong."""
        first = formats.epoch_us_local(2026, 3, 29, 1, 30, 0)
        second = formats.epoch_us_local(2026, 3, 29, 3, 30, 0)
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertGreater(second, first)

    def test_an_impossible_date_returns_none(self) -> None:
        self.assertIsNone(formats.epoch_us_local(2026, 13, 45, 99, 0, 0))

    def test_iso_timestamps_parse_in_their_many_forms(self) -> None:
        for text in ("2026-09-21T11:02:03Z", "2026-09-21 11:02:03",
                     "2026-09-21T11:02:03.123456+02:00",
                     "2026-09-21 11:02:03,123"):
            with self.subTest(text=text):
                self.assertIsNotNone(formats.parse_iso8601(text))

    def test_something_that_is_not_a_time_is_none(self) -> None:
        self.assertIsNone(formats.parse_iso8601("hello"))


if __name__ == "__main__":
    unittest.main()
