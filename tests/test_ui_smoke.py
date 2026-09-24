"""An end-to-end pass over the real window.

Builds the actual AppContext and MainWindow, visits every page, and exercises
the interactions a user would perform in the first few minutes. Nothing here
asserts what things look like — it asserts that nothing raises, that each page
builds against real system state, and that the destructive paths are all gated
behind a confirmation.

It runs on Qt's offscreen platform, so it needs no display and is safe in CI.
"""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from .support import TempHomeTestCase, recent_stamps  # noqa: E402


def _widgets_available() -> bool:
    try:
        from PySide6.QtWidgets import QApplication  # noqa: F401
        return True
    except ImportError:
        return False


@unittest.skipUnless(_widgets_available(), "PySide6.QtWidgets is not installed")
class TestWindow(TempHomeTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from .support import qt_application

        cls.app = qt_application()

    def setUp(self) -> None:
        super().setUp()
        self._block_modal_dialogs()
        self._catch_slot_exceptions()
        # Every core module caches `paths` at import time, so the whole package
        # is reloaded after the temporary XDG directories are installed.
        import importlib
        import clamguard.core.history
        import clamguard.core.quarantine
        import clamguard.core.scheduler
        import clamguard.core.context

        for module in (clamguard.core.history, clamguard.core.quarantine,
                       clamguard.core.scheduler, clamguard.core.context):
            importlib.reload(module)

        from clamguard.core.context import AppContext
        from clamguard.ui.main_window import MainWindow, NAV_ITEMS

        self.nav_items = NAV_ITEMS
        self.context = AppContext()
        self.window = MainWindow(self.context)
        self.window.resize(1200, 860)
        # isVisible() is false for every widget until the whole ancestor chain
        # is shown, so the window is shown even on the offscreen platform.
        self.window.show()
        self.app.processEvents()

    def _block_modal_dialogs(self) -> None:
        """Make every confirmation answer "no" instead of waiting for a click.

        A modal dialog in a headless test blocks forever — there is nobody to
        dismiss it. Stubbing exec() at the dialog classes rather than at each
        call site means a *new* confirmation added anywhere cannot hang the
        suite, and every destructive path is exercised as "the user said no",
        which is what these tests want to assert.
        """
        from PySide6.QtWidgets import QDialog, QMessageBox

        from clamguard.ui.dialogs import ConfirmDialog

        self.dialogs_shown: list[str] = []

        def refuse(dialog_self):
            self.dialogs_shown.append(dialog_self.windowTitle())
            return QDialog.DialogCode.Rejected

        self._saved_exec = ConfirmDialog.exec
        ConfirmDialog.exec = refuse
        self.addCleanup(lambda: setattr(ConfirmDialog, "exec", self._saved_exec))

        for name, answer in (("question", QMessageBox.StandardButton.No),
                             ("warning", QMessageBox.StandardButton.Cancel),
                             ("critical", QMessageBox.StandardButton.Ok),
                             ("information", QMessageBox.StandardButton.Ok)):
            saved = getattr(QMessageBox, name)
            setattr(QMessageBox, name,
                    staticmethod(lambda *args, _a=answer, **kwargs: _a))
            self.addCleanup(lambda n=name, s=saved: setattr(QMessageBox, n, s))

    def _catch_slot_exceptions(self) -> None:
        """Fail the test if an exception escapes into a Qt slot.

        PySide prints an exception raised in a slot or a timer callback and
        carries on, so a test passes while the app is quietly broken. That hid
        a real bug: a deferred layout re-check ran against pages already
        destroyed, sixteen tracebacks per run and every test green.
        """
        import sys
        import traceback

        self.slot_exceptions: list[str] = []
        saved = sys.excepthook

        def collect(kind, value, tb):
            self.slot_exceptions.append("".join(traceback.format_exception(kind, value, tb)))

        sys.excepthook = collect
        self.addCleanup(lambda: setattr(sys, "excepthook", saved))

    def tearDown(self) -> None:
        for page in self.window._pages.values():
            page.shutdown()
        self.window.context.shutdown()
        self.window.tray.hide()
        self.window.deleteLater()
        # Twice: the window's deletion is itself deferred, and whatever it
        # leaves pending must run while this test can still see it fail.
        self.app.processEvents()
        self.app.processEvents()
        super().tearDown()
        self.assertEqual(self.slot_exceptions, [],
                         "an exception escaped into a Qt slot:\n"
                         + "\n".join(self.slot_exceptions))

    # -- the basics -------------------------------------------------------

    def test_every_page_builds_and_renders(self) -> None:
        for item in self.nav_items:
            with self.subTest(page=item.page_id):
                self.window.show_page(item.page_id)
                self.app.processEvents()
                page = self.window.current_page()
                self.assertIsNotNone(page, item.page_id)
                self.assertEqual(page.PAGE_ID, item.page_id)
                self.assertFalse(self.window.grab().isNull())

    def test_the_window_is_never_shorter_than_the_sidebar(self) -> None:
        """Adding the Services page made the sidebar 639px tall against a fixed
        620px floor; at the minimum size its status card slid under the last
        entry. The floor now follows the sidebar."""
        self.window.resize(1, 1)
        self.app.processEvents()
        self.assertGreaterEqual(self.window.height(),
                                self.window.sidebar.minimumSizeHint().height())

    def test_every_page_fits_the_minimum_window(self) -> None:
        """Nothing may be cut off at the smallest size the window allows.

        A page body scrolls vertically but never horizontally, so content wider
        than the viewport is not scrollable — it is simply clipped, silently.
        At 940px that cut the Updates page's third card in half, clipped every
        Dashboard card and the Boot Analyzer's facts, and slid the Boot header's
        preset picker over its Savvy toggle. Each page's own minimum, and the
        minimum of anything inside a scroll area that cannot scroll sideways,
        must fit.
        """
        import time

        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QScrollArea

        self.window.resize(*self.window.minimumSize().toTuple())
        self.app.processEvents()
        for item in self.nav_items:
            with self.subTest(page=item.page_id):
                self.window.show_page(item.page_id)
                page = self.window.current_page()
                # Let background loads land and deferred re-layouts run, the
                # way a live event loop would between frames.
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline and any(
                        getattr(getattr(page, attr, None), "busy", False)
                        for attr in ("manager", "analyzer", "indexer")):
                    self.app.processEvents()
                    time.sleep(0.05)
                for _ in range(12):
                    self.app.processEvents()
                    time.sleep(0.02)

                self.assertLessEqual(page.minimumSizeHint().width(), page.width(),
                                     "the page is wider than the window allows")
                for area in page.findChildren(QScrollArea):
                    content = area.widget()
                    if (content is None or not area.isVisible()
                            or area.horizontalScrollBarPolicy()
                            != Qt.ScrollBarPolicy.ScrollBarAlwaysOff):
                        continue
                    self.assertLessEqual(
                        content.minimumSizeHint().width(), area.viewport().width(),
                        f"content inside a {type(area).__name__} is clipped")

    def test_pages_survive_being_visited_twice(self) -> None:
        """on_shown() rebuilds panels, so a second visit must not double up."""
        for _ in range(2):
            for item in self.nav_items:
                self.window.show_page(item.page_id)
                self.app.processEvents()

    def test_both_themes_apply_to_every_page(self) -> None:
        for theme_name in ("light", "dark", "auto"):
            self.context.settings.set("theme", theme_name)
            self.app.processEvents()
            for item in self.nav_items:
                self.window.show_page(item.page_id)
                self.app.processEvents()
            self.assertFalse(self.window.grab().isNull(), theme_name)

    def test_every_accent_colour_applies(self) -> None:
        from clamguard.ui.theme import ACCENTS

        for accent in ACCENTS:
            self.context.settings.set("accent", accent)
            self.app.processEvents()
        self.assertFalse(self.window.grab().isNull())

    def test_navigating_to_a_page_that_does_not_exist_is_ignored(self) -> None:
        self.window.show_page("no-such-page")
        self.assertIsNotNone(self.window.current_page())

    # -- the dashboard ----------------------------------------------------

    def test_the_dashboard_reflects_real_system_state(self) -> None:
        self.window.show_page("dashboard")
        status = self.context.protection_status()
        self.assertTrue(status.headline)
        self.assertIn(status.level.tone, ("ok", "warn", "danger", "neutral"))
        for issue in status.issues:
            self.assertTrue(issue.title)
            self.assertTrue(issue.detail)

    def test_issue_buttons_point_at_real_pages(self) -> None:
        known = {item.page_id for item in self.nav_items}
        for issue in self.context.protection_status().issues:
            if issue.page:
                self.assertIn(issue.page, known, issue.title)

    # -- scanning ---------------------------------------------------------

    def test_a_real_scan_runs_end_to_end(self) -> None:
        from PySide6.QtCore import QEventLoop, QTimer

        from .support import EICAR

        work = self.tmp / "scan-me"
        work.mkdir()
        for index in range(40):
            (work / f"file{index}.txt").write_text("harmless content " * 20)
        (work / "eicar.com").write_bytes(EICAR)

        if not self.context.clamav.installed:
            self.skipTest("ClamAV is not installed")

        self.window.show_page("scan")
        page = self.window._pages["scan"]
        page.auto_quarantine.setChecked(False)

        results = []
        loop = QEventLoop()
        self.context.scanner.finished.connect(lambda r: (results.append(r), loop.quit()))
        QTimer.singleShot(120_000, loop.quit)
        page.start_custom_scan([work])
        loop.exec()

        self.assertTrue(results, "the scan never finished")
        result = results[0]
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(result.threats), 1, "EICAR should be detected exactly once")
        self.assertEqual(result.threats[0].filename, "eicar.com")

        # It should also have been written to the history database.
        last = self.context.history.last_scan()
        self.assertIsNotNone(last)
        self.assertEqual(last.threats_found, 1)
        self.assertEqual(len(self.context.history.detections_for(last.id)), 1)

        # And the results view should be the one on screen.
        self.assertIs(page.stack.currentWidget(), page.results_view)
        self.assertEqual(page.threat_table.rowCount(), 1)

    def test_scan_scopes_all_resolve(self) -> None:
        from clamguard.core.scan_targets import ScanKind

        self.window.show_page("scan")
        page = self.window._pages["scan"]
        for kind in ScanKind:
            page._select_scope(kind)
            self.app.processEvents()
        self.assertIsNotNone(page._selected_kind)

    def test_starting_a_scan_with_no_target_is_refused_politely(self) -> None:
        from clamguard.core.scan_targets import ScanKind

        self.window.show_page("scan")
        page = self.window._pages["scan"]
        page._custom_paths = []
        page._select_scope(ScanKind.CUSTOM)

        messages = []
        page.notify.connect(lambda text, tone: messages.append((text, tone)))
        page._start_clicked()
        self.assertTrue(messages)
        self.assertFalse(self.context.scanner.busy)

    # -- quarantine -------------------------------------------------------

    def test_the_quarantine_page_shows_real_entries(self) -> None:
        victim = self.tmp / "sample.bin"
        victim.write_bytes(b"pretend malware")
        captured = {}
        self.context.quarantine.quarantine(
            victim, "Test.Sample-1",
            on_success=lambda entry: captured.setdefault("entry", entry),
            on_error=lambda message: captured.setdefault("error", message))
        self.assertIn("entry", captured, captured.get("error"))

        self.window.show_page("quarantine")
        page = self.window._pages["quarantine"]
        self.app.processEvents()
        self.assertEqual(page.table.rowCount(), 1)
        self.assertEqual(page.badge(), "1")
        self.assertTrue(page.list_card.isVisible())
        self.assertFalse(page.empty.isVisible())

    # -- configuration ----------------------------------------------------

    def test_the_configuration_page_loads_both_files(self) -> None:
        from clamguard.core.conf_schema import CLAMD, FRESHCLAM

        self.window.show_page("configuration")
        page = self.window._pages["configuration"]
        for file_key in (CLAMD, FRESHCLAM):
            page._load_file(file_key)
            self.app.processEvents()
            self.assertIsNotNone(page._conf)
            self.assertGreater(page.group_list.count(), 0)

    def test_every_configuration_group_renders_its_editors(self) -> None:
        self.window.show_page("configuration")
        page = self.window._pages["configuration"]
        page.advanced_toggle.setChecked(True)
        for row in range(page.group_list.count()):
            page.group_list.setCurrentRow(row)
            self.app.processEvents()
            self.assertGreater(len(page._editors), 0,
                               f"group {row} rendered nothing")

    def test_searching_the_configuration(self) -> None:
        self.window.show_page("configuration")
        page = self.window._pages["configuration"]
        page.search_box.setText("thread")
        self.app.processEvents()
        self.assertIn("MaxThreads", page._editors)

    def test_editing_an_option_marks_the_page_dirty_but_writes_nothing(self) -> None:
        from clamguard.core import paths

        self.window.show_page("configuration")
        page = self.window._pages["configuration"]
        if not paths.CLAMD_CONF.is_file():
            self.skipTest("no clamd.conf on this machine")

        before = paths.CLAMD_CONF.read_bytes()
        page._on_option_changed("LogVerbose", True)
        self.app.processEvents()

        self.assertTrue(page.preview_button.isEnabled())
        self.assertIn("LogVerbose", page._conf.changed_keys())
        self.assertEqual(paths.CLAMD_CONF.read_bytes(), before,
                         "nothing may be written without an explicit save")

    def test_discarding_changes_reloads_from_disk(self) -> None:
        self.window.show_page("configuration")
        page = self.window._pages["configuration"]
        page._on_option_changed("LogVerbose", True)
        page._load_file(page._file)
        self.assertFalse(page.preview_button.isEnabled())

    # -- protection -------------------------------------------------------

    def test_the_protection_page_diagnoses_this_machine(self) -> None:
        self.window.show_page("protection")
        page = self.window._pages["protection"]
        self.app.processEvents()
        self.assertEqual(len(page.cards), 3)
        self.assertFalse(self.window.grab().isNull())

    def test_applying_a_remedy_without_the_helper_writes_nothing(self) -> None:
        from clamguard.core import paths
        from clamguard.core.diagnostics import Remedy

        if self.context.privileged.available:
            self.skipTest("the helper is installed; this path is not exercised")
        if not paths.CLAMD_CONF.is_file():
            self.skipTest("no clamd.conf on this machine")

        from clamguard.core.conf_file import ConfFile

        before = paths.CLAMD_CONF.read_bytes()
        self.window.show_page("protection")
        page = self.window._pages["protection"]

        outcomes = []
        page.applier.finished.connect(lambda ok, message: outcomes.append(ok))

        remedy = Remedy(title="Exclude the scanner", explanation="why",
                        file=paths.CLAMD_CONF, changes={"LogVerbose": True})
        page._apply_remedy(remedy)
        self.app.processEvents()

        self.assertEqual(outcomes, [False], "the apply must not have succeeded")
        self.assertEqual(paths.CLAMD_CONF.read_bytes(), before,
                         "a refused or unavailable apply must write nothing")

        # And the config it would have written is still a valid change.
        conf = ConfFile.load(paths.CLAMD_CONF)
        remedy.apply_to(conf)
        self.assertTrue(conf.diff())

    def test_saving_the_configuration_asks_before_writing(self) -> None:
        """The confirmation is stubbed to answer no; nothing may be written."""
        from clamguard.core import paths

        if not paths.CLAMD_CONF.is_file():
            self.skipTest("no clamd.conf on this machine")

        before = paths.CLAMD_CONF.read_bytes()
        self.window.show_page("configuration")
        page = self.window._pages["configuration"]
        page._on_option_changed("LogVerbose", True)
        page._save()
        self.app.processEvents()
        self.assertEqual(paths.CLAMD_CONF.read_bytes(), before)

    def test_destructive_quarantine_actions_ask_first(self) -> None:
        victim = self.tmp / "to-delete.bin"
        victim.write_bytes(b"pretend malware")
        captured = {}
        self.context.quarantine.quarantine(
            victim, "Test.Sample-1",
            on_success=lambda entry: captured.setdefault("entry", entry),
            on_error=lambda message: captured.setdefault("error", message))
        entry = captured.get("entry")
        self.assertIsNotNone(entry, captured.get("error"))

        self.window.show_page("quarantine")
        page = self.window._pages["quarantine"]
        self.dialogs_shown.clear()

        page._delete(entry)
        self.assertTrue(self.dialogs_shown, "deleting must ask first")
        self.assertEqual(self.context.quarantine.count(), 1, "a refused delete keeps it")

        self.dialogs_shown.clear()
        page._restore(entry)
        self.assertTrue(self.dialogs_shown, "restoring must ask first")
        self.assertEqual(self.context.quarantine.count(), 1, "a refused restore keeps it")
        self.assertFalse(victim.exists(), "and must not put the file back")

    # -- other pages ------------------------------------------------------

    def test_the_updates_page_lists_the_installed_databases(self) -> None:
        self.window.show_page("updates")
        page = self.window._pages["updates"]
        self.app.processEvents()
        visible = [name for name, card in page.database_cards.items()
                   if card.isVisible()]
        summary = self.context.database.summary
        self.assertEqual(sorted(visible),
                         sorted(entry.name for entry in summary.official()))

    def test_the_logs_page_reads_a_source(self) -> None:
        self.window.show_page("logs")
        page = self.window._pages["logs"]
        self.app.processEvents()
        self.assertGreater(page.source_box.count(), 0)
        page._reload()
        self.assertTrue(page.status.text())

    def test_the_logs_page_stops_following_when_hidden(self) -> None:
        self.window.show_page("logs")
        page = self.window._pages["logs"]
        page.follow_toggle.setChecked(True)
        self.app.processEvents()
        self.window.show_page("dashboard")
        self.assertIsNone(page._tail)

    def test_the_history_page_filters(self) -> None:
        self.window.show_page("history")
        page = self.window._pages["history"]
        page.search_box.setText("nothing will match this")
        self.app.processEvents()
        self.assertEqual(page.table.rowCount(), 0)
        page.search_box.setText("")
        self.app.processEvents()

    def test_the_settings_page_writes_preferences(self) -> None:
        self.window.show_page("settings")
        page = self.window._pages["settings"]
        page.theme_box.setCurrentIndex(page.theme_box.findData("dark"))
        self.app.processEvents()
        self.assertEqual(self.context.settings.str("theme"), "dark")

    def test_adding_and_removing_a_schedule(self) -> None:
        from clamguard.core.scheduler import Schedule

        self.window.show_page("settings")
        page = self.window._pages["settings"]
        added = self.context.scheduler.add(Schedule(name="Test schedule"))
        self.app.processEvents()
        self.assertEqual(page.schedule_list.count(), 1)
        self.context.scheduler.remove(added.id)
        self.app.processEvents()
        self.assertEqual(page.schedule_list.count(), 0)

    def test_the_autostart_entry_stays_inside_a_config_directory(self) -> None:
        """Starting at login must never mean writing to /etc or a system unit."""
        from clamguard.ui.pages.settings_page import AUTOSTART_FILE

        self.assertTrue(AUTOSTART_FILE.is_absolute())
        self.assertEqual(AUTOSTART_FILE.name, "clamguard.desktop")
        self.assertEqual(AUTOSTART_FILE.parent.name, "autostart")
        for forbidden in ("/etc", "/usr", "/lib", "/var"):
            self.assertFalse(str(AUTOSTART_FILE).startswith(forbidden + "/"),
                             AUTOSTART_FILE)

    # -- window behaviour -------------------------------------------------

    def test_dropping_files_starts_a_custom_scan(self) -> None:
        dropped = []
        page = self.window._pages["scan"]
        page.ensure_built()
        original = page.start_custom_scan
        page.start_custom_scan = lambda targets: dropped.append(list(targets))
        try:
            self.window.start_scan(None, [self.tmp])
        finally:
            page.start_custom_scan = original
        self.assertEqual(dropped, [[self.tmp]])

    def test_the_tray_menu_has_the_actions_it_promises(self) -> None:
        labels = [action.text() for action in self.window.tray.contextMenu().actions()]
        self.assertIn("Quick scan", labels)
        self.assertIn("Quit", labels)

    def test_toasts_do_not_crash_the_window(self) -> None:
        for tone in ("ok", "warn", "danger", "info"):
            self.window.toasts.show_message(f"A {tone} message", tone)
        self.app.processEvents()
        self.assertFalse(self.window.grab().isNull())


    # -- the boot analyzer ------------------------------------------------

    def _analysed_boot_page(self):
        """Open the Boot Analyzer and wait for its background run to finish."""
        from PySide6.QtCore import QEventLoop, QTimer

        self.window.show_page("boot")
        page = self.window.current_page()
        if page.report is None:
            loop = QEventLoop()
            page.analyzer.finished.connect(lambda _report: loop.quit())
            page.analyzer.failed.connect(lambda _message: loop.quit())
            QTimer.singleShot(60000, loop.quit)
            if not page.analyzer.busy:
                page.analyse()
            loop.exec()
        self.app.processEvents()
        return page

    def test_the_boot_analyzer_analyses_this_machine(self) -> None:
        page = self._analysed_boot_page()
        self.assertIsNotNone(page.report, "the analysis produced no report")
        self.assertTrue(page.report.findings, "no check said anything")
        self.assertGreaterEqual(page.report.score, 0)
        self.assertLessEqual(page.report.score, 100)
        self.assertTrue(page.report.facts)

    def test_the_boot_analysis_changed_nothing(self) -> None:
        """The whole feature's promise, checked against the real machine."""
        import os

        watched = ["/etc/fstab", "/proc/sys/kernel/kptr_restrict"]
        watched += [path for path in ("/boot/grub/grub.cfg", "/etc/ld.so.preload")
                    if os.path.exists(path)]
        before = {path: os.stat(path).st_mtime for path in watched
                  if os.path.exists(path)}
        self._analysed_boot_page()
        after = {path: os.stat(path).st_mtime for path in before}
        self.assertEqual(before, after)

    def test_every_boot_tab_renders_with_real_data(self) -> None:
        page = self._analysed_boot_page()
        for index in range(page.tabs.count()):
            with self.subTest(tab=page.tabs.tabText(index)):
                page.tabs.setCurrentIndex(index)
                self.app.processEvents()
                self.assertFalse(self.window.grab().isNull())
        page.tabs.setCurrentIndex(0)

    def test_the_boot_findings_can_be_filtered_and_searched(self) -> None:
        page = self._analysed_boot_page()
        total = len(page._visible_findings())

        page.search.setText("zzzz-no-such-thing")
        self.app.processEvents()
        self.assertEqual(page._visible_findings(), [])

        page.search.setText("")
        page.show_passes.setChecked(True)
        page._on_show_passes()
        self.app.processEvents()
        self.assertGreaterEqual(len(page._visible_findings()), total)

    def test_filtering_by_severity_narrows_to_that_severity(self) -> None:
        from clamguard.core.boot.model import Severity

        page = self._analysed_boot_page()
        for level in (Severity.MEDIUM, Severity.LOW, Severity.INFO):
            if page.report.count(level):
                page._filter_by_severity(level)
                self.app.processEvents()
                shown = page._visible_findings()
                self.assertTrue(shown)
                self.assertTrue(all(item.severity is level for item in shown))
                page._filter_by_severity(level)     # click again to clear
                break

    def test_every_finding_row_can_be_expanded(self) -> None:
        page = self._analysed_boot_page()
        for row in page._rows[:12]:
            with self.subTest(finding=row.finding.id):
                row.set_expanded(True)
                self.app.processEvents()
                self.assertTrue(row.expanded)
                row.set_expanded(False)

    def test_muting_a_finding_asks_first_and_writes_nothing_when_refused(self) -> None:
        page = self._analysed_boot_page()
        problems = page.report.problems()
        if not problems:
            self.skipTest("this machine has nothing to mute")
        before = dict(page.profile.mutes)
        page._mute(problems[0].id)
        self.app.processEvents()
        self.assertTrue(self.dialogs_shown, "muting must ask before it counts")
        self.assertEqual(page.profile.mutes, before)

    def test_changing_the_preset_re_runs_and_changes_the_score(self) -> None:
        page = self._analysed_boot_page()
        balanced = page.report.score
        index = page.preset_picker.findData("paranoid")
        page.preset_picker.setCurrentIndex(index)
        page = self._analysed_boot_page()
        self.assertEqual(page.profile.preset, "paranoid")
        self.assertLessEqual(page.report.score, balanced)

    def test_the_boot_report_exports_to_every_format(self) -> None:
        import tempfile
        from pathlib import Path

        from clamguard.core.boot import report as export

        page = self._analysed_boot_page()
        target = Path(tempfile.mkdtemp())
        for name, _extension, _blurb in export.describe_formats():
            with self.subTest(format=name):
                written = export.write(page.report, target, name)
                self.assertTrue(written.is_file())

    def test_savvy_mode_reveals_what_the_analyzer_touched(self) -> None:
        page = self._analysed_boot_page()
        page.savvy.setChecked(True)
        self.app.processEvents()
        self.assertTrue(page.probe_card.isVisible())
        self.assertTrue(page.probe_log.toPlainText())
        page.savvy.setChecked(False)

    def test_the_boot_page_offers_a_scan_of_the_boot_surfaces(self) -> None:
        page = self._analysed_boot_page()
        asked = []
        page.request_scan.connect(lambda kind, targets: asked.append(targets))
        page._scan_boot_surfaces()
        self.app.processEvents()
        self.assertTrue(asked, "the scan request never reached the window")
        self.assertTrue(all(path.exists() for path in asked[0]))

    def test_turning_a_check_off_is_remembered(self) -> None:
        page = self._analysed_boot_page()
        page.profile.enable_check("kernel.taint", False)
        page.checks_tab.refresh_from_profile()
        self.app.processEvents()
        self.assertFalse(page.profile.is_enabled("kernel.taint"))
        selected = page.analyzer._selected(())
        self.assertNotIn("kernel.taint", [item.id for item in selected])
        page.profile.enable_check("kernel.taint", True)


    # -- Services --------------------------------------------------------

    def _services_page(self, *, user: bool = False):
        """Open Services and wait for a read of the wanted scope to land."""
        import shutil

        from PySide6.QtCore import QEventLoop, QTimer

        if shutil.which("systemctl") is None:
            self.skipTest("no systemctl on this machine")
        self.window.show_page("services")
        page = self.window.current_page()
        if user:
            page.scope.setCurrentIndex(1)
        deadline_loop = QEventLoop()
        QTimer.singleShot(60000, deadline_loop.quit)

        def landed(_inventory):
            if page.manager.user_scope == user and not page.manager.busy:
                deadline_loop.quit()

        page.inventory_ready.connect(landed)
        if page.inventory is None or page.manager.user_scope != user or page.manager.busy:
            deadline_loop.exec()
        page.inventory_ready.disconnect(landed)
        self.app.processEvents()
        if page.inventory is None or not len(page.inventory):
            self.skipTest("systemctl listed no units here")
        return page

    def test_services_lists_units_and_explains_one(self) -> None:
        page = self._services_page()
        self.assertGreater(page.model.rowCount(), 0)
        self.assertTrue(page.table.currentIndex().isValid(), "nothing was selected")
        self.assertGreater(page.detail.column.count(), 2, "the detail pane is empty")

    def test_every_filter_survives_a_selection(self) -> None:
        """Selecting a row while the proxy was re-filtering once re-entered the
        model mid-rebuild and segfaulted. Walk every filter with a selection."""
        page = self._services_page()
        for index in range(page.state_picker.count()):
            page.state_picker.setCurrentIndex(index)
            self.app.processEvents()
            if page.proxy.rowCount():
                page.table.selectRow(0)
                self.app.processEvents()
        page.state_picker.setCurrentIndex(0)
        page.search.setText("zzzz-no-such-unit")
        self.app.processEvents()
        self.assertEqual(page.proxy.rowCount(), 0)
        page.search.setText("")

    def test_a_refresh_keeps_the_selected_unit(self) -> None:
        from PySide6.QtCore import QEventLoop, QTimer

        page = self._services_page()
        target_row = min(5, page.proxy.rowCount() - 1)
        page.table.selectRow(target_row)
        self.app.processEvents()
        chosen = page._selected_unit_id()
        loop = QEventLoop()
        page.inventory_ready.connect(lambda _i: loop.quit())
        QTimer.singleShot(60000, loop.quit)
        page.refresh()
        loop.exec()
        self.app.processEvents()
        self.assertEqual(page._selected_unit_id(), chosen)

    def test_switching_to_session_units_mid_read_is_not_lost(self) -> None:
        """Changing the picker while a read was in flight used to be dropped,
        leaving "My session's units" over a list of system units."""
        page = self._services_page()
        page.refresh()                      # a system read is now in flight
        page = self._services_page(user=True)
        self.assertTrue(page.manager.user_scope)
        self.assertTrue(all(unit.user_manager for unit in page.inventory))
        self.assertEqual(page.tiles["enabled"].caption_label.text(), "start at login")
        from PySide6.QtWidgets import QWidget

        page.table.selectRow(0)
        self.app.processEvents()
        commands = [widget.command for widget in page.detail.findChildren(QWidget)
                    if isinstance(getattr(widget, "command", None), str)]
        self.assertTrue(commands)
        for command in commands:
            if "systemctl" in command:
                self.assertIn("--user", command, command)
                self.assertNotIn("sudo", command, command)

    # -- Hunt ------------------------------------------------------------

    def _hunt_page(self):
        """Open Hunt, index one small log, and wait for it to land."""
        from PySide6.QtCore import QEventLoop, QTimer

        from clamguard.core.hunt.discovery import Candidate

        self.window.show_page("hunt")
        page = self.window.current_page()
        if page.indexer.status().empty:
            # Timestamps relative to now, never a fixed date. The page opens on
            # "Last 24 hours" and the store purges anything past 120 days, so a
            # literal date passes the day it is written and fails from the next
            # — which is exactly what these tests did on 2026-09-23.
            stamp = recent_stamps(4)
            path = self.tmp / "smoke.log"
            path.write_text(
                f"{stamp[0]} [info] the application started\n"
                f"{stamp[1]} [warn] disk nearly full\n"
                f"{stamp[2]} [error] connection refused to 10.0.0.5\n"
                f"{stamp[3]} [error] connection refused again\n",
                encoding="utf-8")
            info = path.stat()
            loop = QEventLoop()
            page.indexer.index_finished.connect(lambda _run: loop.quit())
            QTimer.singleShot(30000, loop.quit)
            page.indexer.index([Candidate(path=str(path), size=info.st_size,
                                          mtime=info.st_mtime, app="smoke")])
            loop.exec()
        self.app.processEvents()
        page._refresh_status()
        return page

    def _run_hunt_query(self, page, text: str):
        from PySide6.QtCore import QEventLoop, QTimer

        page.editor.set_query(text)
        loop = QEventLoop()
        page.indexer.query_finished.connect(lambda _table: loop.quit())
        page.indexer.query_failed.connect(lambda _error: loop.quit())
        QTimer.singleShot(30000, loop.quit)
        page.run_query()
        loop.exec()
        self.app.processEvents()
        return page._last_result

    def test_hunt_opens_empty_and_says_what_it_would_do(self) -> None:
        self.window.show_page("hunt")
        page = self.window.current_page()
        self.assertTrue(page.empty.isVisible())
        self.assertIn("nothing indexed", page.index_chip.text())

    def test_hunt_indexes_a_log_and_queries_it(self) -> None:
        page = self._hunt_page()
        self.assertGreaterEqual(page.indexer.status().events, 4)
        result = self._run_hunt_query(
            page, 'Logs | where Level == "error" | project Timestamp, Message')
        self.assertIsNotNone(result)
        self.assertEqual(len(result.rows), 2)
        self.assertEqual(page.grid.model().rowCount(), 2)
        self.assertFalse(page.empty.isVisible())

    def test_an_empty_result_says_the_events_are_older_than_the_window(self) -> None:
        """Index last week's log and run a first query on "Last 24 hours": the
        answer is one click on the time picker, and the notice has to say so
        rather than a bare "No rows matched", which reads as Hunt being broken."""
        from PySide6.QtCore import QEventLoop, QTimer

        from clamguard.core.hunt.discovery import Candidate

        self.window.show_page("hunt")
        page = self.window.current_page()
        stamps = recent_stamps(2, hours_ago=24 * 6)
        path = self.tmp / "old.log"
        path.write_text(f"{stamps[0]} [info] from last week\n"
                        f"{stamps[1]} [error] also from last week\n", encoding="utf-8")
        info = path.stat()
        loop = QEventLoop()
        page.indexer.index_finished.connect(lambda _run: loop.quit())
        QTimer.singleShot(30000, loop.quit)
        page.indexer.index([Candidate(path=str(path), size=info.st_size,
                                      mtime=info.st_mtime, app="old")])
        loop.exec()

        result = self._run_hunt_query(page, "Logs | take 10")
        self.assertEqual(result.rows, [])
        text = page.notice._text.text()
        self.assertIn("newest indexed event", text)
        self.assertRegex(text, r"\b[56] days ago\b")

    def test_a_result_row_expands_into_its_fields(self) -> None:
        page = self._hunt_page()
        self._run_hunt_query(page, "Logs | take 2")
        model = page.grid.model()
        top = model.index(0, 0)
        self.assertTrue(model.hasChildren(top))
        page.grid.expand(top)
        self.app.processEvents()
        self.assertEqual(model.rowCount(top), len(page._last_result.columns))

    def test_a_broken_query_underlines_itself_rather_than_raising(self) -> None:
        page = self._hunt_page()
        self._run_hunt_query(page, "Logs | wher Level == 1")
        self.assertIsNotNone(page.editor.error)
        self.assertTrue(page.notice.isVisible())

    def test_the_live_check_runs_without_touching_the_store(self) -> None:
        page = self._hunt_page()
        page.editor.set_query("Logs | where Levl == 1")
        page.editor._run_check()
        self.assertIsNotNone(page.editor.error)
        page.editor.set_query('Logs | where Level == "error"')
        page.editor._run_check()
        self.assertIsNone(page.editor.error)

    def test_a_render_directive_fills_the_chart_tab(self) -> None:
        page = self._hunt_page()
        self._run_hunt_query(
            page, "Logs | summarize Events = count() by Level | render columnchart")
        self.assertIs(page.tabs.currentWidget(), page.chart)
        self.assertTrue(page.chart._series)
        page.chart.grab()

    def test_adding_a_filter_from_a_cell_re_runs_the_query(self) -> None:
        page = self._hunt_page()
        self._run_hunt_query(page, "Logs | take 4")
        page._append_stage('where Level == "error"')
        self.app.processEvents()
        self.assertIn('where Level == "error"', page.editor.toPlainText())

    def test_the_left_rail_lists_tables_queries_and_functions(self) -> None:
        page = self._hunt_page()
        page.rail.set_sources(page.indexer.store.sources())
        for index in range(3):
            page.rail.tabs.setCurrentIndex(index)
            self.app.processEvents()
            with self.subTest(tab=index):
                self.assertGreater(page.rail.tree.topLevelItemCount(), 0)

    def test_a_library_query_can_be_run_from_the_rail(self) -> None:
        from clamguard.core.hunt import library

        page = self._hunt_page()
        from PySide6.QtCore import QEventLoop, QTimer

        loop = QEventLoop()
        page.indexer.query_finished.connect(lambda _table: loop.quit())
        page.indexer.query_failed.connect(lambda _error: loop.quit())
        QTimer.singleShot(30000, loop.quit)
        page.rail.query_requested.emit(library.get("recent-errors").text, True)
        loop.exec()
        self.app.processEvents()
        self.assertIsNotNone(page._last_result)

    def test_the_analysis_rules_run_and_produce_a_verdict(self) -> None:
        from PySide6.QtCore import QEventLoop, QTimer

        page = self._hunt_page()
        loop = QEventLoop()
        page.indexer.review_finished.connect(lambda _review: loop.quit())
        QTimer.singleShot(120000, loop.quit)
        page.run_analysis()
        loop.exec()
        self.app.processEvents()
        self.assertIsNotNone(page.insights.review)
        self.assertGreater(page.insights.review.checked, 5)
        self.assertEqual(page.insights.review.failed, [])

    def test_the_time_range_is_remembered(self) -> None:
        from datetime import timedelta

        from clamguard.core.hunt.model import TimeRange

        page = self._hunt_page()
        page.time_range = TimeRange.rolling(timedelta(hours=3), "Last 3 hours")
        page.on_hidden()
        self.assertEqual(page.settings.time_range.last, timedelta(hours=3))

    def test_exporting_writes_a_file(self) -> None:
        from clamguard.core.hunt import export

        page = self._hunt_page()
        result = self._run_hunt_query(page, "Logs | take 3")
        target = export.write(result, self.tmp / "out", "csv")
        self.assertTrue(target.is_file())
        self.assertIn("Message", target.read_text())

    def test_forgetting_the_index_is_behind_a_confirmation(self) -> None:
        page = self._hunt_page()
        before = page.indexer.status().events
        page._clear_index()
        self.app.processEvents()
        self.assertEqual(page.indexer.status().events, before,
                         "the index was cleared without a confirmation")
        self.assertTrue(self.dialogs_shown)

    def test_the_journal_can_be_indexed_and_queried(self) -> None:
        """Skipped where journalctl is absent or the account cannot read it —
        a container, or a user not in systemd-journal."""
        from PySide6.QtCore import QEventLoop, QTimer

        from clamguard.core.hunt import journal as journal_module

        page = self._hunt_page()
        available = page.indexer.journal_availability()
        if not available.usable:
            self.skipTest(available.describe())

        page.settings.journal_enabled = True
        page.settings.journal_window = "boot"
        page.settings.journal_priority = "err"
        page.settings.journal_max_entries = 500
        page.settings.save()

        loop = QEventLoop()
        page.indexer.journal_finished.connect(lambda _i: loop.quit())
        QTimer.singleShot(180000, loop.quit)
        page.index_journal()
        loop.exec()
        self.app.processEvents()

        status = page.indexer.status()
        self.assertGreaterEqual(status.journal_units, 0)
        if not status.journal_events:
            self.skipTest("this machine's journal has no errors this boot")

        # A capped read takes the *oldest* entries of the boot, and a boot can
        # be days old — so on the page's default "Last 24 hours" this query
        # matched nothing once the machine had been up a day. What is under
        # test is that units become sources, not the time filter.
        from clamguard.core.hunt.model import TimeRange

        page.time_range = TimeRange.everything()
        result = self._run_hunt_query(
            page, 'Logs | where Location == "journal" '
                  "| summarize Entries = count() by App")
        self.assertTrue(result.rows)
        # The whole reason units become their own sources: App names the unit.
        self.assertNotEqual(result.rows[0][0], "journal")

    def test_reading_the_journal_twice_adds_nothing_the_second_time(self) -> None:
        from PySide6.QtCore import QEventLoop, QTimer

        page = self._hunt_page()
        if not page.indexer.journal_availability().usable:
            self.skipTest("the journal is not readable here")
        page.settings.journal_enabled = True
        page.settings.journal_window = "boot"
        page.settings.journal_priority = "err"
        page.settings.journal_max_entries = 500
        page.settings.save()

        outcomes = []
        for _pass in range(2):
            loop = QEventLoop()
            # Connected and disconnected each time: leaving the first
            # connection attached would have the second emit fire both.
            handler = lambda ingest: (outcomes.append(ingest), loop.quit())
            page.indexer.journal_finished.connect(handler)
            QTimer.singleShot(180000, loop.quit)
            try:
                page.index_journal()
                loop.exec()
            finally:
                page.indexer.journal_finished.disconnect(handler)
            self.app.processEvents()

        self.assertEqual(len(outcomes), 2)
        if outcomes[0].truncated:
            self.skipTest("the first pass hit its cap, so there is more to read")
        self.assertLessEqual(outcomes[1].added, outcomes[0].added)

    def test_the_sources_dialog_has_a_journal_tab(self) -> None:
        from clamguard.ui.pages.hunt_dialogs import SourcesDialog

        page = self._hunt_page()
        dialog = SourcesDialog(page, crawl=page.indexer.last_crawl,
                               sources=page.indexer.store.sources(),
                               journal=page._journal_state())
        try:
            self.assertEqual(dialog.tabs.tabText(3), "Journal")
            self.assertTrue(dialog.journal.headline.text())
            self.assertTrue(dialog.journal.detail.text())
            dialog.grab()

            # Again with a journal that has actually been read: the "never"
            # branch hid a crash on the one that had.
            import time as _time

            from clamguard.core.hunt import journal as journal_module

            dialog.journal.show_state(
                journal_module.availability(), journal_module.JournalOptions(),
                51_696, 50, _time.time(), True,
                [("sshd.service", 12), ("kernel", 5405)])
            self.assertIn("51,696", dialog.journal.headline.text())
            self.assertIn("Last read", dialog.journal.detail.text())
            self.assertEqual(dialog.journal.units.rowCount(), 2)
            dialog.grab()
        finally:
            dialog.deleteLater()

    def test_an_unreadable_directory_reaches_the_skipped_tab(self) -> None:
        from clamguard.core.hunt import discovery

        found = discovery.Crawl()
        root = discovery.Root("test", self.tmp, "Test", "")
        discovery._note_unreadable(found, "/var/log/audit", root, str(self.tmp),
                                   PermissionError(13, "Permission denied"))

        from clamguard.ui.pages.hunt_dialogs import SourcesDialog

        page = self._hunt_page()
        dialog = SourcesDialog(page, crawl=found, sources=[],
                               journal=page._journal_state())
        try:
            self.assertEqual(dialog.skipped.rowCount(), 1)
            self.assertIn("directory cannot be read",
                          dialog.skipped.item(0, 2).text())
        finally:
            dialog.deleteLater()

    def test_the_hunt_page_survives_a_theme_change(self) -> None:
        page = self._hunt_page()
        self._run_hunt_query(page, "Logs | summarize count() by Level | render piechart")
        for theme in ("light", "dark"):
            with self.subTest(theme=theme):
                self.context.settings.set("theme", theme)
                self.app.processEvents()
                page.grab()


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(_widgets_available(), "PySide6.QtWidgets is not installed")
class TestCommandBlock(unittest.TestCase):
    """A command wider than its box must still be readable.

    The box was sized for exactly one line, and the horizontal scrollbar that
    a long command needs was drawn over that line: in the Services pane,
    `journalctl --user-unit dbus-broker.service -n 100 --no-pager` rendered as
    an empty box with a scrollbar in it.
    """

    @classmethod
    def setUpClass(cls) -> None:
        from .support import qt_application

        cls.app = qt_application()

    def block(self, command: str, width: int):
        from clamguard.ui.widgets import CommandBlock

        block = CommandBlock(command)
        block.resize(width, 80)
        block.show()
        for _ in range(5):
            self.app.processEvents()
        self.addCleanup(block.deleteLater)
        return block

    def test_a_short_command_keeps_its_one_line_box(self) -> None:
        block = self.block("man 5 clamd.conf", 600)
        self.assertEqual(block._view.height(), block._text_height)

    def test_a_long_command_grows_to_make_room_for_its_scrollbar(self) -> None:
        block = self.block("journalctl --user-unit dbus-broker.service -n 100 --no-pager", 180)
        bar = block._view.horizontalScrollBar()
        self.assertGreater(bar.maximum(), 0, "the command should overflow at this width")
        self.assertEqual(block._view.height(), block._text_height + bar.sizeHint().height())

    def test_copy_gives_the_exact_command(self) -> None:
        from PySide6.QtWidgets import QApplication

        command = "systemctl --user status dbus-broker.service"
        self.block(command, 200)._copy()
        self.assertEqual(QApplication.clipboard().text(), command)


@unittest.skipUnless(_widgets_available(), "PySide6.QtWidgets is not installed")
class TestServicesReading(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from .support import qt_application

        cls.app = qt_application()

    def test_the_homepage_row_shows_the_address(self) -> None:
        """It showed "dbus-broker homepage" — neither readable nor copyable."""
        from clamguard.core.units.inventory import build_unit
        from clamguard.core.units.purpose import describe
        from clamguard.ui.pages.services_detail import UnitDetail
        from clamguard.ui.widgets import KeyValueRow

        unit = build_unit({"Id": "dbus-broker.service", "LoadState": "loaded"})
        unit.package, unit.package_url = "dbus-broker", "https://github.com/bus1/dbus-broker/wiki"
        unit.purpose = describe(unit)
        detail = UnitDetail()
        self.addCleanup(detail.deleteLater)
        card = detail._reading(unit)
        rows = card.findChildren(KeyValueRow)
        self.assertEqual([(r.key_label.text(), r.value_label.text()) for r in rows],
                         [("Homepage", "https://github.com/bus1/dbus-broker/wiki")])
