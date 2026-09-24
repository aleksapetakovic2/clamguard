"""Regression tests for the security properties ClamGuard claims to have.

Each of these exists because the property it checks was once violated. They
assert the *boundary*, not the implementation, so a refactor that quietly
reopens a hole fails here.
"""

from __future__ import annotations

import ast
import os
import re
import stat
import unittest

from .support import REPO_ROOT, TempHomeTestCase, qt_application

HELPER = REPO_ROOT / "packaging" / "clamguard-helper"


def helper_namespace() -> dict:
    """Import the helper's module-level definitions without running it."""
    source = HELPER.read_text(encoding="utf-8")
    namespace: dict = {}
    exec(compile(source.replace('if __name__ == "__main__":', "if False:"),
                 "clamguard-helper", "exec"), namespace)
    return namespace


class TestPrivilegeEscalation(unittest.TestCase):
    """The helper runs as root. These are the ways it must not be abusable."""

    def setUp(self) -> None:
        self.source = HELPER.read_text(encoding="utf-8")
        self.namespace = helper_namespace()

    # -- restore ----------------------------------------------------------

    def test_restore_takes_an_id_not_a_path(self) -> None:
        """A caller-supplied path would let the GUI choose where root writes."""
        body = self._function_source("verb_restore")
        self.assertIn("ENTRY_ID.match", body)
        self.assertIn("read_record", body)
        self.assertNotIn("original_path", body.split("read_record")[0])

    def test_restore_reads_its_own_record_not_the_users(self) -> None:
        """Metadata in the user's home is editable by the user, so it is not
        allowed to decide a destination, an owner or a mode."""
        body = self._function_source("verb_restore")
        self.assertIn('record.get("original_path"', body)
        self.assertIn('record.get("mode"', body)
        self.assertIn('record.get("uid"', body)
        # The user's own metadata file must not be parsed here at all.
        self.assertNotIn("meta_path", body)
        self.assertNotIn("json.loads", body)

    def test_entry_ids_cannot_escape_the_record_directory(self) -> None:
        pattern = self.namespace["ENTRY_ID"]
        self.assertTrue(pattern.match("20260920-034213-15cf03"))
        for hostile in ("../../etc/shadow", "a/../b", "..", "/absolute",
                        "20260920-034213-15cf03/../x", "", "*", "x" * 200):
            self.assertIsNone(pattern.match(hostile), hostile)

    def test_setuid_and_setgid_are_stripped_on_the_way_in(self) -> None:
        """Quarantining a setuid root binary must not record those bits."""
        body = self._function_source("verb_quarantine")
        self.assertIn("st_mode & 0o0777", body)

    def test_setuid_and_setgid_are_stripped_on_the_way_out(self) -> None:
        """Even if a record were tampered with, restore must not honour them.

        A root-owned file with the setuid bit and content of the caller's
        choosing is an immediate root shell, so this is masked twice.
        """
        body = self._function_source("verb_restore")
        self.assertIn("& 0o0777", body)
        self.assertNotIn("0o7777", body)

    def test_mode_masking_actually_removes_the_dangerous_bits(self) -> None:
        for hostile in (0o4755, 0o6755, 0o2755, 0o7777):
            masked = hostile & 0o0777
            self.assertFalse(masked & stat.S_ISUID, oct(hostile))
            self.assertFalse(masked & stat.S_ISGID, oct(hostile))
            self.assertFalse(masked & stat.S_ISVTX, oct(hostile))

    def test_dangerous_restore_destinations_are_refused(self) -> None:
        forbidden = self.namespace["FORBIDDEN_RESTORE_PREFIXES"]
        must_cover = [
            "/usr/bin/ls", "/bin/sh", "/etc/cron.d/evil", "/etc/crontab",
            "/etc/profile.d/evil.sh", "/etc/sudoers.d/evil", "/etc/pam.d/sshd",
            "/etc/systemd/system/evil.service", "/root/.bashrc",
            "/var/spool/cron/crontabs/root", "/etc/ld.so.preload",
            "/etc/shadow", "/boot/vmlinuz", "/etc/init.d/evil",
        ]
        for path in must_cover:
            self.assertTrue(any(path.startswith(p) for p in forbidden),
                            f"{path} is not covered by the restore blocklist")

    # -- quarantine -------------------------------------------------------

    def test_quarantine_will_not_touch_a_file_clamav_does_not_flag(self) -> None:
        """Otherwise the verb is "read and delete any file, as root".

        The scan is of the bytes already read, and it has to come before
        anything is written to the vault or unlinked. (It once came before the
        read, on the path — which a race could point at a different file.)
        """
        body = self._function_source("verb_quarantine")
        self.assertIn("confirm_infected(data", body)
        self.assertLess(body.index("read_from("), body.index("confirm_infected"))
        self.assertLess(body.index("confirm_infected"), body.index("O_CREAT"))
        self.assertLess(body.index("confirm_infected"), body.index("os.unlink("))
        scanner = self._function_source("confirm_infected")
        self.assertIn("input=data", scanner)
        self.assertIn('"-"', scanner)

    def test_the_infection_check_fails_closed(self) -> None:
        body = self._function_source("confirm_infected")
        self.assertIn("refuse(", body)
        self.assertIn("fail(", body)
        self.assertIn("no working ClamAV scanner", body)

    def test_quarantine_is_size_capped(self) -> None:
        self.assertIn("MAX_QUARANTINE_BYTES", self._function_source("verb_quarantine"))
        self.assertLessEqual(self.namespace["MAX_QUARANTINE_BYTES"], 1024 ** 3)

    # -- symlink races ----------------------------------------------------

    def test_vault_writes_do_not_follow_symlinks(self) -> None:
        """The vault is in the user's home, so they can swap a path for a
        symlink between this helper checking it and using it — any directory on
        the path, not only the last component. TestHelperRaces stages those
        swaps for real; this keeps ordinary path IO out of the two verbs."""
        self.assertIn("O_NOFOLLOW", self._function_source("open_directory"))
        by_descriptor = {"open", "unlink", "stat", "rename", "replace", "link",
                         "mkdir", "chmod", "chown"}
        by_path = {"open", "read_bytes", "write_bytes", "read_text", "write_text",
                   "mkdir", "unlink", "rename", "replace", "chmod", "chown", "touch",
                   "resolve", "symlink_to"}
        for name in ("verb_quarantine", "verb_restore"):
            body = self._function_source(name)
            self.assertIn("open_vault(", body, name)
            self.assertIn("open_directory(", body, name)
            for node in ast.walk(ast.parse(body)):
                if not isinstance(node, ast.Call):
                    continue
                function = node.func
                if isinstance(function, ast.Name):
                    self.assertNotEqual(function.id, "open", f"{name} calls open()")
                    continue
                if not isinstance(function, ast.Attribute):
                    continue
                receiver = ast.unparse(function.value)
                self.assertNotIn(receiver, ("shutil", "tempfile"), f"{name} uses {receiver}")
                if receiver == "os" and function.attr in by_descriptor:
                    keywords = {keyword.arg for keyword in node.keywords}
                    self.assertTrue(keywords & {"dir_fd", "src_dir_fd"},
                                    f"{name}: os.{function.attr} without a dir_fd")
                elif receiver != "os":
                    self.assertNotIn(function.attr, by_path,
                                     f"{name}: {receiver}.{function.attr}() by path")

    # -- the record store -------------------------------------------------

    def test_records_are_root_only(self) -> None:
        body = self._function_source("write_record")
        self.assertIn("0o700", body)
        self.assertIn("0o600", body)
        self.assertTrue(str(self.namespace["RECORD_DIR"]).startswith("/var/lib/"))

    def test_a_user_cannot_restore_what_another_user_quarantined(self) -> None:
        self.assertIn("by_uid", self._function_source("verb_restore"))

    # -- general ----------------------------------------------------------

    def test_the_helper_refuses_to_run_without_root(self) -> None:
        self.assertIn("os.geteuid() != 0", self.source)

    def test_the_helper_requires_pkexec(self) -> None:
        self.assertIn("PKEXEC_UID", self._function_source("calling_user"))

    def test_no_shell_is_ever_invoked(self) -> None:
        """shell=True with any attacker-influenced string would be a hole."""
        self.assertNotIn("shell=True", self.source)
        self.assertNotIn("os.system", self.source)
        self.assertNotIn("os.popen", self.source)

    def test_subprocesses_run_with_a_clean_environment(self) -> None:
        for call in re.finditer(r"subprocess\.run\((.*?)\)\n", self.source, re.S):
            self.assertIn("env=", call.group(1),
                          "a subprocess inherits the environment")

    def test_every_verb_validates_its_argument_count(self) -> None:
        for verb in ("read-file", "write-config", "service", "quarantine", "restore"):
            name = "verb_" + verb.replace("-", "_")
            self.assertIn("refuse(", self._function_source(name), name)

    def test_config_writes_are_limited_to_clamav_files(self) -> None:
        for path in self.namespace["CONFIG_FILES"]:
            self.assertTrue("clam" in path or "freshclam" in path, path)
            self.assertFalse(path.startswith("/etc/systemd"), path)

    def test_service_control_is_limited_to_clamav_units(self) -> None:
        for unit in self.namespace["UNITS"]:
            self.assertTrue("clam" in unit, unit)
        self.assertNotIn("daemon-reload", self.namespace["UNIT_ACTIONS"])
        self.assertNotIn("mask", self.namespace["UNIT_ACTIONS"])

    def _function_source(self, name: str) -> str:
        tree = ast.parse(self.source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == name:
                return ast.get_source_segment(self.source, node) or ""
        raise AssertionError(f"{name} is not defined in the helper")


class TestHelperRaces(unittest.TestCase):
    """The helper's quarantine and restore, run for real against the races.

    Everything here happens in a temporary directory as the current user, with
    the helper's root-only locations pointed into it; what is being tested is
    what the helper does when a directory on a path it was given changes under
    it. The scanner is faked so that it can make that change at the worst
    possible moment: after the path was checked, before the file is used.
    """

    EICAR_ISH = b"pretend this is malware\n"

    def setUp(self) -> None:
        import io
        import pwd
        import shutil
        import tempfile
        from contextlib import redirect_stderr
        from pathlib import Path

        self.Path = Path
        self.tmp = Path(tempfile.mkdtemp(prefix="clamguard-helper-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = self.tmp / "home"
        self.vault = self.home / ".local/share/clamguard/quarantine/vault"
        self.vault.mkdir(parents=True)
        self.work = self.tmp / "work"
        self.work.mkdir()
        self.victim = self.tmp / "victim"
        self.victim.mkdir()

        self.helper = helper_namespace()
        me = pwd.getpwuid(os.getuid())
        user = pwd.struct_passwd((me.pw_name, "x", os.getuid(), os.getgid(), "",
                                  str(self.home), "/bin/sh"))
        self.helper["calling_user"] = lambda: user
        self.helper["RECORD_DIR"] = self.tmp / "records"
        self.helper["LOG_PATH"] = self.tmp / "helper.log"
        self.scanned: list[bytes] = []
        self.helper["confirm_infected"] = self._scanner(lambda: None)

        quiet = redirect_stderr(io.StringIO())
        quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)

    def _scanner(self, during_scan):
        def confirm_infected(data: bytes, _shown_as) -> str:
            self.scanned.append(data)
            during_scan()
            return "Eicar-Test-Signature"
        return confirm_infected

    def _swap_for_symlink(self, directory, target) -> None:
        directory.rename(directory.with_name(directory.name + "-moved"))
        directory.symlink_to(target, target_is_directory=True)

    def _exit_code(self, verb: str, *args: str) -> int:
        from contextlib import redirect_stdout
        import io

        with redirect_stdout(io.StringIO()):
            try:
                self.helper["verb_" + verb](list(args))
            except SystemExit as stop:
                return int(stop.code)
        return 0

    def _quarantine(self, name: str = "sample.bin") -> tuple[str, object]:
        source = self.work / name
        source.write_bytes(self.EICAR_ISH)
        entry_id = "20260924-120000-abcdef"
        payload = self.vault / f"{entry_id}.quar"
        self.assertEqual(self._exit_code("quarantine", str(source), str(payload)), 0)
        return entry_id, payload

    # -- the directory walk ------------------------------------------------

    def test_a_symlink_that_was_always_there_is_resolved_and_used(self) -> None:
        """Silverblue's /home is a symlink; that must keep working."""
        link = self.tmp / "link"
        link.symlink_to(self.work, target_is_directory=True)
        real, descriptor = self.helper["open_directory"](link)
        self.addCleanup(os.close, descriptor)
        self.assertEqual(real, self.work.resolve())
        self.assertEqual(os.fstat(descriptor).st_ino, self.work.stat().st_ino)

    def test_a_directory_swapped_for_a_symlink_after_the_check_is_not_followed(self) -> None:
        from unittest import mock

        real_realpath = os.path.realpath

        def resolve_then_race(path, *args, **kwargs):
            resolved = real_realpath(path, *args, **kwargs)
            self._swap_for_symlink(self.work, self.victim)
            return resolved

        with mock.patch("os.path.realpath", resolve_then_race):
            with self.assertRaises(SystemExit) as stop:
                self.helper["open_directory"](self.work)
        self.assertEqual(stop.exception.code, 1)

    # -- quarantine --------------------------------------------------------

    def test_quarantine_moves_what_it_scanned_even_if_the_folder_is_swapped(self) -> None:
        """The attack the path-based helper allowed: ClamAV approves one file,
        the folder is repointed, and root reads and deletes another."""
        precious = self.victim / "sample.bin"
        precious.write_bytes(b"root's secret\n")
        self.helper["confirm_infected"] = self._scanner(
            lambda: self._swap_for_symlink(self.work, self.victim))

        entry_id, payload = self._quarantine()

        self.assertEqual(precious.read_bytes(), b"root's secret\n")
        self.assertEqual(self.scanned, [self.EICAR_ISH])
        neutralise = self.helper["neutralise"]
        self.assertEqual(neutralise(payload.read_bytes()), self.EICAR_ISH)
        self.assertFalse((self.tmp / "work-moved" / "sample.bin").exists(),
                         "the file that was scanned should be the one removed")
        self.assertTrue((self.helper["RECORD_DIR"] / f"{entry_id}.json").exists())

    def test_a_file_replaced_during_the_scan_is_not_deleted(self) -> None:
        def replace_it() -> None:
            (self.work / "sample.bin").unlink()
            (self.work / "sample.bin").write_bytes(b"something else\n")

        self.helper["confirm_infected"] = self._scanner(replace_it)
        source = self.work / "sample.bin"
        source.write_bytes(self.EICAR_ISH)
        payload = self.vault / "20260924-120000-abcdef.quar"
        self.assertEqual(self._exit_code("quarantine", str(source), str(payload)), 1)
        self.assertEqual(source.read_bytes(), b"something else\n")
        self.assertFalse(payload.exists(), "an aborted quarantine leaves no payload")
        self.assertEqual(list(self.helper["RECORD_DIR"].iterdir()), [])

    def test_a_reused_inode_number_is_not_mistaken_for_the_same_file(self) -> None:
        """ext4 gives a freed inode to the next file created, which is how the
        test above first passed on tmpfs and failed on GitHub's runner."""
        from types import SimpleNamespace

        identity = self.helper["_identity"]
        read = SimpleNamespace(st_dev=1, st_ino=42, st_size=24,
                               st_mtime_ns=1_000, st_ctime_ns=1_000)
        for change in ({"st_size": 15}, {"st_ctime_ns": 2_000}, {"st_mtime_ns": 2_000}):
            stand_in = SimpleNamespace(**{**vars(read), **change})
            self.assertNotEqual(identity(stand_in), identity(read), change)
        self.assertEqual(identity(SimpleNamespace(**vars(read))), identity(read))

    def test_the_source_of_a_quarantine_is_never_a_symlink(self) -> None:
        (self.victim / "target").write_bytes(self.EICAR_ISH)
        (self.work / "link").symlink_to(self.victim / "target")
        payload = self.vault / "20260924-120000-abcdef.quar"
        self.assertEqual(self._exit_code("quarantine", str(self.work / "link"), str(payload)), 2)
        self.assertTrue((self.victim / "target").exists())
        self.assertEqual(self.scanned, [])

    def test_a_fifo_is_refused_without_hanging(self) -> None:
        os.mkfifo(self.work / "pipe")
        payload = self.vault / "20260924-120000-abcdef.quar"
        self.assertEqual(self._exit_code("quarantine", str(self.work / "pipe"), str(payload)), 2)

    def test_payload_names_are_the_ones_the_app_makes(self) -> None:
        (self.work / "sample.bin").write_bytes(self.EICAR_ISH)
        for name in ("20260924-120000-abcdef.sh", "evil.quar", "20260924-120000-abcdef"):
            self.assertEqual(
                self._exit_code("quarantine", str(self.work / "sample.bin"),
                                str(self.vault / name)), 2, name)

    def test_the_vault_must_be_inside_the_users_home_and_theirs(self) -> None:
        (self.work / "sample.bin").write_bytes(self.EICAR_ISH)
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        self.assertEqual(self._exit_code(
            "quarantine", str(self.work / "sample.bin"),
            str(elsewhere / "20260924-120000-abcdef.quar")), 2)

        # A vault that is not the caller's — say, ~/.local/share/clamguard
        # pointed at a directory root owns, to aim the write at /etc — is
        # refused. Staged by making the caller someone else, so that it holds
        # when the tests themselves run as root.
        import pwd

        stranger = pwd.struct_passwd(("stranger", "x", os.getuid() + 1, os.getgid(), "",
                                      str(self.home), "/bin/sh"))
        self.helper["calling_user"] = lambda: stranger
        self.assertEqual(self._exit_code(
            "quarantine", str(self.work / "sample.bin"),
            str(self.vault / "20260924-120000-abcdef.quar")), 2)
        self.assertTrue((self.work / "sample.bin").exists())
        self.assertEqual(self.scanned, [])

    # -- restore -----------------------------------------------------------

    def test_restore_puts_the_same_bytes_back_with_the_same_mode(self) -> None:
        (self.work / "sample.bin").write_bytes(self.EICAR_ISH)
        (self.work / "sample.bin").chmod(0o640)
        entry_id, payload = self._quarantine()
        self.assertFalse((self.work / "sample.bin").exists())

        self.assertEqual(self._exit_code("restore", entry_id), 0)
        restored = self.work / "sample.bin"
        self.assertEqual(restored.read_bytes(), self.EICAR_ISH)
        self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o640)
        self.assertEqual([p.name for p in self.work.iterdir()], ["sample.bin"],
                         "no temporary file is left behind")

    def test_restore_only_goes_back_into_the_folder_it_came_from(self) -> None:
        """The blocklist cannot name every directory where a file is dangerous
        (/etc/modprobe.d, /etc/udev/rules.d, ...). A folder repointed after the
        quarantine is refused instead, wherever it now leads."""
        entry_id, _payload = self._quarantine()
        self._swap_for_symlink(self.work, self.victim)

        self.assertEqual(self._exit_code("restore", entry_id), 2)
        self.assertEqual(list(self.victim.iterdir()), [])
        self.assertTrue((self.helper["RECORD_DIR"] / f"{entry_id}.json").exists(),
                        "a refused restore keeps the record, so it can be retried")

    def test_restore_does_not_overwrite(self) -> None:
        entry_id, _payload = self._quarantine()
        (self.work / "sample.bin").write_bytes(b"new file\n")
        self.assertEqual(self._exit_code("restore", entry_id), 1)
        self.assertEqual((self.work / "sample.bin").read_bytes(), b"new file\n")

    # -- read-file ---------------------------------------------------------

    def test_read_file_does_not_follow_a_log_swapped_for_a_symlink(self) -> None:
        """/var/log/clamav belongs to the clamav user, not root."""
        secret = self.victim / "shadow"
        secret.write_text("root:$6$hash\n")
        log = self.work / "clamd.log"
        log.symlink_to(secret)
        self.helper["LOG_FILES"] = frozenset({str(log)})
        self.assertEqual(self._exit_code("read_file", str(log)), 2)

    def test_read_file_prints_the_end_of_a_long_log_from_a_line_start(self) -> None:
        import io
        from contextlib import redirect_stdout

        log = self.work / "clamd.log"
        log.write_text("".join(f"line {n}\n" for n in range(1000)))
        self.helper["LOG_FILES"] = frozenset({str(log)})
        self.helper["LOG_TAIL_BYTES"] = 100
        output = io.StringIO()
        with redirect_stdout(output):
            self.helper["verb_read_file"]([str(log)])
        text = output.getvalue()
        self.assertTrue(text.startswith("line "), text[:20])
        self.assertTrue(text.endswith("line 999\n"))
        self.assertLessEqual(len(text), 100)


class TestBootAnalyzerIsReadOnly(unittest.TestCase):
    """The Boot Analyzer inspects bootloaders, sysctls and unit files.

    Those are precisely the settings where an automatic fix turns into an
    unbootable machine, so the feature's whole posture is that it reads and
    never writes. These tests assert that at the level of the code, not the
    intent, because "we just won't write anything" is not a boundary.
    """

    BOOT = REPO_ROOT / "src" / "clamguard" / "core" / "boot"

    def sources(self):
        return sorted(self.BOOT.rglob("*.py"))

    #: The only modules allowed to write, and only under the user's own XDG
    #: directories: the profile, the baseline, the exports, and the worked
    #: example dropped into the checks folder.
    WRITERS = {"profile.py", "baseline.py", "report.py", "custom.py"}

    def analysis_sources(self):
        """Everything that must never write anything at all."""
        return [path for path in self.sources() if path.name not in self.WRITERS]

    def test_no_check_opens_a_file_for_writing(self) -> None:
        offences = []
        for path in self.analysis_sources():
            for number, line in enumerate(path.read_text().splitlines(), start=1):
                if re.search(r"""open\([^)]*["'][waxr]\+?["']""", line) \
                        and "rb" not in line and '"r"' not in line:
                    offences.append(f"{path.name}:{number}")
        self.assertEqual(offences, [])

    def test_no_check_deletes_or_moves_anything(self) -> None:
        forbidden = ("os.remove", "os.unlink", "os.rename", "os.replace",
                     "os.rmdir", "shutil.rmtree", "shutil.move", "Path.unlink",
                     ".write_text(", ".write_bytes(", ".mkdir(", ".chmod(")
        offences = []
        for path in self.analysis_sources():
            text = path.read_text()
            for name in forbidden:
                if name in text:
                    offences.append(f"{path.name}: {name}")
        self.assertEqual(offences, [])

    def test_no_write_in_this_feature_names_an_absolute_path(self) -> None:
        """Four modules write. None of them chooses where.

        Checked structurally rather than by grepping for "/etc": this package
        is full of absolute paths, and every one of them is somewhere it
        *reads*. What must not exist is a write whose destination is a literal
        path rather than something the caller or core.paths supplied.
        """
        writes = ("write_text", "write_bytes", "mkdir", "chmod", "replace",
                  "unlink", "rmdir", "touch", "symlink_to")
        offences = []
        for path in self.sources():
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                target = node.func
                # A literal path can only reach a write as the object it is
                # called on — Path("/etc/x").write_text(...) — or as the first
                # argument of open()/os.* .
                if isinstance(target, ast.Attribute) and target.attr in writes:
                    receiver = target.value
                    if isinstance(receiver, ast.Constant) \
                            and isinstance(receiver.value, str) \
                            and receiver.value.startswith("/"):
                        offences.append(f"{path.name}:{node.lineno} {target.attr}")
                    if isinstance(receiver, ast.Call) and node.args is not None:
                        for argument in receiver.args:
                            if isinstance(argument, ast.Constant) \
                                    and isinstance(argument.value, str) \
                                    and argument.value.startswith("/"):
                                offences.append(
                                    f"{path.name}:{node.lineno} {target.attr}")
                if isinstance(target, ast.Name) and target.id == "open" \
                        and len(node.args) >= 2:
                    mode = node.args[1]
                    if isinstance(mode, ast.Constant) and "r" not in str(mode.value):
                        offences.append(f"{path.name}:{node.lineno} open(mode=…)")
        self.assertEqual(offences, [],
                         "a write in the Boot Analyzer picked its own destination")

    def test_the_writers_take_their_destination_from_core_paths(self) -> None:
        for name in sorted(self.WRITERS - {"report.py"}):
            with self.subTest(module=name):
                self.assertIn("paths.", (self.BOOT / name).read_text(),
                              "a writer must take its destination from core.paths")

    def test_the_analyzer_never_reaches_for_the_privileged_helper(self) -> None:
        """Checked by import, not by substring: the prose says "unprivileged"
        all over this package, and that is the opposite of a problem."""
        for path in self.sources():
            tree = ast.parse(path.read_text())
            with self.subTest(module=path.name):
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom):
                        self.assertNotIn("privileged", node.module or "")
                    elif isinstance(node, ast.Import):
                        for alias in node.names:
                            self.assertNotIn("privileged", alias.name)
                    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                        self.assertNotIn("pkexec", node.value,
                                         "nothing here should mention pkexec")

    def test_no_new_privileged_verb_was_added_for_the_boot_analyzer(self) -> None:
        namespace = helper_namespace()
        self.assertEqual(
            set(namespace["VERBS"]),
            {"status", "read-file", "write-config", "service", "update-db",
             "quarantine", "restore"},
            "the Boot Analyzer must not have grown a way to become root")

    def test_every_command_the_analyzer_can_run_is_on_the_allow_list(self) -> None:
        from clamguard.core.boot.probe import ALLOWED_COMMANDS

        called = set()
        for path in self.sources():
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                target = node.func
                if isinstance(target, ast.Attribute) and target.attr == "run" \
                        and node.args and isinstance(node.args[0], ast.Constant) \
                        and isinstance(node.args[0].value, str):
                    called.add(node.args[0].value)
        self.assertTrue(called, "no probe.run() calls were found at all")
        self.assertEqual(called - set(ALLOWED_COMMANDS), set())

    def test_the_allow_list_contains_nothing_that_changes_state(self) -> None:
        from clamguard.core.boot.probe import ALLOWED_COMMANDS

        self.assertEqual(
            ALLOWED_COMMANDS & {"sh", "bash", "sudo", "pkexec", "rm", "mv",
                                "chmod", "chown", "mount", "umount", "modprobe",
                                "sysctl", "grub-install", "bootctl-install",
                                "mkinitcpio", "dracut", "update-initramfs"},
            set())

    def test_a_user_written_check_cannot_execute_anything(self) -> None:
        from clamguard.core.boot import custom

        for kind in custom.KINDS:
            with self.subTest(kind=kind):
                self.assertNotIn("command", kind)
                self.assertNotIn("exec", kind)
        source = (self.BOOT / "custom.py").read_text()
        self.assertNotIn("subprocess", source)
        self.assertNotIn("eval(", source)
        self.assertNotIn("exec(", source)

    def test_the_suggested_command_script_arrives_inert(self) -> None:
        from clamguard.core.boot.model import Category, Finding, Fix, Report, Severity
        from clamguard.core.boot.report import to_script

        report = Report(findings=(Finding(
            id="a.b", check_id="a", category=Category.BOOTCHAIN,
            severity=Severity.CRITICAL, title="t", summary="s",
            fixes=(Fix("Destroy everything", command="rm -rf / --no-preserve-root"),),
        ),))
        script = to_script(report)
        self.assertIn("# rm -rf / --no-preserve-root", script)
        for line in script.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                self.assertIn(stripped,
                              ("#!/bin/bash", "set -euo pipefail",
                               "echo \'Nothing happened: every command in this "
                               "file is commented out.\'"),
                              f"this line would run: {line!r}")

    def test_the_html_export_escapes_everything_it_is_given(self) -> None:
        """Threat names and file paths reach the report; neither is trusted."""
        from clamguard.core.boot.model import (
            Category, Evidence, Finding, Report, Severity)
        from clamguard.core.boot.report import to_html

        nasty = '<img src=x onerror="fetch(\'http://evil/\')">'
        report = Report(
            findings=(Finding(id="a.b", check_id="a", category=Category.PERSISTENCE,
                              severity=Severity.HIGH, title=nasty, summary=nasty,
                              value=nasty,
                              evidence=(Evidence(nasty, nasty),)),),
            facts={"Bootloader": nasty}, hostname=nasty,
        )
        html = to_html(report)
        # The payload must survive only as inert text. `onerror=` still appears
        # as characters — what must not survive is the `<` that would start a
        # tag, or the unescaped quote that would open an attribute.
        self.assertNotIn("<img", html)
        self.assertNotIn('onerror="', html)
        self.assertNotIn("http://evil/'", html)
        self.assertIn("&lt;img", html, "the payload should be shown, escaped")

    def test_the_html_export_fetches_nothing(self) -> None:
        from clamguard.core.boot.model import Report
        from clamguard.core.boot.report import to_html

        html = to_html(Report())
        for marker in ("<script", "<iframe", "src=\"http", "@import"):
            self.assertNotIn(marker, html)


class TestHuntCannotWriteOrEscape(unittest.TestCase):
    """Hunt reads every log on the machine and runs a query language over it.

    Two things follow. The log lines are attacker-influenced text, so nothing
    may interpret them; and a query language over a database is one bug away
    from being a way to change that database, so the connection it runs on is
    read-only at the VFS level rather than by the compiler being careful.
    """

    HUNT = REPO_ROOT / "src" / "clamguard" / "core" / "hunt"

    def sources(self):
        return sorted(self.HUNT.rglob("*.py"))

    #: The only modules allowed to write, and only under XDG or a directory
    #: the user picked in a file dialog.
    WRITERS = {"store.py", "settings.py", "saved.py", "rules.py", "export.py"}

    def test_reading_the_journal_needs_no_privilege(self) -> None:
        """It reads what the user could read by typing the same command."""
        source = (self.HUNT / "journal.py").read_text()
        for word in ("sudo", "pkexec", "setuid", "--root", "privileged"):
            with self.subTest(word=word):
                self.assertNotIn(word, source)

    def language_sources(self):
        """The query engine. Nothing in here may write anything, ever."""
        return sorted((self.HUNT / "kql").rglob("*.py"))

    # -- the language ------------------------------------------------------

    #: A SQL statement that changes something, as opposed to the English word
    #: "insert" appearing in a tooltip. Matched as a statement so that
    #: "Insert at the cursor" and "Drop columns by name" are not offences.
    WRITING_SQL = re.compile(
        r"\b(INSERT\s+(INTO|OR)|UPDATE\s+\w+\s+SET|DELETE\s+FROM|"
        r"DROP\s+(TABLE|INDEX|VIEW)|ALTER\s+TABLE|"
        r"CREATE\s+(TABLE|INDEX|VIRTUAL|VIEW|TRIGGER)|"
        r"ATTACH\s+DATABASE|DETACH\s+DATABASE|VACUUM|REINDEX)\b",
        re.IGNORECASE)

    def test_the_query_engine_emits_no_statement_that_changes_anything(self) -> None:
        """Every string literal the query engine holds, checked for SQL."""
        offences = []
        for path in self.language_sources():
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                found = self.WRITING_SQL.search(node.value)
                if found:
                    offences.append(f"{path.name}:{node.lineno} {found.group(0)}")
        self.assertEqual(offences, [],
                         "the query language can produce a statement that writes")

    def test_the_query_engine_never_opens_a_file(self) -> None:
        offences = []
        for path in self.language_sources():
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                target = node.func
                if isinstance(target, ast.Name) and target.id in ("open", "Path"):
                    offences.append(f"{path.name}:{node.lineno} {target.id}()")
                if isinstance(target, ast.Attribute) and target.attr in (
                        "write_text", "write_bytes", "mkdir", "unlink",
                        "remove", "rmtree", "chmod"):
                    offences.append(f"{path.name}:{node.lineno} {target.attr}")
        self.assertEqual(offences, [],
                         "the query engine touched the filesystem")

    #: The one module in core/hunt allowed to run a command, and the only
    #: program it may run. Reading the systemd journal means executing
    #: journalctl; confining that to a single named module with an argument
    #: allow-list is what keeps "Hunt cannot run anything" a real statement
    #: rather than one that quietly stopped being true.
    COMMAND_RUNNER = "journal.py"
    COMMAND_PROGRAM = "journalctl"

    def test_only_one_module_in_hunt_may_run_a_command(self) -> None:
        """A second module joining the exemption has to be a deliberate act."""
        offenders = []
        for path in self.sources():
            if path.name == self.COMMAND_RUNNER:
                continue
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                for name in names:
                    if name.split(".")[0] in ("subprocess", "pty", "shlex",
                                              "multiprocessing", "ctypes"):
                        offenders.append(f"{path.name}:{node.lineno} {name}")
        self.assertEqual(offenders, [],
                         f"only {self.COMMAND_RUNNER} may run a command")

    def test_the_one_command_runner_runs_exactly_one_program(self) -> None:
        from clamguard.core.hunt import journal

        self.assertEqual(journal.PROGRAM, self.COMMAND_PROGRAM)
        source = (self.HUNT / self.COMMAND_RUNNER).read_text()
        self.assertIn("shutil.which(PROGRAM)", source,
                      "the program must be resolved through PATH, never "
                      "taken from settings or the database")
        self.assertNotIn("shell=True", source)

    def test_the_command_runner_checks_every_argument_before_running(self) -> None:
        from clamguard.core.hunt import journal

        source = (self.HUNT / self.COMMAND_RUNNER).read_text()
        self.assertIn("check_arguments", source)
        # Every combination of settings the UI can produce.
        for window in journal.WINDOWS:
            for priority in journal.PRIORITIES:
                for cursor in ("", "s=ab;i=1;b=cd;m=2;t=3;x=4"):
                    options = journal.JournalOptions(window=window,
                                                     priority=priority)
                    with self.subTest(window=window, priority=priority):
                        self.assertEqual(
                            journal.check_arguments(
                                journal.build_arguments(options, cursor)), [])

    def test_the_command_runner_cannot_express_a_destructive_flag(self) -> None:
        """journalctl can rotate, vacuum and erase the journal."""
        from clamguard.core.hunt import journal

        for flag in ("--vacuum-size=1", "--vacuum-time=1s", "--vacuum-files=1",
                     "--rotate", "--flush", "--sync", "--relinquish-var",
                     "--setup-keys", "--update-catalog", "--header",
                     "--dump-catalog", "--interval=1"):
            with self.subTest(flag=flag):
                self.assertEqual(journal.check_arguments([flag]), [flag])

    def test_a_tampered_cursor_cannot_become_a_flag(self) -> None:
        """The cursor round-trips through a database file the user can edit."""
        from clamguard.core.hunt import journal

        for hostile in ("--vacuum-time=1s", "--rotate", "; rm -rf /",
                        "$(whoami)", "`id`", "--output=cat"):
            with self.subTest(cursor=hostile):
                arguments = journal.build_arguments(
                    journal.JournalOptions(), hostile)
                self.assertEqual(journal.check_arguments(arguments), [])
                self.assertNotIn(hostile, arguments)
                self.assertFalse([item for item in arguments
                                  if item.startswith("--after-cursor")])

    def test_nothing_in_hunt_shells_out_or_evaluates_code(self) -> None:
        """Checked as imports and calls, not as substrings.

        A substring search finds "pty." inside "empty." and "eval(" inside
        "evaluate(", which is how a security test turns into noise that gets
        switched off.
        """
        modules = {"pty", "shlex", "multiprocessing", "ctypes"}
        builtins = {"eval", "exec", "compile", "__import__"}
        dangerous = {"system", "popen", "execv", "execve", "execl", "execlp",
                     "spawnv", "fork", "posix_spawn"}
        offences = []
        for path in self.sources():
            if path.name == self.COMMAND_RUNNER:
                # Covered by the four tests above, which are stricter than
                # this one: one program, an argument allow-list, and no shell.
                continue
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split(".")[0] in modules:
                            offences.append(f"{path.name}:{node.lineno} {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    if (node.module or "").split(".")[0] in modules:
                        offences.append(f"{path.name}:{node.lineno} {node.module}")
                elif isinstance(node, ast.Call):
                    target = node.func
                    if isinstance(target, ast.Name) and target.id in builtins:
                        offences.append(f"{path.name}:{node.lineno} {target.id}()")
                    if isinstance(target, ast.Attribute) and target.attr in dangerous \
                            and isinstance(target.value, ast.Name) \
                            and target.value.id == "os":
                        offences.append(f"{path.name}:{node.lineno} os.{target.attr}")
        self.assertEqual(offences, [],
                         "Hunt must not be able to run anything")

    def test_nothing_in_hunt_can_reach_the_network(self) -> None:
        """`urllib.parse` is fine — it parses. `urllib.request` fetches."""
        allowed = {"urllib.parse"}
        offences = []
        for path in self.sources():
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                for name in names:
                    if name in allowed:
                        continue
                    for bad in ("socket", "http", "urllib.request", "ftplib",
                                "smtplib", "requests", "asyncio", "ssl"):
                        if name == bad or name.startswith(bad + "."):
                            offences.append(f"{path.name}:{node.lineno} {name}")
        self.assertEqual(offences, [], "Hunt makes no network requests")

    def test_the_language_refuses_the_operators_that_reach_outside(self) -> None:
        from clamguard.core.hunt.kql import KqlError, parse
        from clamguard.core.hunt.kql.parser import REFUSED_OPERATORS

        for word in ("evaluate", "externaldata", "invoke", "ingest"):
            with self.subTest(operator=word):
                self.assertIn(word, REFUSED_OPERATORS)
                with self.assertRaises(KqlError):
                    parse(f"Logs | {word} anything")

    def test_a_query_connection_is_opened_read_only(self) -> None:
        source = (self.HUNT / "store.py").read_text()
        self.assertIn("mode=ro", source)
        self.assertIn("query_only", source)

    def test_only_the_history_database_is_ever_attached(self) -> None:
        from clamguard.core.hunt.catalogue import ATTACHED_SCHEMAS
        from clamguard.core.hunt.indexer import HuntIndexer

        source = (self.HUNT / "indexer.py").read_text()
        self.assertEqual(ATTACHED_SCHEMAS, ("history",))
        self.assertIn("paths.HISTORY_DB", source)
        attachments = HuntIndexer.attachments
        self.assertTrue(callable(attachments))

    def test_an_attached_database_is_opened_read_only_too(self) -> None:
        self.assertIn('f"file:{target}?mode=ro"', (self.HUNT / "store.py").read_text())

    # -- writing -----------------------------------------------------------

    def test_no_write_in_hunt_names_an_absolute_path(self) -> None:
        writes = ("write_text", "write_bytes", "mkdir", "chmod", "replace",
                  "unlink", "rmdir", "touch", "symlink_to")
        offences = []
        for path in self.sources():
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                target = node.func
                if isinstance(target, ast.Attribute) and target.attr in writes:
                    receiver = target.value
                    if isinstance(receiver, ast.Constant) \
                            and isinstance(receiver.value, str) \
                            and receiver.value.startswith("/"):
                        offences.append(f"{path.name}:{node.lineno} {target.attr}")
                    if isinstance(receiver, ast.Call):
                        for argument in receiver.args:
                            if isinstance(argument, ast.Constant) \
                                    and isinstance(argument.value, str) \
                                    and argument.value.startswith("/"):
                                offences.append(
                                    f"{path.name}:{node.lineno} {target.attr}")
        self.assertEqual(offences, [],
                         "a write in Hunt picked its own destination")

    def test_the_writers_take_their_destination_from_core_paths(self) -> None:
        for name in sorted(self.WRITERS - {"export.py"}):
            with self.subTest(module=name):
                self.assertIn("paths.", (self.HUNT / name).read_text())

    def test_discovery_only_ever_reads(self) -> None:
        text = (self.HUNT / "discovery.py").read_text()
        for name in ("write_text", "write_bytes", "os.remove", "os.rename",
                     "shutil.", "mkdir", "chmod"):
            with self.subTest(call=name):
                self.assertNotIn(name, text)

    def test_discovery_does_not_follow_symlinked_directories(self) -> None:
        """A loop would otherwise run the crawl until its budget died, and a
        symlink out of the home directory would index something the user did
        not ask for."""
        self.assertIn("is_dir(follow_symlinks=False)",
                      (self.HUNT / "discovery.py").read_text())

    def test_no_new_privileged_verb_was_added_for_hunt(self) -> None:
        namespace = helper_namespace()
        self.assertEqual(
            set(namespace["VERBS"]),
            {"status", "read-file", "write-config", "service", "update-db",
             "quarantine", "restore"},
            "Hunt must not have grown a way to become root")

    def test_hunt_never_reaches_for_the_privileged_helper(self) -> None:
        for path in self.sources():
            tree = ast.parse(path.read_text())
            with self.subTest(module=path.name):
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom):
                        self.assertNotIn("privileged", node.module or "")
                    elif isinstance(node, ast.Import):
                        for alias in node.names:
                            self.assertNotIn("privileged", alias.name)

    # -- the store itself --------------------------------------------------

    def test_the_store_is_created_private(self) -> None:
        """It holds every log line on the machine. Some of them are tokens."""
        self.assertIn("chmod(0o600)", (self.HUNT / "store.py").read_text())

    def test_a_user_written_rule_is_a_query_and_nothing_else(self) -> None:
        from clamguard.core.hunt.rules import Rule, parse_rule

        rule = parse_rule({"id": "x", "title": "t", "query": "Logs | count",
                           "command": "rm -rf /", "exec": "evil"})
        self.assertIsInstance(rule, Rule)
        self.assertEqual(
            [name for name in Rule.__dataclass_fields__
             if name in ("command", "exec", "script", "path")], [],
            "a rule must have no field that could name something to run")

    def test_regular_expressions_from_a_query_are_length_capped(self) -> None:
        """Catastrophic backtracking is real, and the pattern came from a text
        box."""
        from clamguard.core.hunt.kql.functions import MAX_PATTERN, compile_pattern
        from clamguard.core.hunt.kql import KqlError

        self.assertLessEqual(MAX_PATTERN, 4000)
        with self.assertRaises(KqlError):
            compile_pattern("x" * (MAX_PATTERN + 1))

    # -- untrusted text in the UI -----------------------------------------

    def test_no_hunt_widget_renders_its_text_as_markup(self) -> None:
        """Every cell holds text something else wrote into a log file."""
        ui = REPO_ROOT / "src" / "clamguard" / "ui"
        suspects = [ui / "widgets" / "results_grid.py",
                    ui / "widgets" / "kql_editor.py",
                    ui / "widgets" / "chart.py",
                    ui / "pages" / "hunt.py",
                    ui / "pages" / "hunt_rail.py",
                    ui / "pages" / "hunt_insights.py",
                    ui / "pages" / "hunt_dialogs.py"]
        for path in suspects:
            text = path.read_text()
            with self.subTest(module=path.name):
                for name in ("setHtml", "insertHtml", "RichText",
                             "toHtml", "setMarkdown"):
                    self.assertNotIn(name, text,
                                     f"{path.name} can interpret a log line as markup")

    def test_the_csv_export_defuses_spreadsheet_formulas(self) -> None:
        from clamguard.core.hunt.export import to_csv
        from clamguard.core.hunt.model import ColumnType, ResultTable

        table = ResultTable.of([("A", ColumnType.STRING)],
                               [("=cmd|'/c calc'!A1",)])
        self.assertIn("\t=cmd", to_csv(table))


class TestUntrustedTextInTheUi(TempHomeTestCase):
    """File paths and threat names come from outside. They are not markup."""

    def setUp(self) -> None:
        super().setUp()
        self.app = qt_application()

    def test_no_label_interprets_its_text_as_html(self) -> None:
        """Qt's default auto-detects HTML. A file named `<img src=http://…>`
        would make ClamGuard fetch that URL — a beacon, from an application
        that promises it makes no network requests of its own."""
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QLabel

        from clamguard.core.context import AppContext
        from clamguard.ui.main_window import MainWindow, NAV_ITEMS

        context = AppContext()
        window = MainWindow(context)
        window.resize(1100, 800)
        window.show()
        try:
            for item in NAV_ITEMS:
                window.show_page(item.page_id)
                self.app.processEvents()

            offenders = [
                widget for widget in window.findChildren(QLabel)
                if widget.text() and widget.textFormat() != Qt.TextFormat.PlainText
            ]
            self.assertEqual(
                [w.text()[:40] for w in offenders], [],
                "these labels would render a crafted filename as markup")
        finally:
            for page in window._pages.values():
                page.shutdown()
            context.shutdown()
            window.tray.hide()
            window.deleteLater()
            self.app.processEvents()

    def test_the_widget_helpers_produce_plain_text(self) -> None:
        from PySide6.QtCore import Qt

        from clamguard.ui.widgets import Badge, ElidedLabel, KeyValueRow, label

        hostile = '<img src="http://attacker.example/p.png"><b>spoof</b>'
        row = KeyValueRow(hostile, hostile)
        widgets = [label(hostile), label(hostile, wrap=True),
                   label(hostile, selectable=True), ElidedLabel(hostile),
                   Badge(hostile, "danger"), row.key_label, row.value_label]
        for widget in widgets:
            self.assertEqual(widget.textFormat(), Qt.TextFormat.PlainText)
            self.assertEqual(widget.toolTip() or hostile, widget.toolTip() or hostile)


class TestQuarantineVaultPermissions(TempHomeTestCase):
    def test_the_vault_is_not_readable_by_other_users(self) -> None:
        self.paths.ensure_directories()
        for directory in (self.paths.QUARANTINE_DIR, self.paths.QUARANTINE_VAULT,
                          self.paths.QUARANTINE_META):
            mode = os.stat(directory).st_mode & 0o777
            self.assertEqual(mode & 0o077, 0,
                             f"{directory} is {oct(mode)}, readable by others")

    def test_payloads_are_written_private(self) -> None:
        from clamguard.core.privileged import PrivilegedHelper
        from clamguard.core.quarantine import Quarantine

        victim = self.tmp / "sample.bin"
        victim.write_bytes(b"pretend malware")
        vault = Quarantine(PrivilegedHelper())
        captured = {}
        vault.quarantine(victim, "T", on_success=lambda e: captured.setdefault("e", e))
        entry = captured["e"]
        self.assertEqual(os.stat(entry.payload()).st_mode & 0o077, 0)
        self.assertEqual(os.stat(entry.metadata_path()).st_mode & 0o077, 0)


class TestServicesAreReadOnly(unittest.TestCase):
    """The Services page browses every unit on the machine.

    That makes it the obvious place to grow a Start button, and the reason it
    must not: `clamguard-helper` holds a ClamAV-only allow-list, and widening it
    for a browser would turn "controls ClamAV" into "controls this machine".
    The page offers commands to copy instead, so these tests assert the
    boundary rather than the intention.
    """

    UNITS = REPO_ROOT / "src" / "clamguard" / "core" / "units"
    PAGES = (REPO_ROOT / "src" / "clamguard" / "ui" / "pages" / "services.py",
             REPO_ROOT / "src" / "clamguard" / "ui" / "pages" / "services_detail.py")

    def sources(self):
        return sorted(self.UNITS.rglob("*.py"))

    def test_nothing_in_the_feature_reaches_for_the_privileged_helper(self) -> None:
        for path in list(self.sources()) + list(self.PAGES):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            with self.subTest(module=path.name):
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom):
                        self.assertNotIn("privileged", node.module or "")
                    elif isinstance(node, ast.Import):
                        for alias in node.names:
                            self.assertNotIn("privileged", alias.name)

    def test_no_new_privileged_verb_was_added_for_the_services_page(self) -> None:
        namespace = helper_namespace()
        self.assertEqual(
            set(namespace["VERBS"]),
            {"status", "read-file", "write-config", "service", "update-db",
             "quarantine", "restore"},
            "browsing units must not have grown a way to become root")

    def test_the_helper_still_controls_only_the_clamav_units(self) -> None:
        """Eight names, not eight units: the three ClamAV roles plus the
        socket, each spelled the way Arch/Debian and upstream package it."""
        namespace = helper_namespace()
        self.assertEqual(
            set(namespace["UNITS"]),
            {"clamav-daemon.service", "clamav-freshclam.service",
             "clamav-clamonacc.service", "clamav-daemon.socket",
             "clamd.service", "clamd@scan.service", "freshclam.service",
             "clamonacc.service"},
            "the Services page must not have widened the unit allow-list")
        for unit in namespace["UNITS"]:
            self.assertTrue(
                unit.startswith(("clamav", "clamd", "freshclam", "clamonacc")),
                f"{unit} is not a ClamAV unit")

    def test_every_command_the_feature_runs_only_reads(self) -> None:
        """Collected from the code, not from a list someone maintains."""
        allowed = {"systemctl", "systemd-analyze", "pacman", "dpkg", "dpkg-query",
                   "rpm", "whatis", "ss"}
        called = set()
        for path in self.sources():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                if name in ("run", "which") and node.args \
                        and isinstance(node.args[0], ast.Constant) \
                        and isinstance(node.args[0].value, str):
                    called.add(node.args[0].value)
        self.assertTrue(called, "no commands were found at all")
        self.assertEqual(called - allowed, set())

    FORBIDDEN_VERBS = {"start", "stop", "restart", "reload", "enable", "disable",
                       "mask", "unmask", "kill", "isolate", "set-property",
                       "daemon-reload", "reset-failed", "edit", "revert", "preset"}

    def test_no_state_changing_systemctl_verb_is_ever_passed(self) -> None:
        """`systemctl show`, `list-units` and `list-unit-files` only.

        Every string constant in the package is checked, with one exemption:
        a constant that is only *compared against* — the right-hand side of an
        `in` test, such as the preset parser asking whether a line starts with
        "enable" — is reading, not running. Anything that could be passed to
        a command is still caught.
        """
        for path in self.sources():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            compared = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Compare):
                    for op, right in zip(node.ops, node.comparators):
                        if isinstance(op, (ast.In, ast.NotIn)) and \
                                isinstance(right, (ast.Tuple, ast.List, ast.Set)):
                            compared |= {id(element) for element in right.elts}
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                        and id(node) not in compared:
                    self.assertNotIn(node.value, self.FORBIDDEN_VERBS,
                                     f"{path.name} names a state-changing verb")

    def test_a_full_read_runs_only_read_only_commands(self) -> None:
        """What is actually executed, recorded — not what the source spells."""
        import importlib
        from unittest import mock

        from clamguard.core.process import CommandResult

        enrich = importlib.import_module("clamguard.core.units.enrich")
        inventory = importlib.import_module("clamguard.core.units.inventory")
        manager = importlib.import_module("clamguard.core.units.manager")

        executed: list[tuple[str, tuple[str, ...]]] = []

        def fake_run(program, args=(), **_kwargs):
            executed.append((program.rpartition("/")[2], tuple(args)))
            stdout = "Id=a.service\nLoadState=loaded\n" if "show" in args else ""
            if "list-unit-files" in args:
                stdout = "a.service enabled enabled\n"
            return CommandResult(program, tuple(args), 0, stdout, "")

        def fake_which(program):
            return f"/usr/bin/{program}"

        for user in (False, True):
            with self.subTest(user=user), \
                    mock.patch.object(inventory, "run", fake_run), \
                    mock.patch.object(inventory, "which", fake_which), \
                    mock.patch.object(enrich, "run", fake_run), \
                    mock.patch.object(enrich, "which", fake_which):
                manager.gather(user=user)
        self.assertTrue(executed)
        allowed = {
            "systemctl": {"show", "list-units", "list-unit-files"},
            "systemd-analyze": {"security", "blame"},
        }
        for program, args in executed:
            words = [a for a in args if not a.startswith("-")]
            if program in allowed:
                self.assertIn(words[0], allowed[program], f"{program} {' '.join(args)}")
            for word in words:
                self.assertNotIn(word, self.FORBIDDEN_VERBS, f"{program} {' '.join(args)}")

    def test_the_page_offers_commands_to_copy_and_never_runs_them(self) -> None:
        """CommandBlock is copy-only by construction — assert it is what the
        detail pane uses, and that no QProcess or subprocess sits beside it."""
        source = self.PAGES[1].read_text(encoding="utf-8")
        self.assertIn("CommandBlock", source)
        for banned in ("QProcess", "subprocess", "os.system", "Popen"):
            self.assertNotIn(banned, source, f"{banned} has no business here")

    def test_the_feature_writes_no_files(self) -> None:
        for path in list(self.sources()) + list(self.PAGES):
            text = path.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), start=1):
                if re.search(r"""open\([^)]*["'][waxr]\+["']""", line) or \
                        re.search(r"""\bopen\([^)]*["'][wax]["']""", line):
                    self.fail(f"{path.name}:{number} opens a file for writing")
                for banned in ("os.remove(", "os.unlink(", "shutil.rmtree(",
                               "os.rename(", ".write_text(", ".write_bytes("):
                    self.assertNotIn(banned, line,
                                     f"{path.name}:{number} modifies the filesystem")


class TestSqlInjection(TempHomeTestCase):
    def test_search_terms_are_bound_not_interpolated(self) -> None:
        from clamguard.core.history import History

        history = History(self.tmp / "history.db")
        scan_id = history.start_scan("quick", ["/home"])
        history.add_detection(scan_id, "/home/x", "Threat.One")
        history.finish_scan(scan_id, status="completed", threats_found=1)

        for hostile in ("'; DROP TABLE scans; --", "%", "_", "' OR '1'='1"):
            history.search_scans(text=hostile)
            history.search_detections(hostile)
        # The tables must still be there and still hold the row.
        self.assertEqual(history.totals()["scans"], 1)
        self.assertEqual(history.totals()["detections"], 1)


if __name__ == "__main__":
    unittest.main()
