"""The probe: caching, honest failures, and the read-only guarantee.

The probe is the only thing in the Boot Analyzer that touches the machine, so
these tests are the ones that pin down what "read-only" actually means, and
they check the parsing that several checks quietly depend on — mountinfo
stacking, the kernel command line, and the difference between "absent" and
"not allowed".
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from .support import REPO_ROOT, qt_application  # noqa: F401  - sets sys.path

from clamguard.core.boot.probe import (  # noqa: E402
    ALLOWED_COMMANDS,
    FakeProbe,
    Probe,
)


class TestFileReading(unittest.TestCase):
    def setUp(self) -> None:
        qt_application()
        self.tmp = Path(tempfile.mkdtemp(prefix="clamguard-probe-"))
        self.probe = Probe()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_a_missing_file_is_missing_not_denied(self) -> None:
        result = self.probe.file(self.tmp / "nope")
        self.assertTrue(result.missing)
        self.assertFalse(result.denied)
        self.assertFalse(result.ok)
        self.assertEqual(result.text, "")

    def test_an_unreadable_file_is_denied_not_missing(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root can read anything")
        secret = self.tmp / "secret"
        secret.write_text("x")
        secret.chmod(0o000)
        result = self.probe.file(secret)
        # NTFS and other non-POSIX filesystems ignore chmod, which would make
        # this assert the opposite of what it means.
        if result.ok:
            self.skipTest("this filesystem does not enforce permissions")
        self.assertFalse(result.missing)
        self.assertTrue(result.denied)

    def test_a_directory_is_reported_as_one_rather_than_read(self) -> None:
        result = self.probe.file(self.tmp)
        self.assertFalse(result.ok)
        self.assertIn("directory", result.error)

    def test_reads_are_cached(self) -> None:
        target = self.tmp / "file"
        target.write_text("first")
        self.assertEqual(self.probe.text(target), "first")
        target.write_text("second")
        self.assertEqual(self.probe.text(target), "first",
                         "a second read in the same run must come from the cache")

    def test_one_read_produces_one_audit_record(self) -> None:
        target = self.tmp / "file"
        target.write_text("x")
        self.probe.text(target)
        self.probe.text(target)
        records = [r for r in self.probe.records if r.target == str(target)]
        self.assertEqual(len(records), 1)

    def test_value_strips_and_takes_the_first_line(self) -> None:
        target = self.tmp / "sysfs"
        target.write_text("\n  2  \nignored\n")
        self.assertEqual(self.probe.value(target), "2")

    def test_binary_content_never_raises(self) -> None:
        target = self.tmp / "binary"
        target.write_bytes(b"\xff\xfe\x00rubbish")
        self.assertIsInstance(self.probe.text(target), str)

    def test_raw_bytes_come_back_unmangled(self) -> None:
        target = self.tmp / "efivar"
        target.write_bytes(b"\x06\x00\x00\x00\x01")
        self.assertEqual(self.probe.read_bytes(target), b"\x06\x00\x00\x00\x01")

    def test_raw_bytes_from_a_missing_file_are_none(self) -> None:
        self.assertIsNone(self.probe.read_bytes(self.tmp / "nope"))


class TestStat(unittest.TestCase):
    def setUp(self) -> None:
        qt_application()
        self.tmp = Path(tempfile.mkdtemp(prefix="clamguard-probe-"))
        self.probe = Probe()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_stat_does_not_follow_a_symlink_by_default(self) -> None:
        target = self.tmp / "real"
        target.mkdir(mode=0o755)
        link = self.tmp / "link"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("this filesystem has no symlinks")
        # A symlink's own mode is 0777 everywhere; that is exactly the trap
        # that made /bin look world-writable.
        self.assertEqual(self.probe.stat(link).st_mode & 0o777, 0o777)
        self.assertEqual(self.probe.stat(link, follow=True).st_mode & 0o777, 0o755)

    def test_following_and_not_following_are_cached_separately(self) -> None:
        target = self.tmp / "dir"
        target.mkdir(mode=0o700)
        self.assertEqual(self.probe.stat(target).st_mode & 0o777, 0o700)
        self.assertEqual(self.probe.stat(target, follow=True).st_mode & 0o777, 0o700)

    def test_a_missing_path_stats_as_none(self) -> None:
        self.assertIsNone(self.probe.stat(self.tmp / "nope"))
        self.assertFalse(self.probe.exists(self.tmp / "nope"))

    def test_listing_a_missing_directory_gives_an_empty_list(self) -> None:
        self.assertEqual(self.probe.listdir(self.tmp / "nope"), [])


class TestCommands(unittest.TestCase):
    def setUp(self) -> None:
        qt_application()
        self.probe = Probe()

    def test_only_inspection_commands_may_be_run(self) -> None:
        with self.assertRaises(ValueError) as caught:
            self.probe.run("rm", "-rf", "/")
        self.assertIn("not an allowed inspection command", str(caught.exception))

    def test_the_allow_list_holds_nothing_that_changes_state(self) -> None:
        forbidden = {"rm", "mv", "cp", "chmod", "chown", "dd", "mkfs", "sh",
                     "bash", "sudo", "pkexec", "efibootmgr-set", "sysctl",
                     "mount", "umount", "modprobe", "insmod", "systemd-run"}
        self.assertEqual(ALLOWED_COMMANDS & forbidden, set())

    def test_systemctl_is_allowed_but_only_as_a_reader(self) -> None:
        # There is no way to stop systemctl writing from the allow-list alone,
        # so this asserts the intent at the call sites instead.
        source = (REPO_ROOT / "src" / "clamguard" / "core" / "boot").rglob("*.py")
        offences = []
        for path in source:
            text = path.read_text(encoding="utf-8")
            for verb in ("start", "stop", "restart", "enable", "disable",
                         "mask", "unmask", "set-property"):
                if f'"systemctl", "{verb}"' in text:
                    offences.append(f"{path.name}: systemctl {verb}")
        self.assertEqual(offences, [],
                         "the Boot Analyzer must never change a unit's state")

    def test_a_missing_program_is_a_result_not_an_exception(self) -> None:
        result = self.probe.run("mokutil", "--sb-state")
        self.assertIsNotNone(result)
        if not self.probe.available("mokutil"):
            self.assertIn("not installed", result.error)

    def test_command_results_are_cached_per_argument_vector(self) -> None:
        self.probe.run("uname", "-r")
        self.probe.run("uname", "-r")
        self.probe.run("uname", "-a")
        records = [r for r in self.probe.records if r.kind == "command"]
        self.assertEqual(len(records), 2)


class TestParsing(unittest.TestCase):
    def test_the_kernel_command_line_becomes_a_mapping(self) -> None:
        probe = FakeProbe(files={
            "/proc/cmdline": "BOOT_IMAGE=/vmlinuz root=UUID=abc rw quiet\n"})
        parameters = probe.cmdline_parameters()
        self.assertEqual(parameters["root"], "UUID=abc")
        self.assertEqual(parameters["quiet"], "")
        self.assertIn("rw", parameters)

    def test_a_repeated_parameter_keeps_the_last_value(self) -> None:
        probe = FakeProbe(files={"/proc/cmdline": "mitigations=auto mitigations=off"})
        self.assertEqual(probe.cmdline_parameters()["mitigations"], "off")

    def test_os_release_is_unquoted(self) -> None:
        probe = FakeProbe(files={
            "/etc/os-release": 'NAME="Arch Linux"\n# a comment\nID=arch\n'})
        fields = probe.os_release()
        self.assertEqual(fields["NAME"], "Arch Linux")
        self.assertEqual(fields["ID"], "arch")

    def test_mountinfo_is_parsed_into_target_source_type_and_options(self) -> None:
        probe = FakeProbe(files={"/proc/self/mountinfo": (
            "25 1 259:3 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p3 rw\n")})
        entry = probe.mount_for("/")
        self.assertEqual(entry["source"], "/dev/nvme0n1p3")
        self.assertEqual(entry["fstype"], "ext4")
        self.assertIn("relatime", entry["options"])

    def test_the_topmost_mount_wins_when_two_share_a_point(self) -> None:
        # /efi is routinely an autofs with the real vfat mounted over it.
        probe = FakeProbe(files={"/proc/self/mountinfo": (
            "35 67 0:39 / /efi rw shared:24 - autofs systemd-1 rw\n"
            "184 35 259:2 / /efi rw,nosuid shared:118 - vfat /dev/nvme0n1p2 rw,umask=0077\n"
        )})
        entry = probe.mount_for("/efi")
        self.assertEqual(entry["fstype"], "vfat",
                         "the autofs underneath must not shadow the real mount")

    def test_escaped_spaces_in_a_mount_point_are_decoded(self) -> None:
        probe = FakeProbe(files={"/proc/self/mountinfo": (
            "25 1 8:1 / /mnt/my\\040disk rw - ext4 /dev/sda1 rw\n")})
        self.assertIsNotNone(probe.mount_for("/mnt/my disk"))

    def test_malformed_mountinfo_lines_are_skipped_not_fatal(self) -> None:
        probe = FakeProbe(files={"/proc/self/mountinfo":
                                 "rubbish\n25 1 8:1 / / rw - ext4 /dev/sda1 rw\n"})
        self.assertEqual(len(probe.mounts()), 1)

    def test_sysctl_reads_the_file_rather_than_running_anything(self) -> None:
        probe = FakeProbe(files={"/proc/sys/kernel/kptr_restrict": "1\n"})
        self.assertEqual(probe.sysctl("kernel.kptr_restrict"), "1")
        self.assertEqual(probe.sysctl_int("kernel.kptr_restrict"), 1)

    def test_an_absent_sysctl_is_none_not_zero(self) -> None:
        self.assertIsNone(FakeProbe().sysctl_int("kernel.nope"))

    def test_a_non_numeric_sysctl_is_none_rather_than_a_crash(self) -> None:
        probe = FakeProbe(files={"/proc/sys/kernel/core_pattern": "|/usr/bin/x"})
        self.assertIsNone(probe.sysctl_int("kernel.core_pattern"))


class TestFakeProbe(unittest.TestCase):
    """The test double has to behave like the real one or the checks lie."""

    def test_anything_not_supplied_is_absent(self) -> None:
        probe = FakeProbe()
        self.assertTrue(probe.file("/anything").missing)
        self.assertEqual(probe.listdir("/anything"), [])
        self.assertIsNone(probe.stat("/anything"))

    def test_denied_files_report_as_denied(self) -> None:
        probe = FakeProbe(denied={"/boot/initramfs.img"})
        result = probe.file("/boot/initramfs.img")
        self.assertTrue(result.denied)
        self.assertFalse(result.missing)

    def test_a_stubbed_command_can_ignore_the_flags(self) -> None:
        probe = FakeProbe(commands={("systemd-analyze",): "Startup finished in 3s"})
        self.assertIn("Startup", probe.run("systemd-analyze", "time").stdout)

    def test_an_exact_argument_vector_wins_over_the_program_stub(self) -> None:
        probe = FakeProbe(commands={
            ("systemctl",): "generic",
            ("systemctl", "is-system-running"): "degraded",
        })
        self.assertEqual(probe.run("systemctl", "is-system-running").stdout,
                         "degraded")

    def test_a_program_declared_missing_reports_as_missing(self) -> None:
        probe = FakeProbe(binaries=set())
        self.assertFalse(probe.available("bootctl"))
        self.assertIn("not installed", probe.run("bootctl", "status").error)

    def test_the_fake_enforces_the_same_command_allow_list(self) -> None:
        with self.assertRaises(ValueError):
            FakeProbe().run("rm", "-rf", "/")

    def test_the_fake_stat_reports_the_mode_it_was_given(self) -> None:
        probe = FakeProbe(modes={"/boot": 0o040777})
        self.assertEqual(probe.stat("/boot").st_mode & 0o777, 0o777)


class TestAudit(unittest.TestCase):
    def test_the_probe_can_say_what_it_touched(self) -> None:
        probe = Probe()
        probe.text("/proc/cmdline")
        probe.listdir("/sys/class/tpm")
        lines = probe.log_lines()
        self.assertTrue(any("/proc/cmdline" in line for line in lines))
        self.assertIn("read", probe.summary())


if __name__ == "__main__":
    unittest.main()
