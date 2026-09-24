"""What the user wants analysed, and how harshly.

Two objects live here and they do different jobs:

:class:`Profile`
    The user's persisted choices — which checks run, which findings are muted,
    which severities they have overridden, and which preset is in force. It is
    mutable, it is JSON on disk, and the UI edits it.

:class:`Policy`
    The frozen, resolved view a check sees while it runs: thresholds and the
    severity to use for each named condition. A check never sees the Profile,
    so it cannot depend on mutable state, and every check is reproducible from
    ``(Probe, Policy)`` alone.

Why presets exist: "Secure Boot is off" is a five-alarm fire on a laptop that
leaves the house and a shrug on a desktop that never does. Rather than pick one
answer and be wrong for half the users, each such judgement has a **policy
key** whose severity the preset sets. The four presets are the four reasonable
answers; the per-finding override is the fifth.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from .. import paths
from ..logging_setup import get_logger
from .model import Finding, Severity

log = get_logger(__name__)

PROFILE_FILE = "boot-profile.json"


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

#: Every numeric judgement the checks make, with the balanced value. Presets
#: override individual entries; the user can override any of them again.
BASE_THRESHOLDS: dict[str, float] = {
    #: Total boot time above which the analyzer says something about it.
    "boot_total_seconds": 90.0,
    #: A single unit taking longer than this is called out.
    "unit_slow_seconds": 15.0,
    #: Firmware (pre-bootloader) time worth mentioning.
    "firmware_seconds": 30.0,
    #: How many error-priority journal messages this boot is unremarkable.
    "journal_error_budget": 50.0,
    #: systemd-analyze security exposure at or above this is reported.
    "exposure_unsafe": 9.0,
    #: An initramfs older than its kernel image by this many days is stale.
    "initramfs_stale_days": 30.0,
    #: Window for "changed recently" when looking at /boot.
    "boot_change_days": 7.0,
    #: Kernel newer than the running one by this long means a pending reboot.
    "pending_reboot_hours": 1.0,
}


# ---------------------------------------------------------------------------
# Policy severities
# ---------------------------------------------------------------------------

#: Every judgement call a check makes, and what "balanced" thinks of it.
#: A check asks for its severity by key rather than hard-coding one, which is
#: what makes the presets and the per-site tuning possible.
BASE_SEVERITIES: dict[str, Severity] = {
    # -- firmware ---------------------------------------------------------
    "secure_boot_off": Severity.MEDIUM,
    "secure_boot_setup_mode": Severity.HIGH,
    "no_uefi": Severity.LOW,
    "no_tpm": Severity.LOW,
    "no_measured_boot": Severity.INFO,
    "no_dbx": Severity.LOW,
    "boot_order_unexpected": Severity.LOW,
    "esp_permissions": Severity.MEDIUM,
    # -- kernel -----------------------------------------------------------
    "lockdown_none": Severity.LOW,
    "module_signing_off": Severity.LOW,
    "unsigned_modules": Severity.LOW,
    "kernel_tainted_serious": Severity.HIGH,
    "kernel_tainted_modules": Severity.LOW,
    "cmdline_risky": Severity.HIGH,
    "cpu_vulnerable": Severity.HIGH,
    "microcode_stale": Severity.MEDIUM,
    "no_iommu": Severity.LOW,
    "stale_running_kernel": Severity.MEDIUM,
    "kexec_enabled": Severity.INFO,
    # -- hardening --------------------------------------------------------
    "sysctl_weak": Severity.LOW,
    "no_mac_lsm": Severity.LOW,
    "unprivileged_userns": Severity.INFO,
    "suid_dumpable": Severity.MEDIUM,
    # -- boot chain -------------------------------------------------------
    "boot_world_writable": Severity.CRITICAL,
    "boot_permissions": Severity.MEDIUM,
    "grub_no_password": Severity.LOW,
    "initramfs_missing": Severity.HIGH,
    "initramfs_stale": Severity.MEDIUM,
    "no_root_encryption": Severity.LOW,
    "unencrypted_swap": Severity.MEDIUM,
    "mount_options_weak": Severity.LOW,
    "boot_on_removable": Severity.MEDIUM,
    # -- services ---------------------------------------------------------
    "failed_unit": Severity.MEDIUM,
    "system_degraded": Severity.LOW,
    "unit_exposure": Severity.INFO,
    "vendor_unit_overridden": Severity.LOW,
    "masked_security_unit": Severity.MEDIUM,
    # -- persistence ------------------------------------------------------
    "ld_preload": Severity.HIGH,
    #: These four are all "a start-up entry does something with no innocent
    #: explanation". They are deliberately equal: where the entry lives says
    #: nothing about how bad the command in it is. Entries that are merely
    #: unusual never reach this severity — checks.persistence.weight_of caps
    #: those at LOW before the policy is consulted.
    "suspicious_exec": Severity.HIGH,
    "autostart_suspicious": Severity.HIGH,
    "cron_suspicious": Severity.HIGH,
    "profile_script_suspicious": Severity.HIGH,
    "modprobe_install_hook": Severity.HIGH,
    "udev_run_rule": Severity.LOW,
    "world_writable_path": Severity.HIGH,
    "unit_in_home": Severity.MEDIUM,
    # -- performance ------------------------------------------------------
    "boot_slow": Severity.LOW,
    "unit_slow": Severity.INFO,
    "device_timeout": Severity.MEDIUM,
    "firmware_slow": Severity.INFO,
    # -- integrity --------------------------------------------------------
    "baseline_drift": Severity.MEDIUM,
    "baseline_drift_expected": Severity.INFO,
    "journal_errors": Severity.LOW,
}


@dataclass(frozen=True)
class Preset:
    """A named stance, as a set of differences from the balanced defaults."""

    name: str
    title: str
    blurb: str
    thresholds: Mapping[str, float] = field(default_factory=dict)
    severities: Mapping[str, Severity] = field(default_factory=dict)


PRESETS: dict[str, Preset] = {
    "relaxed": Preset(
        "relaxed", "Relaxed",
        "For a desktop that never leaves the house. Reports what is broken and "
        "what is dangerous; stays quiet about hardening you have chosen not to do.",
        thresholds={
            "boot_total_seconds": 180.0,
            "unit_slow_seconds": 30.0,
            "firmware_seconds": 60.0,
            "journal_error_budget": 200.0,
            "exposure_unsafe": 9.6,
        },
        severities={
            "secure_boot_off": Severity.LOW,
            "no_tpm": Severity.INFO,
            "no_dbx": Severity.INFO,
            "lockdown_none": Severity.INFO,
            "module_signing_off": Severity.INFO,
            "unsigned_modules": Severity.INFO,
            "kernel_tainted_modules": Severity.INFO,
            "sysctl_weak": Severity.INFO,
            "no_mac_lsm": Severity.INFO,
            "no_root_encryption": Severity.INFO,
            "no_iommu": Severity.INFO,
            "grub_no_password": Severity.INFO,
            "mount_options_weak": Severity.INFO,
            "unit_exposure": Severity.INFO,
            "vendor_unit_overridden": Severity.INFO,
            "udev_run_rule": Severity.INFO,
            "autostart_suspicious": Severity.MEDIUM,
            "cron_suspicious": Severity.MEDIUM,
            "profile_script_suspicious": Severity.MEDIUM,
            "boot_slow": Severity.INFO,
            "system_degraded": Severity.INFO,
        },
    ),
    "balanced": Preset(
        "balanced", "Balanced",
        "The default. Flags anything that meaningfully weakens the boot chain "
        "or that looks like persistence, and mentions the rest once.",
    ),
    "strict": Preset(
        "strict", "Strict",
        "For a machine that travels, or that you would rather over-report. "
        "Hardening you have skipped becomes a finding rather than a note.",
        thresholds={
            "boot_total_seconds": 60.0,
            "unit_slow_seconds": 8.0,
            "firmware_seconds": 20.0,
            "journal_error_budget": 20.0,
            "exposure_unsafe": 8.0,
            "initramfs_stale_days": 14.0,
        },
        severities={
            "secure_boot_off": Severity.HIGH,
            "no_tpm": Severity.MEDIUM,
            "no_measured_boot": Severity.LOW,
            "no_dbx": Severity.MEDIUM,
            "lockdown_none": Severity.MEDIUM,
            "module_signing_off": Severity.MEDIUM,
            "unsigned_modules": Severity.MEDIUM,
            "kernel_tainted_modules": Severity.MEDIUM,
            "sysctl_weak": Severity.MEDIUM,
            "no_mac_lsm": Severity.MEDIUM,
            "unprivileged_userns": Severity.LOW,
            "no_root_encryption": Severity.MEDIUM,
            "no_iommu": Severity.MEDIUM,
            "grub_no_password": Severity.MEDIUM,
            "mount_options_weak": Severity.MEDIUM,
            "kexec_enabled": Severity.LOW,
            "unit_exposure": Severity.LOW,
            "vendor_unit_overridden": Severity.MEDIUM,
            "udev_run_rule": Severity.MEDIUM,
            "boot_slow": Severity.MEDIUM,
            "unit_slow": Severity.LOW,
            "journal_errors": Severity.MEDIUM,
            "system_degraded": Severity.MEDIUM,
        },
    ),
    "paranoid": Preset(
        "paranoid", "Paranoid",
        "Treats every unverified link in the boot chain as a finding. Expect a "
        "long list on a normal desktop — that is the point of this setting.",
        thresholds={
            "boot_total_seconds": 45.0,
            "unit_slow_seconds": 5.0,
            "firmware_seconds": 15.0,
            "journal_error_budget": 10.0,
            "exposure_unsafe": 7.0,
            "initramfs_stale_days": 7.0,
        },
        severities={
            "secure_boot_off": Severity.CRITICAL,
            "secure_boot_setup_mode": Severity.CRITICAL,
            "no_uefi": Severity.MEDIUM,
            "no_tpm": Severity.HIGH,
            "no_measured_boot": Severity.MEDIUM,
            "no_dbx": Severity.HIGH,
            "lockdown_none": Severity.HIGH,
            "module_signing_off": Severity.HIGH,
            "unsigned_modules": Severity.HIGH,
            "kernel_tainted_modules": Severity.MEDIUM,
            "sysctl_weak": Severity.MEDIUM,
            "no_mac_lsm": Severity.HIGH,
            "unprivileged_userns": Severity.MEDIUM,
            "no_root_encryption": Severity.HIGH,
            "unencrypted_swap": Severity.HIGH,
            "no_iommu": Severity.HIGH,
            "grub_no_password": Severity.MEDIUM,
            "mount_options_weak": Severity.MEDIUM,
            "kexec_enabled": Severity.MEDIUM,
            "boot_permissions": Severity.HIGH,
            "unit_exposure": Severity.LOW,
            "vendor_unit_overridden": Severity.MEDIUM,
            "masked_security_unit": Severity.HIGH,
            "udev_run_rule": Severity.MEDIUM,
            "boot_slow": Severity.MEDIUM,
            "unit_slow": Severity.LOW,
            "journal_errors": Severity.MEDIUM,
            "system_degraded": Severity.MEDIUM,
            "baseline_drift": Severity.HIGH,
        },
    ),
}

DEFAULT_PRESET = "balanced"


# ---------------------------------------------------------------------------
# What a check sees
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Policy:
    """The resolved thresholds and severities for one analysis run."""

    preset: str = DEFAULT_PRESET
    thresholds: Mapping[str, float] = field(default_factory=lambda: dict(BASE_THRESHOLDS))
    severities: Mapping[str, Severity] = field(default_factory=lambda: dict(BASE_SEVERITIES))

    def threshold(self, key: str) -> float:
        """A numeric limit. Unknown keys fall back to the balanced default."""
        if key in self.thresholds:
            return float(self.thresholds[key])
        if key in BASE_THRESHOLDS:
            return BASE_THRESHOLDS[key]
        raise KeyError(f"no such threshold: {key!r}")

    def severity(self, key: str) -> Severity:
        """How severe this policy considers a named condition."""
        if key in self.severities:
            return self.severities[key]
        if key in BASE_SEVERITIES:
            return BASE_SEVERITIES[key]
        raise KeyError(f"no such policy: {key!r}")

    def at_least(self, key: str, floor: Severity) -> Severity:
        """The policy severity, but never below `floor`.

        For conditions that are bad regardless of taste — a world-writable
        file under /boot stays serious even on the relaxed preset.
        """
        return max(self.severity(key), floor)

    @classmethod
    def for_preset(cls, name: str) -> "Policy":
        preset = PRESETS.get(name, PRESETS[DEFAULT_PRESET])
        thresholds = dict(BASE_THRESHOLDS)
        thresholds.update(preset.thresholds)
        severities = dict(BASE_SEVERITIES)
        severities.update(preset.severities)
        return cls(preset.name, thresholds, severities)


# ---------------------------------------------------------------------------
# What the user chose
# ---------------------------------------------------------------------------


@dataclass
class Mute:
    """A finding the user has told us to stop counting."""

    finding_id: str
    reason: str = ""
    muted_at: str = ""

    def to_dict(self) -> dict:
        return {"reason": self.reason, "muted_at": self.muted_at}


class Profile:
    """The user's Boot Analyzer settings, persisted as JSON.

    Stored separately from ``settings.json`` because it is a different kind of
    thing — a security policy with dozens of small knobs, which someone might
    reasonably want to copy between machines or keep in configuration
    management. One file, one purpose, easy to diff.
    """

    def __init__(self, path=None) -> None:
        self.path = path or (paths.CONFIG_DIR / PROFILE_FILE)
        self.preset: str = DEFAULT_PRESET
        self.disabled_checks: set[str] = set()
        self.severity_overrides: dict[str, Severity] = {}
        self.policy_overrides: dict[str, Severity] = {}
        self.threshold_overrides: dict[str, float] = {}
        self.mutes: dict[str, Mute] = {}
        #: Show PASS findings in the list by default.
        self.show_passes: bool = False
        #: Start in savvy mode — evidence and commands expanded.
        self.savvy_mode: bool = False
        self.load()

    # -- persistence ------------------------------------------------------

    def load(self) -> None:
        """Re-read from disk. A broken file is logged, not fatal."""
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("cannot read the boot profile (%s); using defaults", exc)
            return
        if not isinstance(data, dict):
            log.warning("the boot profile is not a JSON object; ignoring it")
            return

        self.preset = str(data.get("preset", DEFAULT_PRESET))
        if self.preset not in PRESETS:
            self.preset = DEFAULT_PRESET
        self.disabled_checks = {str(item) for item in data.get("disabled_checks", [])}
        self.show_passes = bool(data.get("show_passes", False))
        self.savvy_mode = bool(data.get("savvy_mode", False))

        self.severity_overrides = _read_severities(data.get("severity_overrides"))
        self.policy_overrides = _read_severities(data.get("policy_overrides"),
                                                 known=set(BASE_SEVERITIES))
        self.threshold_overrides = _read_thresholds(data.get("threshold_overrides"))

        self.mutes = {}
        for finding_id, value in (data.get("muted") or {}).items():
            if isinstance(value, dict):
                self.mutes[str(finding_id)] = Mute(
                    str(finding_id), str(value.get("reason", "")),
                    str(value.get("muted_at", "")))
            else:
                self.mutes[str(finding_id)] = Mute(str(finding_id), str(value))

    def save(self) -> None:
        """Write atomically. Called after every change the UI makes."""
        payload = {
            "preset": self.preset,
            "disabled_checks": sorted(self.disabled_checks),
            "severity_overrides": {key: value.label.lower()
                                   for key, value in sorted(self.severity_overrides.items())},
            "policy_overrides": {key: value.label.lower()
                                 for key, value in sorted(self.policy_overrides.items())},
            "threshold_overrides": dict(sorted(self.threshold_overrides.items())),
            "muted": {key: value.to_dict() for key, value in sorted(self.mutes.items())},
            "show_passes": self.show_passes,
            "savvy_mode": self.savvy_mode,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(".json.tmp")
            temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            temporary.replace(self.path)
        except OSError as exc:
            log.error("cannot save the boot profile to %s: %s", self.path, exc)

    def reset(self) -> None:
        """Back to defaults, including the mute list."""
        self.preset = DEFAULT_PRESET
        self.disabled_checks.clear()
        self.severity_overrides.clear()
        self.policy_overrides.clear()
        self.threshold_overrides.clear()
        self.mutes.clear()
        self.show_passes = False
        self.save()

    # -- editing ----------------------------------------------------------

    def set_preset(self, name: str) -> None:
        if name in PRESETS and name != self.preset:
            self.preset = name
            self.save()

    def enable_check(self, check_id: str, enabled: bool) -> None:
        if enabled:
            self.disabled_checks.discard(check_id)
        else:
            self.disabled_checks.add(check_id)
        self.save()

    def is_enabled(self, check_id: str) -> bool:
        return check_id not in self.disabled_checks

    def mute(self, finding_id: str, reason: str = "") -> None:
        self.mutes[finding_id] = Mute(
            finding_id, reason, datetime.now().isoformat(timespec="seconds"))
        self.save()

    def unmute(self, finding_id: str) -> None:
        if self.mutes.pop(finding_id, None) is not None:
            self.save()

    def is_muted(self, finding_id: str) -> bool:
        return finding_id in self.mutes

    def override_severity(self, finding_id: str, severity: Severity | None) -> None:
        """Pin one finding's severity, or clear the pin with None."""
        if severity is None:
            self.severity_overrides.pop(finding_id, None)
        else:
            self.severity_overrides[finding_id] = severity
        self.save()

    def override_policy(self, key: str, severity: Severity | None) -> None:
        """Change what a whole class of condition is worth."""
        if key not in BASE_SEVERITIES:
            raise KeyError(f"no such policy: {key!r}")
        if severity is None:
            self.policy_overrides.pop(key, None)
        else:
            self.policy_overrides[key] = severity
        self.save()

    def override_threshold(self, key: str, value: float | None) -> None:
        if key not in BASE_THRESHOLDS:
            raise KeyError(f"no such threshold: {key!r}")
        if value is None:
            self.threshold_overrides.pop(key, None)
        else:
            self.threshold_overrides[key] = float(value)
        self.save()

    @property
    def customised(self) -> bool:
        """True when anything has been changed from the stock balanced profile."""
        return bool(
            self.preset != DEFAULT_PRESET or self.disabled_checks
            or self.severity_overrides or self.policy_overrides
            or self.threshold_overrides or self.mutes
        )

    def summary(self) -> str:
        """One line for the header: what this profile does differently."""
        parts = [PRESETS[self.preset].title]
        if self.disabled_checks:
            parts.append(f"{len(self.disabled_checks)} check"
                         f"{'' if len(self.disabled_checks) == 1 else 's'} off")
        if self.mutes:
            parts.append(f"{len(self.mutes)} muted")
        tuned = len(self.policy_overrides) + len(self.threshold_overrides) \
            + len(self.severity_overrides)
        if tuned:
            parts.append(f"{tuned} tuned")
        return " · ".join(parts)

    # -- what the run uses ------------------------------------------------

    def policy(self) -> Policy:
        """The frozen view handed to every check."""
        base = Policy.for_preset(self.preset)
        thresholds = dict(base.thresholds)
        thresholds.update(self.threshold_overrides)
        severities = dict(base.severities)
        severities.update(self.policy_overrides)
        return Policy(self.preset, thresholds, severities)

    def apply_to(self, finding: Finding) -> Finding:
        """Overlay the user's per-finding decisions onto one result."""
        override = self.severity_overrides.get(finding.id)
        if override is not None:
            finding = finding.with_severity(override)
        mute = self.mutes.get(finding.id)
        if mute is not None:
            finding = finding.muted_as(mute.reason)
        return finding


def _read_severities(raw: Any, known: set[str] | None = None) -> dict[str, Severity]:
    if not isinstance(raw, dict):
        return {}
    parsed: dict[str, Severity] = {}
    for key, value in raw.items():
        if known is not None and key not in known:
            log.warning("boot profile mentions an unknown policy %r; ignoring it", key)
            continue
        parsed[str(key)] = Severity.parse(str(value), Severity.INFO)
    return parsed


def _read_thresholds(raw: Any) -> dict[str, float]:
    if not isinstance(raw, dict):
        return {}
    parsed: dict[str, float] = {}
    for key, value in raw.items():
        if key not in BASE_THRESHOLDS:
            log.warning("boot profile mentions an unknown threshold %r; ignoring it", key)
            continue
        try:
            parsed[str(key)] = float(value)
        except (TypeError, ValueError):
            log.warning("boot profile threshold %r is not a number; ignoring it", key)
    return parsed
