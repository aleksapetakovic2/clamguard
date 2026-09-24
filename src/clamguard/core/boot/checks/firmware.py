"""What the firmware verifies before the kernel exists.

This is the first link in the chain. If the firmware will load any bootloader
handed to it, nothing further down can make up for that: a bootkit installed
here runs before the kernel, before any antivirus, and before anything that
could notice it.

Everything is read from ``/sys/firmware/efi`` and from ``bootctl`` /
``efibootmgr``, all of which answer without privilege. Nothing here writes an
EFI variable — that is a genuinely dangerous operation and it belongs in the
firmware's own setup menu, not in an antivirus.
"""

from __future__ import annotations

from typing import Iterator

from ..model import Category, Evidence, Finding, Fix, Reference, Severity
from ..probe import Probe
from ..profile import Policy
from ..registry import SkipCheck, check, finding, get, passed

EFIVARS = "/sys/firmware/efi/efivars"

#: The EFI global variable namespace, and the image-security one. These GUIDs
#: are fixed by the UEFI specification, not by the vendor.
GLOBAL_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
SECURITY_GUID = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"

UEFI_SPEC = Reference("UEFI specification, Secure Boot",
                      "https://uefi.org/specifications")


# ---------------------------------------------------------------------------
# Shared readers
# ---------------------------------------------------------------------------


def is_uefi(probe: Probe) -> bool:
    return probe.exists("/sys/firmware/efi")


def efi_variable(probe: Probe, name: str, guid: str = GLOBAL_GUID) -> bytes | None:
    """The value of an EFI variable, with its four attribute bytes removed."""
    data = probe.read_bytes(f"{EFIVARS}/{name}-{guid}")
    if data is None or len(data) < 5:
        return None
    return data[4:]


def bootctl_fields(probe: Probe) -> dict[str, str]:
    """``bootctl status`` as a mapping of its ``Label: value`` lines.

    ``bootctl`` exits non-zero when it cannot read the ESP — which is normal
    for an unprivileged user on a 0700 mount — while still printing the
    firmware summary we want, so its exit code is deliberately ignored.
    """
    result = probe.run("bootctl", "status")
    fields: dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        if ":" not in line:
            continue
        label, _, value = line.partition(":")
        label = label.strip()
        value = value.strip()
        # Only the summary block uses "Label: value"; the feature lists use
        # tick marks and would otherwise overwrite real entries with noise.
        if label and value and not label.startswith(("✓", "✗", "-")):
            fields.setdefault(label, value)
    return fields


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


@check(
    "firmware.boot-mode",
    title="UEFI or legacy BIOS",
    category=Category.FIRMWARE,
    inspects="Whether /sys/firmware/efi exists.",
    worst=Severity.MEDIUM,
    tags=("firmware", "secure-boot"),
)
def boot_mode(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Legacy BIOS boot rules out every verification feature below."""
    item = get("firmware.boot-mode")
    if is_uefi(probe):
        yield passed(
            item, "uefi", "The machine boots in UEFI mode",
            "Secure Boot and measured boot are possible on this machine, "
            "whether or not they are turned on.",
            value="UEFI",
            evidence=(Evidence("/sys/firmware/efi", "present", kind="sysfs"),),
        )
        return

    yield finding(
        item, "legacy", policy.severity("no_uefi"),
        "This machine boots in legacy BIOS mode",
        "There is no /sys/firmware/efi, so the firmware started the bootloader "
        "the old way. Legacy boot has no signature verification at all: the "
        "firmware runs whatever is in the master boot record.",
        impact="Secure Boot, measured boot and TPM-sealed disk keys cannot be "
               "used. Anything that can write to the boot sector runs before "
               "the kernel.",
        value="legacy BIOS",
        expected="UEFI",
        evidence=(Evidence("/sys/firmware/efi", "not present", kind="sysfs"),),
        fixes=(Fix(
            title="Reinstall with UEFI firmware settings",
            explanation=(
                "Switching a system that was installed in legacy mode over to "
                "UEFI means repartitioning for an EFI system partition and "
                "reinstalling the bootloader. It is not a setting you can flip."
            ),
            manual="Firmware setup → Boot → change CSM/Legacy to UEFI, then "
                   "reinstall the bootloader.",
            risk="Done wrong, the machine will not boot. Have installation "
                 "media to hand before starting.",
        ),),
        tags=frozenset({"firmware"}),
    )


@check(
    "firmware.secure-boot",
    title="Secure Boot",
    category=Category.FIRMWARE,
    inspects="The SecureBoot and SetupMode EFI variables, and bootctl status.",
    worst=Severity.CRITICAL,
    tags=("firmware", "secure-boot"),
)
def secure_boot(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Is the firmware checking the bootloader's signature, and whose keys?"""
    item = get("firmware.secure-boot")
    if not is_uefi(probe):
        raise SkipCheck("this machine does not boot with UEFI firmware")

    raw = efi_variable(probe, "SecureBoot")
    fields = bootctl_fields(probe)
    reported = fields.get("Secure Boot", "")

    if raw is None and not reported:
        yield finding(
            item, "unknown", Severity.INFO,
            "Secure Boot state could not be read",
            "Neither the SecureBoot EFI variable nor bootctl would say. On some "
            "firmware the variable is only exposed while efivarfs is mounted "
            "read-write.",
            value="unknown",
            evidence=(Evidence(f"{EFIVARS}/SecureBoot-{GLOBAL_GUID}",
                               "unreadable", kind="sysfs"),),
            fixes=(Fix("Ask the firmware directly",
                       "mokutil reports the same state through a different path.",
                       command="mokutil --sb-state"),),
        )
        return

    enabled = bool(raw and raw[0] == 1) or reported.startswith("enabled")
    setup_mode = bool((efi_variable(probe, "SetupMode") or b"\x00")[0] == 1)

    evidence = (
        Evidence(f"{EFIVARS}/SecureBoot-{GLOBAL_GUID}",
                 f"value = {raw[0] if raw else '?'}  (1 = enabled, 0 = disabled)",
                 kind="sysfs"),
        Evidence("bootctl status",
                 "\n".join(f"{key}: {value}" for key, value in fields.items()
                           if key in ("Secure Boot", "TPM2 Support", "Measured UKI",
                                      "Measured OS", "Product")) or "no summary",
                 kind="command"),
    )

    if setup_mode:
        yield finding(
            item, "setup-mode", policy.severity("secure_boot_setup_mode"),
            "The firmware is in Secure Boot setup mode",
            "SetupMode is 1, which means the platform key has been cleared. In "
            "this state anything running with enough privilege can enrol its "
            "own keys and then sign whatever it likes.",
            impact="An attacker who reaches root once can enrol their own "
                   "Secure Boot key, sign a bootkit, and from then on the "
                   "firmware will vouch for it.",
            value="setup mode",
            expected="user mode, with a platform key enrolled",
            evidence=evidence,
            fixes=(Fix(
                title="Restore the factory keys in firmware setup",
                explanation="Most firmware has a 'Restore factory keys' or "
                            "'Install default Secure Boot keys' button, which "
                            "leaves setup mode and re-enrols Microsoft's keys.",
                manual="Firmware setup → Security → Secure Boot → Restore "
                       "factory keys.",
                recommended=True,
            ),),
            references=(UEFI_SPEC,),
            tags=frozenset({"firmware", "secure-boot"}),
        )
        return

    if enabled:
        yield passed(
            item, "enabled", "Secure Boot is on",
            "The firmware verifies the signature on the bootloader before "
            "running it.",
            value=reported or "enabled",
            evidence=evidence,
        )
        return

    yield finding(
        item, "disabled", policy.severity("secure_boot_off"),
        "Secure Boot is off",
        "The firmware will run any bootloader it finds, signed or not. Nothing "
        "checks what starts before the kernel does.",
        impact=(
            "A bootkit written to the EFI system partition runs before the "
            "kernel and before ClamGuard. Nothing in userspace can reliably "
            "detect code that loaded first."
        ),
        value="disabled",
        expected="enabled",
        evidence=evidence,
        fixes=(
            Fix(
                title="Turn Secure Boot on in firmware setup",
                explanation=(
                    "Only the firmware can change this; there is no command "
                    "for it. Reboot, enter setup, and enable Secure Boot."
                ),
                manual="Reboot → firmware setup (usually Del, F2 or F12) → "
                       "Security or Boot → Secure Boot → Enabled.",
                risk=(
                    "If your kernel or its modules are not signed by a key the "
                    "firmware trusts — which is the case for out-of-tree "
                    "drivers such as NVIDIA's on many distributions — the "
                    "machine will refuse to boot or will lose those drivers. "
                    "Check that your distribution ships a signed kernel first."
                ),
                reboot_required=True,
                recommended=True,
            ),
            Fix(
                title="Check what your distribution signs, first",
                explanation="Lists the keys the firmware currently trusts, "
                            "which tells you whether your kernel would pass.",
                command="mokutil --list-enrolled | head -40",
            ),
        ),
        references=(UEFI_SPEC,),
        tags=frozenset({"firmware", "secure-boot"}),
    )


@check(
    "firmware.revocation",
    title="Revoked signature list (dbx)",
    category=Category.FIRMWARE,
    inspects="The size of the dbx EFI variable.",
    worst=Severity.HIGH,
    tags=("firmware", "secure-boot"),
)
def revocation_list(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """An empty dbx means known-broken signed bootloaders still pass."""
    item = get("firmware.revocation")
    if not is_uefi(probe):
        raise SkipCheck("this machine does not boot with UEFI firmware")

    raw = efi_variable(probe, "SecureBoot")
    if not (raw and raw[0] == 1):
        raise SkipCheck("Secure Boot is off, so the revocation list has no effect")

    dbx = efi_variable(probe, "dbx", SECURITY_GUID)
    size = len(dbx) if dbx is not None else 0
    evidence = (Evidence(f"{EFIVARS}/dbx-{SECURITY_GUID}",
                         f"{size} bytes", kind="sysfs"),)

    # A populated dbx from any of the last few Microsoft updates is several
    # kilobytes. Anything under one is either absent or a stub.
    if size >= 1024:
        yield passed(
            item, "present", "The firmware has a revocation list",
            f"dbx holds {size} bytes of revoked signatures, so bootloaders "
            "known to be vulnerable are refused even though they are signed.",
            value=f"{size} bytes", evidence=evidence,
        )
        return

    yield finding(
        item, "empty", policy.severity("no_dbx"),
        "The firmware's revocation list is empty or tiny",
        "dbx is the list of signatures Secure Boot should refuse even though "
        "they are valid. Several widely distributed bootloaders have had holes "
        "that let them load unsigned code; revoking them is how that is fixed.",
        impact="Secure Boot is on, but a known-vulnerable signed bootloader "
               "would still be accepted, which defeats the point of it.",
        value=f"{size} bytes",
        expected="several kilobytes",
        evidence=evidence,
        fixes=(
            Fix(
                title="Apply firmware updates through fwupd",
                explanation="Vendors ship dbx updates as firmware updates. "
                            "fwupd applies them without a Windows install.",
                command="fwupdmgr refresh && fwupdmgr get-updates",
                risk="Read what it proposes before applying. A dbx update that "
                     "revokes the bootloader you are currently using will stop "
                     "the machine booting until you update that too.",
                recommended=True,
            ),
        ),
        references=(Reference("UEFI revocation list file",
                              "https://uefi.org/revocationlistfile"),),
        tags=frozenset({"firmware", "secure-boot"}),
    )


@check(
    "firmware.tpm",
    title="TPM and measured boot",
    category=Category.FIRMWARE,
    inspects="/sys/class/tpm, its PCR registers, and bootctl's measurement summary.",
    worst=Severity.HIGH,
    tags=("firmware", "tpm"),
)
def trusted_platform_module(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """A TPM is what makes "has this machine changed?" answerable at all."""
    item = get("firmware.tpm")
    devices = [name for name in probe.listdir("/sys/class/tpm") if name.startswith("tpm")]

    if not devices:
        yield finding(
            item, "absent", policy.severity("no_tpm"),
            "No TPM is available",
            "Nothing under /sys/class/tpm. Either the machine has no TPM or it "
            "is switched off in firmware setup — on AMD systems it is called "
            "fTPM or PSP, on Intel, PTT.",
            impact="Without a TPM the boot chain cannot be measured, so there "
                   "is no way to tell afterwards whether something changed. "
                   "Disk keys also cannot be sealed to the machine's state.",
            value="none",
            expected="TPM 2.0",
            evidence=(Evidence("/sys/class/tpm", "empty", kind="sysfs"),),
            fixes=(Fix(
                title="Enable the firmware TPM",
                explanation="Most machines from the last decade have one but "
                            "ship with it off.",
                manual="Firmware setup → Security → fTPM / PTT / TPM Device → "
                       "Enabled.",
                risk="If you already use disk encryption with a TPM-sealed key "
                     "on another OS, changing this can invalidate it. Have your "
                     "recovery key ready.",
                reboot_required=True,
            ),),
            tags=frozenset({"firmware", "tpm"}),
        )
        return

    device = devices[0]
    major = probe.value(f"/sys/class/tpm/{device}/tpm_version_major") or "1"
    fields = bootctl_fields(probe)
    pcr_names = probe.listdir(f"/sys/class/tpm/{device}/pcr-sha256")
    measured = [key for key in ("Measured UKI", "Measured OS")
                if fields.get(key, "no").startswith("yes")]

    evidence = (
        Evidence(f"/sys/class/tpm/{device}/tpm_version_major", major, kind="sysfs"),
        Evidence(f"/sys/class/tpm/{device}/pcr-sha256",
                 f"{len(pcr_names)} PCR registers readable", kind="sysfs"),
        Evidence("bootctl status",
                 "\n".join(f"{key}: {fields.get(key, 'n/a')}"
                           for key in ("TPM2 Support", "Measured UKI", "Measured OS")),
                 kind="command"),
    )

    if major.strip() != "2":
        yield finding(
            item, "old", policy.severity("no_tpm"),
            f"This machine has a TPM {major}.x, not a TPM 2.0",
            "TPM 1.2 uses SHA-1 and is not supported by current disk "
            "encryption tooling.",
            impact="Measured boot and sealed keys are effectively unavailable.",
            value=f"TPM {major}.x", expected="TPM 2.0", evidence=evidence,
            tags=frozenset({"firmware", "tpm"}),
        )
        return

    if not measured:
        yield finding(
            item, "not-measured", policy.severity("no_measured_boot"),
            "A TPM 2.0 is present but the boot is not measured",
            "The hardware is there and its registers can be read, but nothing "
            "in this boot path records what it loaded into the TPM in a way "
            "systemd recognises. That is normal with GRUB and a separate "
            "initramfs; unified kernel images are what usually change it.",
            impact="You cannot ask the machine 'has my boot chain changed since "
                   "yesterday?' and get a trustworthy answer. ClamGuard's own "
                   "baseline comparison is a weaker substitute that checks "
                   "files rather than what actually ran.",
            value="present, not measuring",
            expected="measured boot",
            evidence=evidence,
            fixes=(Fix(
                title="Record a ClamGuard baseline instead",
                explanation=(
                    "Until the boot is measured, the practical alternative is "
                    "the Integrity tab here: record the hashes of everything in "
                    "/boot now and get told when they change."
                ),
                manual="Boot Analyzer → ⋯ → Record baseline.",
                recommended=True,
            ),),
            tags=frozenset({"firmware", "tpm"}),
        )
        return

    yield passed(
        item, "measured", "The boot chain is measured into a TPM 2.0",
        f"{', '.join(measured)} reported by bootctl, and "
        f"{len(pcr_names)} PCR registers are readable.",
        value="TPM 2.0, measured", evidence=evidence,
    )


@check(
    "firmware.boot-entries",
    title="EFI boot entries",
    category=Category.FIRMWARE,
    inspects="efibootmgr -v: the boot order, the current entry, and BootNext.",
    worst=Severity.MEDIUM,
    tags=("firmware",),
)
def boot_entries(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """What the firmware would boot next, and whether that is what you expect."""
    item = get("firmware.boot-entries")
    if not is_uefi(probe):
        raise SkipCheck("this machine does not boot with UEFI firmware")
    if not probe.available("efibootmgr"):
        raise SkipCheck("efibootmgr is not installed")

    result = probe.run("efibootmgr", "-v")
    if not result.ok:
        raise SkipCheck(f"efibootmgr could not read the boot entries: {result.output[:120]}")

    listing = result.stdout
    header = {}
    entries: dict[str, str] = {}
    for line in listing.splitlines():
        if line.startswith("Boot") and (line[4:8].isalnum() and len(line) > 8) \
                and line[8:9] in ("*", " "):
            entries[line[4:8]] = line[9:].strip()
        elif ":" in line:
            key, _, value = line.partition(":")
            header[key.strip()] = value.strip()

    order = [code.strip() for code in header.get("BootOrder", "").split(",") if code.strip()]
    current = header.get("BootCurrent", "")
    next_boot = header.get("BootNext", "")
    evidence = (Evidence("efibootmgr -v", listing.strip(), kind="command"),)

    if next_boot:
        yield finding(
            item, "bootnext", Severity.LOW,
            "A one-shot boot entry is queued",
            f"BootNext is set to {next_boot}"
            + (f" ({entries.get(next_boot, 'unknown entry')})" if next_boot in entries else "")
            + ". The next restart will use that entry once and then go back to "
            "the normal order.",
            impact="Usually this was set deliberately — by a firmware update "
                   "tool, or by `systemctl reboot --boot-loader-entry`. If you "
                   "did not set it, something else did.",
            value=next_boot, evidence=evidence,
            fixes=(Fix("Clear the one-shot entry",
                       "Removes BootNext so the next boot follows BootOrder.",
                       command="sudo efibootmgr --delete-bootnext"),),
            tags=frozenset({"firmware"}),
        )

    first = order[0] if order else ""
    first_label = entries.get(first, "")
    if first and _looks_removable(first_label):
        yield finding(
            item, "removable-first", policy.severity("boot_order_unexpected"),
            "The firmware tries removable media before the installed system",
            f"The first entry in BootOrder is {first} — {first_label}. Anything "
            "plugged into a USB port at power-on gets to run before the "
            "installed bootloader does.",
            impact="Someone with physical access and a USB stick does not even "
                   "need to enter the boot menu.",
            value=first_label or first,
            evidence=evidence,
            fixes=(Fix(
                title="Put the installed system first",
                explanation="Reorders the firmware's boot list. Replace the "
                            "codes with your own order from the evidence above.",
                command=f"sudo efibootmgr --bootorder {current or 'XXXX'}"
                        + ("," + ",".join(code for code in order if code != current)
                           if order else ""),
                risk="Getting the order wrong can leave the machine booting to "
                     "the firmware menu. It is recoverable from that menu.",
            ),),
            tags=frozenset({"firmware"}),
        )
    elif current and order and current != order[0]:
        yield finding(
            item, "unexpected-current", Severity.INFO,
            "This boot did not use the first entry in the boot order",
            f"BootCurrent is {current} ({entries.get(current, 'unknown')}) but "
            f"BootOrder starts with {order[0]} ({entries.get(order[0], 'unknown')}). "
            "That happens when you pick an entry from the firmware menu, or "
            "when the first entry failed and the firmware fell through to the "
            "next one.",
            value=entries.get(current, current), evidence=evidence,
            tags=frozenset({"firmware"}),
        )
    else:
        yield passed(
            item, "order", "The boot order is what it looks like",
            f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}; this boot "
            f"used {entries.get(current, current) or 'the default'}.",
            value=entries.get(current, current), evidence=evidence,
        )


def _looks_removable(label: str) -> bool:
    lowered = label.lower()
    return any(word in lowered for word in
               ("usb", "removable", "cd/dvd", "cdrom", "pxe", "network", "ipv4", "ipv6"))


@check(
    "firmware.esp",
    title="EFI system partition permissions",
    category=Category.FIRMWARE,
    inspects="The mount options and directory mode of the EFI system partition.",
    worst=Severity.CRITICAL,
    tags=("firmware", "permissions"),
)
def esp_permissions(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """A writable ESP is a writable bootloader."""
    item = get("firmware.esp")
    if not is_uefi(probe):
        raise SkipCheck("this machine does not boot with UEFI firmware")

    mount = None
    for candidate in ("/efi", "/boot/efi", "/boot"):
        entry = probe.mount_for(candidate)
        if entry and entry["fstype"] in ("vfat", "msdos", "fat", "exfat"):
            mount = entry
            break
    if mount is None:
        raise SkipCheck("no FAT filesystem is mounted at /efi, /boot/efi or /boot")

    target = mount["target"]
    info = probe.stat(target)
    mode = info.st_mode & 0o7777 if info else 0
    options = mount["options"]
    evidence = (
        Evidence("/proc/self/mountinfo",
                 f"{target}  {mount['source']}  {mount['fstype']}  {options}"),
        Evidence(f"stat {target}", f"mode {mode:04o}", kind="computed"),
    )

    if mode & 0o002:
        yield finding(
            item, "world-writable", policy.at_least("esp_permissions", Severity.CRITICAL),
            "The EFI system partition is writable by everyone",
            f"{target} is mounted mode {mode:04o}. Any user on this machine can "
            "replace the bootloader.",
            impact="This is a direct route from an unprivileged account to code "
                   "that runs before the kernel. Nothing else on this page "
                   "matters more.",
            value=f"{mode:04o}", expected="0700",
            evidence=evidence,
            fixes=(Fix(
                title="Mount it with a restrictive umask",
                explanation="FAT has no permissions of its own, so the mount "
                            "options decide. umask=0077 gives root-only access.",
                command=f"# add umask=0077 to the {target} line in /etc/fstab, then\n"
                        f"sudo mount -o remount,umask=0077 {target}",
                recommended=True,
            ),),
            tags=frozenset({"firmware", "permissions"}),
        )
    elif mode & 0o077:
        yield finding(
            item, "readable", Severity.INFO,
            "The EFI system partition is readable by everyone",
            f"{target} is mounted mode {mode:04o}. Its contents are public "
            "anyway — a bootloader is not a secret — so this is a tidiness "
            "point rather than a hole. It becomes one if the mode ever grows a "
            "write bit.",
            value=f"{mode:04o}", expected="0700",
            evidence=evidence,
            fixes=(Fix(
                title="Restrict it to root",
                explanation="Matches what systemd-boot's own tooling expects.",
                command=f"# add umask=0077 to the {target} line in /etc/fstab, then\n"
                        f"sudo mount -o remount,umask=0077 {target}",
            ),),
            tags=frozenset({"firmware", "permissions"}),
        )
    else:
        yield passed(
            item, "restricted", "The EFI system partition is root-only",
            f"{target} is mounted mode {mode:04o}, so only root can read or "
            "change the bootloader.",
            value=f"{mode:04o}", evidence=evidence,
        )
