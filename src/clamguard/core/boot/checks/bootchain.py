"""The files and disks the machine boots from.

Between the firmware handing over and the kernel taking control there is a
bootloader, a kernel image and usually an initramfs, all sitting in an ordinary
directory. Whoever can write to that directory decides what the machine runs,
and does so before any of the protections on the other tabs exist.

Several of these files are root-only on a sensible system, which means
ClamGuard — which never runs as root — cannot read them. Where that happens the
check says so and gives the command that would answer the question, rather than
guessing or staying quiet.
"""

from __future__ import annotations

import os
import time
from typing import Iterator

from ..model import Category, Evidence, Finding, Fix, Reference, Severity
from ..probe import Probe
from ..profile import Policy
from ..registry import SkipCheck, check, finding, get, passed
from .common import describe_mode, listing, octal, plural

#: Where kernels and bootloaders live, in the order distributions prefer.
BOOT_DIR = "/boot"

#: Walking /boot is bounded: a machine with hundreds of stale kernels should
#: not turn a security check into a disk-bound crawl.
MAX_BOOT_ENTRIES = 4000


# ---------------------------------------------------------------------------
# Which bootloader
# ---------------------------------------------------------------------------


def detect_bootloader(probe: Probe) -> tuple[str, str]:
    """``("GRUB", "/boot/grub/grub.cfg")`` — the name and its main config."""
    for path, name in (
        ("/boot/grub/grub.cfg", "GRUB"),
        ("/boot/grub2/grub.cfg", "GRUB"),
        ("/boot/efi/EFI/grub/grub.cfg", "GRUB"),
        ("/boot/loader/loader.conf", "systemd-boot"),
        ("/efi/loader/loader.conf", "systemd-boot"),
        ("/boot/refind_linux.conf", "rEFInd"),
        ("/boot/syslinux/syslinux.cfg", "syslinux"),
        ("/boot/extlinux/extlinux.conf", "extlinux"),
    ):
        if probe.exists(path):
            return name, path
    if probe.is_dir("/boot/loader/entries") or probe.is_dir("/efi/loader/entries"):
        return "systemd-boot", "/boot/loader/entries"
    return "", ""


@check(
    "bootchain.bootloader",
    title="Bootloader",
    category=Category.BOOTCHAIN,
    inspects="Which bootloader configuration exists in /boot, plus bootctl status.",
    worst=Severity.LOW,
    tags=("bootchain",),
)
def bootloader(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Identify the bootloader. Mostly context for everything below it."""
    item = get("bootchain.bootloader")
    name, config = detect_bootloader(probe)
    from .firmware import bootctl_fields

    product = bootctl_fields(probe).get("Product", "")

    if not name and not product:
        yield finding(
            item, "unknown", Severity.INFO,
            "The bootloader could not be identified",
            "None of the usual configuration files are in /boot. That is "
            "normal if /boot is not mounted right now, or if this machine uses "
            "a unified kernel image or boots over the network.",
            value="unknown",
            evidence=(Evidence("/boot", ", ".join(probe.listdir("/boot")) or "empty"),),
            tags=frozenset({"bootchain"}),
        )
        return

    yield passed(
        item, "detected", f"Booted by {product or name}",
        f"Configuration at {config}." if config else "",
        value=product or name,
        evidence=(
            Evidence(config or "/boot",
                     f"{name or 'unknown'} configuration present" if config
                     else ", ".join(probe.listdir("/boot"))),
            Evidence("bootctl status", product or "not reported", kind="command"),
        ),
    )


@check(
    "bootchain.grub-password",
    title="GRUB menu password",
    category=Category.BOOTCHAIN,
    inspects="/etc/grub.d and /etc/default/grub for a superusers/password_pbkdf2 setting.",
    worst=Severity.MEDIUM,
    tags=("bootchain", "physical"),
)
def grub_password(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Without a menu password, anyone at the keyboard can edit the cmdline."""
    item = get("bootchain.grub-password")
    name, config = detect_bootloader(probe)
    if name != "GRUB":
        raise SkipCheck("this machine does not use GRUB")

    sources = ["/etc/default/grub", config]
    sources += probe.files_in("/etc/grub.d")
    readable, unreadable = [], []
    protected = False
    for path in sources:
        if not path:
            continue
        result = probe.file(path)
        if result.ok:
            readable.append(path)
            if "password_pbkdf2" in result.text or "superusers" in result.text:
                protected = True
        elif result.exists:
            unreadable.append(path)

    evidence = (
        Evidence("grep -l 'password_pbkdf2\\|superusers' /etc/default/grub "
                 "/etc/grub.d/* " + (config or ""),
                 "found" if protected else "not found in "
                 f"{plural(len(readable), 'readable file')}"
                 + (f"; {plural(len(unreadable), 'file')} were root-only"
                    if unreadable else ""),
                 kind="computed"),
    )

    if protected:
        yield passed(
            item, "set", "The GRUB menu is password-protected",
            "Editing a boot entry or opening the GRUB shell needs a password, "
            "so someone at the keyboard cannot simply add init=/bin/sh.",
            value="protected", evidence=evidence,
        )
        return

    if unreadable and not readable:
        yield finding(
            item, "unknown", Severity.INFO,
            "Whether GRUB has a menu password could not be checked",
            "The GRUB configuration is readable only by root, which is the "
            "right permission for it. ClamGuard does not run as root, so it "
            "cannot look.",
            value="unknown",
            evidence=evidence,
            fixes=(Fix(
                title="Check it yourself",
                explanation="Prints nothing if no password is configured.",
                command="sudo grep -r 'password_pbkdf2\\|superusers' "
                        "/etc/grub.d/ /etc/default/grub /boot/grub/grub.cfg",
            ),),
            tags=frozenset({"bootchain"}),
        )
        return

    yield finding(
        item, "unset", policy.severity("grub_no_password"),
        "The GRUB menu has no password",
        "Anyone who can reach the keyboard during boot can press `e`, add "
        "`init=/bin/sh` to the kernel line, and get a root shell without a "
        "password. No exploit involved — it is a documented GRUB feature.",
        impact=(
            "This only matters where someone can physically reach the machine. "
            "On a desktop in a locked room it is close to irrelevant; on a "
            "laptop or a machine in a shared space it means full-disk "
            "encryption is the only thing between a stranger and your files."
        ),
        value="none",
        expected="a superuser and password set",
        evidence=evidence,
        fixes=(Fix(
            title="Set a GRUB superuser password",
            explanation=(
                "grub-mkpasswd-pbkdf2 prints a hash; put it and a superusers "
                "line in /etc/grub.d/40_custom, then regenerate grub.cfg. The "
                "password is asked for only when editing an entry, not on a "
                "normal boot, if you mark the entries --unrestricted."
            ),
            command="grub-mkpasswd-pbkdf2",
            risk="Forget the password and you cannot edit boot entries from "
                 "the menu any more. Keep a copy somewhere else.",
        ),),
        references=(Reference("GRUB manual: security",
                              "https://www.gnu.org/software/grub/manual/grub/"
                              "grub.html#Security"),),
        tags=frozenset({"bootchain", "physical"}),
    )


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


@check(
    "bootchain.permissions",
    title="Permissions under /boot",
    category=Category.BOOTCHAIN,
    inspects="The owner and mode of every file and directory under /boot.",
    worst=Severity.CRITICAL,
    tags=("bootchain", "permissions"),
    slow=True,
)
def boot_permissions(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Anything writable here is a way to replace the kernel."""
    item = get("bootchain.permissions")
    if not probe.is_dir(BOOT_DIR):
        raise SkipCheck("/boot is not a directory on this machine")

    writable: list[str] = []
    group_writable: list[str] = []
    not_root: list[str] = []
    examined = 0

    for path, info in _walk(probe, BOOT_DIR):
        examined += 1
        mode = info.st_mode & 0o7777
        if mode & 0o002:
            writable.append(f"{path}  {octal(mode)}")
        elif mode & 0o020 and info.st_gid != 0:
            group_writable.append(f"{path}  {octal(mode)}  group {info.st_gid}")
        if info.st_uid != 0:
            not_root.append(f"{path}  owner uid {info.st_uid}")

    summary = Evidence(
        f"walk {BOOT_DIR}",
        f"{examined} entries examined\n"
        f"{len(writable)} world-writable\n"
        f"{len(group_writable)} group-writable by a non-root group\n"
        f"{len(not_root)} not owned by root",
        kind="computed")

    if writable:
        yield finding(
            item, "world-writable",
            policy.at_least("boot_world_writable", Severity.CRITICAL),
            f"{plural(len(writable), 'file')} under /boot can be written by anyone",
            "Any user on this machine can replace these. They are loaded "
            "before the kernel starts or by the kernel itself.",
            impact=(
                "This is the shortest path from an unprivileged account to "
                "permanent, undetectable control of the machine. Replace a "
                "kernel or an initramfs and every protection on every other tab "
                "is bypassed at the next boot."
            ),
            value=plural(len(writable), "file"),
            expected="0644 or stricter, owned by root",
            evidence=(Evidence("world-writable entries",
                               "\n".join(writable[:20]), kind="computed"), summary),
            fixes=(Fix(
                title="Take the write bit away",
                explanation="Nothing under /boot should be writable by anyone "
                            "but root.",
                command="sudo chmod -R go-w /boot && sudo chown -R root:root /boot",
                recommended=True,
            ),),
            tags=frozenset({"bootchain", "permissions"}),
        )

    if not_root:
        yield finding(
            item, "not-root-owned", policy.severity("boot_permissions"),
            f"{plural(len(not_root), 'entry', 'entries')} under /boot is not owned by root",
            "Files in /boot should belong to root. Something owned by another "
            "account can be changed by that account without any privilege.",
            impact="Whoever owns the file can change its permissions and then "
                   "its contents, which is the same outcome as the finding "
                   "above by a slightly longer route.",
            value=plural(len(not_root), "entry", "entries"),
            expected="root:root",
            evidence=(Evidence("non-root entries", "\n".join(not_root[:20]),
                               kind="computed"), summary),
            fixes=(Fix("Give them back to root", "",
                       command="sudo chown -R root:root /boot"),),
            tags=frozenset({"bootchain", "permissions"}),
        )

    if group_writable:
        yield finding(
            item, "group-writable", policy.severity("boot_permissions"),
            f"{plural(len(group_writable), 'entry', 'entries')} under /boot "
            "is writable by a non-root group",
            "Anyone in that group can change these files.",
            impact="Group membership is easier to obtain than root, and this "
                   "achieves the same thing.",
            value=plural(len(group_writable), "entry", "entries"),
            evidence=(Evidence("group-writable entries",
                               "\n".join(group_writable[:20]), kind="computed"),
                      summary),
            fixes=(Fix("Remove group write", "", command="sudo chmod -R g-w /boot"),),
            tags=frozenset({"bootchain", "permissions"}),
        )

    if not writable and not not_root and not group_writable:
        info = probe.stat(BOOT_DIR)
        yield passed(
            item, "clean", "Everything under /boot is root-owned and root-only writable",
            f"{examined} entries checked; /boot itself is "
            f"{octal(info.st_mode) if info else '????'} "
            f"({describe_mode(info.st_mode) if info else 'unknown'}).",
            value=f"{examined} entries", evidence=(summary,),
        )


def _walk(probe: Probe, root: str) -> Iterator[tuple[str, os.stat_result]]:
    """Every entry under `root`, bounded, without following symlinks out."""
    info = probe.stat(root)
    if info is not None:
        yield root, info
    seen = 0
    stack = [root]
    while stack and seen < MAX_BOOT_ENTRIES:
        current = stack.pop()
        for name in probe.listdir(current):
            path = os.path.join(current, name)
            entry = probe.stat(path)
            if entry is None:
                continue
            seen += 1
            yield path, entry
            # lstat, so a symlink is never descended into: /boot sometimes
            # contains one pointing at the ESP, and walking it twice would
            # double-report everything.
            if os.path.isdir(path) and not os.path.islink(path):
                stack.append(path)


# ---------------------------------------------------------------------------
# Kernels and initramfs images
# ---------------------------------------------------------------------------

_KERNEL_PREFIXES = ("vmlinuz", "vmlinux", "kernel-")


def _kernel_images(probe: Probe) -> list[str]:
    return [name for name in probe.listdir(BOOT_DIR)
            if name.startswith(_KERNEL_PREFIXES) and not name.endswith(".old")]


def _initramfs_for(probe: Probe, kernel_name: str) -> str:
    """The initramfs that goes with a kernel image, across naming conventions.

    Arch writes ``vmlinuz-linux`` / ``initramfs-linux.img``, Debian
    ``vmlinuz-6.1.0-13-amd64`` / ``initrd.img-6.1.0-13-amd64``, Fedora
    ``vmlinuz-6.5.6-200.fc38`` / ``initramfs-6.5.6-200.fc38.img``. All three
    are the kernel's name with the prefix swapped, so that is what is tried.
    """
    suffix = kernel_name.split("-", 1)[1] if "-" in kernel_name else ""
    candidates = [
        f"initramfs-{suffix}.img", f"initrd.img-{suffix}", f"initramfs-{suffix}",
        f"initrd-{suffix}.img", f"initrd-{suffix}",
    ] if suffix else ["initramfs.img", "initrd.img", "initrd"]
    for candidate in candidates:
        if probe.exists(os.path.join(BOOT_DIR, candidate)):
            return candidate
    return ""


@check(
    "bootchain.initramfs",
    title="Initramfs images",
    category=Category.BOOTCHAIN,
    inspects="Kernel images in /boot and the initramfs that goes with each one.",
    worst=Severity.HIGH,
    tags=("bootchain",),
)
def initramfs(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """An initramfs older than its kernel usually means a failed update hook."""
    item = get("bootchain.initramfs")
    kernels = _kernel_images(probe)
    if not kernels:
        raise SkipCheck("no kernel images were found in /boot")

    stale: list[str] = []
    missing: list[str] = []
    rows: list[str] = []
    stale_days = policy.threshold("initramfs_stale_days")

    for kernel in sorted(kernels):
        kernel_info = probe.stat(os.path.join(BOOT_DIR, kernel))
        image = _initramfs_for(probe, kernel)
        if not image:
            missing.append(kernel)
            rows.append(f"{kernel:<34} (no initramfs found)")
            continue
        image_info = probe.stat(os.path.join(BOOT_DIR, image))
        if kernel_info is None or image_info is None:
            continue
        behind_days = (kernel_info.st_mtime - image_info.st_mtime) / 86400
        rows.append(
            f"{kernel:<34} {time.strftime('%Y-%m-%d', time.localtime(kernel_info.st_mtime))}"
            f"   {image:<34} {time.strftime('%Y-%m-%d', time.localtime(image_info.st_mtime))}")
        if behind_days > stale_days:
            stale.append(f"{image} is {behind_days:.0f} days older than {kernel}")

    evidence = (Evidence("ls -l /boot", "\n".join(rows), kind="computed"),)

    if missing:
        yield finding(
            item, "missing", Severity.INFO,
            f"{plural(len(missing), 'kernel image')} has no matching initramfs",
            "No initramfs was found for " + listing(missing) + ". That is "
            "normal for a kernel with every needed driver built in, or for a "
            "unified kernel image where the initramfs is inside the file. It "
            "is a problem only if the machine cannot find its root filesystem.",
            value=listing(missing, limit=3),
            evidence=evidence,
            tags=frozenset({"bootchain"}),
        )

    if stale:
        yield finding(
            item, "stale", policy.severity("initramfs_stale"),
            "An initramfs is older than the kernel it belongs to",
            "\n".join(stale) + ". The initramfs is rebuilt by a package hook "
            "whenever the kernel changes; one that is older means the hook did "
            "not run or failed.",
            impact=(
                "The initramfs carries the microcode update and the modules "
                "needed to reach the root filesystem. A stale one can mean the "
                "microcode fix is not applied, or that the machine will not "
                "boot after the next change to its disks."
            ),
            value=plural(len(stale), "image"),
            expected="rebuilt with each kernel",
            evidence=evidence,
            fixes=(Fix(
                title="Rebuild the initramfs",
                explanation="The command differs by distribution; use the one "
                            "that matches yours.",
                command="# Debian/Ubuntu: sudo update-initramfs -u -k all\n"
                        "# Fedora/RHEL:   sudo dracut --force --regenerate-all\n"
                        "# Arch:          sudo mkinitcpio -P",
                recommended=True,
            ),),
            tags=frozenset({"bootchain"}),
        )

    if not stale and not missing:
        yield passed(
            item, "current", "Every kernel has an initramfs newer than itself",
            f"{plural(len(kernels), 'kernel image')} checked.",
            value=f"{len(kernels)} checked", evidence=evidence,
        )


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------


def _device_mapper_uuids(probe: Probe) -> dict[str, str]:
    """``{"/dev/mapper/root": "CRYPT-LUKS2-…"}`` from sysfs, without cryptsetup."""
    mapping: dict[str, str] = {}
    for device in probe.listdir("/sys/block"):
        if not device.startswith("dm-"):
            continue
        name = probe.value(f"/sys/block/{device}/dm/name")
        uuid = probe.value(f"/sys/block/{device}/dm/uuid")
        if name:
            mapping[f"/dev/mapper/{name}"] = uuid
            mapping[f"/dev/{device}"] = uuid
    return mapping


def _is_encrypted(probe: Probe, source: str) -> bool:
    uuid = _device_mapper_uuids(probe).get(source, "")
    return uuid.startswith("CRYPT-")


@check(
    "bootchain.encryption",
    title="Disk encryption",
    category=Category.BOOTCHAIN,
    inspects="/proc/self/mountinfo and the device-mapper UUIDs under /sys/block.",
    worst=Severity.HIGH,
    tags=("bootchain", "encryption"),
)
def disk_encryption(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Whether the data at rest is protected from someone holding the disk."""
    item = get("bootchain.encryption")
    root = probe.mount_for("/")
    if root is None:
        raise SkipCheck("the root filesystem could not be identified")

    mapper = _device_mapper_uuids(probe)
    root_encrypted = _is_encrypted(probe, root["source"])
    home = probe.mount_for("/home")
    home_encrypted = root_encrypted if home is None else _is_encrypted(probe, home["source"])

    table = "\n".join(
        f"{entry['target']:<20} {entry['source']:<28} {entry['fstype']:<8} "
        f"{mapper.get(entry['source'], '(not device-mapper)')}"
        for entry in probe.mounts()
        if entry["target"] in ("/", "/home", "/var") or entry["source"].startswith("/dev/"))
    evidence = (Evidence("/proc/self/mountinfo and /sys/block/*/dm/uuid", table,
                         kind="computed"),)

    if root_encrypted:
        yield passed(
            item, "root", "The root filesystem is encrypted",
            f"{root['source']} is a device-mapper crypt device, so the contents "
            "of this disk are not readable without the passphrase.",
            value="LUKS", evidence=evidence,
        )
    else:
        yield finding(
            item, "none", policy.severity("no_root_encryption"),
            "The root filesystem is not encrypted",
            f"{root['source']} is a plain {root['fstype']} filesystem. Anyone "
            "who can take the disk out, or boot the machine from a USB stick, "
            "can read and change everything on it.",
            impact=(
                "Encryption is the only defence against physical access. "
                "Without it, a stolen laptop is a copy of every file, and a "
                "few minutes alone with the machine is enough to add something "
                "to the boot chain that no antivirus running on top of it will "
                "ever see."
            ),
            value="plain " + root["fstype"],
            expected="LUKS",
            evidence=evidence,
            fixes=(Fix(
                title="Encrypt at the next reinstall",
                explanation=(
                    "Converting a live root filesystem in place is possible "
                    "with cryptsetup-reencrypt but is genuinely risky. Every "
                    "installer offers full-disk encryption as a checkbox; that "
                    "is the moment to take it."
                ),
                manual="Back up, reinstall, tick 'Encrypt the installation'.",
                risk="In-place conversion can lose the filesystem if it is "
                     "interrupted. Back up first, whichever route you take.",
            ),),
            tags=frozenset({"bootchain", "encryption"}),
        )

    if home is not None and root_encrypted and not home_encrypted:
        yield finding(
            item, "home-plain", policy.at_least("no_root_encryption", Severity.MEDIUM),
            "/home is on a separate, unencrypted filesystem",
            f"The root filesystem is encrypted but /home is {home['source']}, "
            "which is not. That is where the documents are.",
            impact="Encrypting the system and leaving the data in the clear is "
                   "the wrong way round.",
            value="plain " + home["fstype"],
            evidence=evidence,
            tags=frozenset({"bootchain", "encryption"}),
        )

    yield from _swap_findings(probe, policy, item, root_encrypted, mapper)


def _swap_findings(probe: Probe, policy: Policy, item, root_encrypted: bool,
                   mapper: dict[str, str]) -> Iterator[Finding]:
    """Unencrypted swap beside an encrypted root defeats the encryption."""
    swaps = [line.split() for line in probe.file("/proc/swaps").lines()[1:]]
    if not swaps:
        return
    evidence = (Evidence("/proc/swaps", probe.text("/proc/swaps").strip()),)

    plain = [fields[0] for fields in swaps
             if fields and not mapper.get(fields[0], "").startswith("CRYPT-")]
    if not plain:
        yield passed(
            item, "swap", "Swap is encrypted",
            "Memory paged out to disk is written through a crypt device.",
            value="encrypted", evidence=evidence,
        )
        return

    if not root_encrypted:
        # The disk is readable anyway; swap adds nothing to the exposure and
        # saying so twice would just pad the list.
        return

    yield finding(
        item, "swap-plain", policy.severity("unencrypted_swap"),
        "Swap is not encrypted, but the root filesystem is",
        f"{listing(plain)} is plain. Anything the kernel pages out of memory — "
        "including the contents of files you have decrypted, and in the case "
        "of hibernation the entire contents of RAM — lands there in the clear.",
        impact="It undoes the disk encryption for whatever happened to be "
               "paged out, which is not something you get to choose.",
        value=listing(plain, limit=2),
        expected="a crypt device, or no swap",
        evidence=evidence,
        fixes=(Fix(
            title="Put swap on a crypt device",
            explanation=(
                "For a swap partition you never hibernate from, a random key "
                "per boot is simplest: add it to /etc/crypttab with "
                "`/dev/urandom` as the key file and swap as the option. If you "
                "do hibernate, it has to be a real LUKS volume unlocked at boot."
            ),
            command="man 5 crypttab",
            risk="Get it wrong and the machine will wait for a passphrase for "
                 "a device that does not exist. Test before relying on it.",
        ),),
        references=(Reference("crypttab(5)", "man 5 crypttab"),),
        tags=frozenset({"bootchain", "encryption"}),
    )


# ---------------------------------------------------------------------------
# Mount options
# ---------------------------------------------------------------------------

#: Mount point -> the options it really ought to have, and why.
EXPECTED_OPTIONS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("/dev/shm", ("nosuid", "nodev", "noexec"),
     "Shared memory is world-writable by design. Executing from it, or a "
     "setuid file in it, has no legitimate use."),
    ("/tmp", ("nosuid", "nodev"),
     "Every user can write here, so a setuid binary or a device node placed "
     "here would be a straightforward privilege escalation."),
    ("/var/tmp", ("nosuid", "nodev"),
     "Same as /tmp, but it survives a reboot, which makes it more useful to "
     "someone who wants to persist."),
    ("/home", ("nosuid", "nodev"),
     "A user cannot usefully create a setuid binary or a device node in their "
     "own home, and nothing legitimate needs to."),
)


@check(
    "bootchain.mount-options",
    title="Mount options on writable filesystems",
    category=Category.BOOTCHAIN,
    inspects="/proc/self/mountinfo for nosuid, nodev and noexec on shared directories.",
    worst=Severity.MEDIUM,
    tags=("bootchain", "hardening"),
)
def mount_options(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """nosuid and nodev on shared directories cost nothing and close a door."""
    item = get("bootchain.mount-options")
    weak: list[str] = []
    rows: list[str] = []
    checked = 0

    for target, wanted, _why in EXPECTED_OPTIONS:
        entry = probe.mount_for(target)
        if entry is None:
            rows.append(f"{target:<12} (not a separate mount point)")
            continue
        checked += 1
        present = {option.split("=")[0] for option in entry["options"].split(",")}
        rows.append(f"{target:<12} {entry['fstype']:<8} {entry['options']}")
        gaps = [option for option in wanted if option not in present]
        if gaps:
            weak.append(f"{target} is missing {listing(gaps)}")

    if not checked:
        raise SkipCheck("none of the shared directories are separate mount points")

    evidence = (Evidence("/proc/self/mountinfo", "\n".join(rows), kind="computed"),)

    if not weak:
        yield passed(
            item, "set", "Shared directories are mounted with the safe options",
            f"{plural(checked, 'mount point')} checked; all have nosuid and nodev.",
            value=f"{checked} checked", evidence=evidence,
        )
        return

    yield finding(
        item, "weak", policy.severity("mount_options_weak"),
        f"{plural(len(weak), 'writable filesystem')} is missing a mount option",
        "; ".join(weak) + ". `nosuid` makes the kernel ignore the setuid bit "
        "on files there, `nodev` makes it ignore device nodes, and `noexec` "
        "refuses to execute anything at all.",
        impact=(
            "A user who can write to a filesystem without nosuid can drop a "
            "setuid-root binary there — if they can get one written, which is "
            "the point of the other checks on this page. These options make "
            "that final step fail."
        ),
        value=plural(len(weak), "mount point"),
        expected="nosuid,nodev",
        evidence=evidence,
        fixes=(Fix(
            title="Add the options in /etc/fstab",
            explanation=(
                "Edit the options column for each mount point, then remount. "
                "Adding noexec to /tmp breaks some package installers and "
                "build tools, so nosuid and nodev are the safe pair to start "
                "with."
            ),
            command="sudo nano /etc/fstab   # then: sudo mount -o remount /tmp",
            risk="A typo in fstab can stop the machine booting. `sudo findmnt "
                 "--verify` checks it before you reboot.",
        ),),
        tags=frozenset({"bootchain", "hardening"}),
    )


@check(
    "bootchain.removable",
    title="Boot files on removable media",
    category=Category.BOOTCHAIN,
    inspects="Whether the device holding /boot is marked removable in sysfs.",
    worst=Severity.MEDIUM,
    tags=("bootchain",),
)
def removable_boot(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """A /boot on a USB stick is a /boot anyone can walk off with."""
    item = get("bootchain.removable")
    entry = probe.mount_for("/boot") or probe.mount_for("/")
    if entry is None:
        raise SkipCheck("the filesystem holding /boot could not be identified")

    source = entry["source"]
    base = os.path.basename(source)
    # nvme0n1p3 -> nvme0n1, sda1 -> sda: the removable flag is on the disk,
    # not on its partitions.
    disk = base.rstrip("0123456789")
    if "nvme" in base and "p" in base:
        disk = base.split("p")[0]
    removable = probe.value(f"/sys/block/{disk}/removable")
    evidence = (Evidence(f"/sys/block/{disk}/removable", removable or "(unknown)",
                         kind="sysfs"),
                Evidence("/proc/self/mountinfo",
                         f"{entry['target']}  {source}  {entry['fstype']}"))

    if removable == "1":
        yield finding(
            item, "removable", policy.severity("boot_on_removable"),
            "The machine boots from removable media",
            f"{source} is on a device the kernel marks as removable.",
            impact="Whoever holds the device controls what the machine boots. "
                   "That can be deliberate — a rescue setup, or keeping the "
                   "boot chain in your pocket — but it is worth knowing.",
            value=disk, evidence=evidence,
            tags=frozenset({"bootchain"}),
        )
        return

    yield passed(
        item, "fixed", "The boot files are on a fixed disk",
        f"{source} is not removable media.",
        value=disk, evidence=evidence,
    )
