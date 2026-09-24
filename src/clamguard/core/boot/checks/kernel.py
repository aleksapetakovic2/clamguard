"""What the running kernel allows, and what it is protected against.

Everything here describes the kernel that is running *now*, which is not
necessarily the kernel installed on disk — that difference is itself one of the
checks, and on a rolling distribution it is the one that bites people.

Sources: ``/proc/cmdline``, ``/proc/sys/kernel/*``, ``/proc/modules``,
``/sys/devices/system/cpu/vulnerabilities/*`` and this boot's kernel journal.
``dmesg`` is deliberately never used: most distributions now set
``kernel.dmesg_restrict=1``, which makes it fail for an ordinary user, and
``journalctl -b -k`` gives the same messages without privilege.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterator

from ..model import Category, Evidence, Finding, Fix, Reference, Severity
from ..probe import Probe
from ..profile import Policy
from ..registry import SkipCheck, check, finding, get, passed
from .common import listing, plural

KERNEL_DOCS = Reference("Kernel admin guide: tainted kernels",
                        "https://docs.kernel.org/admin-guide/tainted-kernels.html")


# ---------------------------------------------------------------------------
# Taint
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TaintBit:
    """One bit of /proc/sys/kernel/tainted, and what it means."""

    bit: int
    letter: str
    summary: str
    #: "modules" for anything about what was loaded, "fault" for anything that
    #: says the kernel has already misbehaved, "note" for the rest.
    kind: str = "note"

    @property
    def value(self) -> int:
        return 1 << self.bit


#: From Documentation/admin-guide/tainted-kernels.rst. Kept complete rather
#: than trimmed to the interesting ones, because an unexplained taint value is
#: exactly the sort of thing a person ends up searching the web for at 2am.
TAINT_BITS: tuple[TaintBit, ...] = (
    TaintBit(0, "G/P", "a proprietary module was loaded", "modules"),
    TaintBit(1, "F", "a module was force-loaded", "modules"),
    TaintBit(2, "S", "the kernel is running on hardware it was not built for", "fault"),
    TaintBit(3, "R", "a module was force-unloaded", "modules"),
    TaintBit(4, "M", "the processor reported a machine check exception", "fault"),
    TaintBit(5, "B", "a bad page was referenced", "fault"),
    TaintBit(6, "U", "a userspace program asked for the taint flag", "note"),
    TaintBit(7, "D", "the kernel has oopsed or hit a BUG since boot", "fault"),
    TaintBit(8, "A", "an ACPI table was overridden by the user", "note"),
    TaintBit(9, "W", "the kernel issued a warning", "note"),
    TaintBit(10, "C", "a staging (unfinished) driver was loaded", "modules"),
    TaintBit(11, "I", "a workaround for a firmware bug was applied", "note"),
    TaintBit(12, "O", "an externally built, out-of-tree module was loaded", "modules"),
    TaintBit(13, "E", "an unsigned module was loaded", "modules"),
    TaintBit(14, "L", "a soft lockup happened", "fault"),
    TaintBit(15, "K", "the kernel has been live-patched", "note"),
    TaintBit(16, "X", "a distribution-specific taint was set", "note"),
    TaintBit(17, "T", "the kernel was built with structure randomisation", "note"),
    TaintBit(18, "N", "an in-kernel test was run", "note"),
)


@check(
    "kernel.taint",
    title="Kernel taint flags",
    category=Category.KERNEL,
    inspects="/proc/sys/kernel/tainted, decoded bit by bit, and /proc/modules.",
    worst=Severity.HIGH,
    tags=("kernel", "modules"),
)
def taint(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """A tainted kernel is either running third-party code or has already failed."""
    item = get("kernel.taint")
    raw = probe.sysctl_int("kernel.tainted")
    if raw is None:
        raise SkipCheck("/proc/sys/kernel/tainted could not be read")

    if raw == 0:
        yield passed(
            item, "clean", "The kernel is not tainted",
            "Nothing has been force-loaded, no unsigned or out-of-tree module "
            "is loaded, and the kernel has not oopsed since boot.",
            value="0",
            evidence=(Evidence("/proc/sys/kernel/tainted", "0", kind="sysfs"),),
        )
        return

    set_bits = [entry for entry in TAINT_BITS if raw & entry.value]
    letters = "".join(entry.letter.split("/")[-1] for entry in set_bits)
    detail = "\n".join(f"bit {entry.bit:2d} ({entry.letter}) = {entry.value:<6d} "
                       f"{entry.summary}" for entry in set_bits)
    evidence = (
        Evidence("/proc/sys/kernel/tainted", f"{raw}\n\ndecoded:\n{detail}", kind="sysfs"),
    )

    faults = [entry for entry in set_bits if entry.kind == "fault"]
    if faults:
        yield finding(
            item, "fault", policy.severity("kernel_tainted_serious"),
            "The kernel has recorded a fault since this boot",
            "The taint flags say something already went wrong: "
            + listing([entry.summary for entry in faults]) + ".",
            impact=(
                "A kernel that has oopsed, hit a machine check or soft-locked "
                "is in an undefined state. Results from anything running on it "
                "— this analysis included — are less trustworthy than usual, "
                "and the cause is often failing memory or a failing disk."
            ),
            value=letters or str(raw),
            expected="0",
            evidence=evidence + (Evidence(
                "journalctl -b -k -g 'BUG|Oops|machine check|soft lockup'",
                "\n".join(_fault_lines(probe)) or "no matching messages retained",
                kind="command"),),
            fixes=(Fix(
                title="Find out what happened",
                explanation="The journal keeps the message that set the flag. "
                            "Start there before treating anything else here as "
                            "meaningful.",
                command="journalctl -b -k -p warning --no-pager | "
                        "grep -Ei 'bug|oops|machine check|soft lockup'",
                recommended=True,
            ),),
            references=(KERNEL_DOCS,),
            tags=frozenset({"kernel", "stability"}),
        )

    module_bits = [entry for entry in set_bits if entry.kind == "modules"]
    if module_bits:
        unsigned = _tainted_modules(probe)
        yield finding(
            item, "modules", policy.severity("kernel_tainted_modules"),
            "The kernel is running third-party modules",
            "The taint flags say: " + listing([entry.summary for entry in module_bits])
            + (f". The modules responsible are {listing(sorted(unsigned))}."
               if unsigned else "."),
            impact=(
                "Out-of-tree modules run with full kernel privilege and are not "
                "covered by your distribution's security updates. This is "
                "normal and expected on a machine with NVIDIA, VirtualBox or "
                "similar drivers — it is listed so that it is a decision rather "
                "than a surprise."
            ),
            value=letters,
            expected="0",
            evidence=evidence + (Evidence(
                "/proc/modules",
                "\n".join(sorted(unsigned)) or "no modules carry a taint flag"),),
            references=(KERNEL_DOCS,),
            tags=frozenset({"kernel", "modules"}),
        )

    notes = [entry for entry in set_bits if entry.kind == "note"]
    if notes and not faults and not module_bits:
        yield finding(
            item, "note", Severity.INFO,
            "The kernel carries informational taint flags",
            listing([entry.summary for entry in notes]).capitalize() + ".",
            value=letters, evidence=evidence,
            references=(KERNEL_DOCS,),
            tags=frozenset({"kernel"}),
        )


def _fault_lines(probe: Probe) -> list[str]:
    wanted = ("bug:", "oops", "machine check", "soft lockup", "call trace")
    return [line for line in probe.kernel_journal()
            if any(word in line.lower() for word in wanted)][-8:]


def _tainted_modules(probe: Probe) -> set[str]:
    """Modules whose /proc/modules entry carries a taint letter in brackets."""
    found = set()
    for line in probe.file("/proc/modules").lines():
        fields = line.split()
        if len(fields) >= 6 and fields[-1].startswith("(") and fields[-1].endswith(")"):
            letters = fields[-1].strip("()")
            if letters and letters not in ("-",):
                found.add(f"{fields[0]} ({letters})")
    return found


# ---------------------------------------------------------------------------
# Lockdown and module signing
# ---------------------------------------------------------------------------


@check(
    "kernel.lockdown",
    title="Kernel lockdown",
    category=Category.KERNEL,
    inspects="/sys/kernel/security/lockdown.",
    worst=Severity.HIGH,
    tags=("kernel", "hardening"),
)
def lockdown(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Lockdown is what stops root from rewriting the running kernel."""
    item = get("kernel.lockdown")
    raw = probe.value("/sys/kernel/security/lockdown")
    if not raw:
        raise SkipCheck("this kernel was built without the lockdown LSM")

    # The file reads "[none] integrity confidentiality" — the active mode is
    # the one in brackets.
    active = "none"
    for token in raw.split():
        if token.startswith("[") and token.endswith("]"):
            active = token.strip("[]")
            break
    evidence = (Evidence("/sys/kernel/security/lockdown", raw, kind="sysfs"),)

    if active != "none":
        yield passed(
            item, "on", f"Kernel lockdown is in {active} mode",
            "Interfaces that would let even root modify the running kernel — "
            "/dev/mem, unsigned modules, kexec of an unsigned image — are "
            "refused.",
            value=active, evidence=evidence,
        )
        return

    secure_boot_on = _secure_boot_on(probe)
    yield finding(
        item, "none", policy.severity("lockdown_none"),
        "Kernel lockdown is off",
        "Lockdown restricts what even root may do to the running kernel: write "
        "to /dev/mem, load an unsigned module, kexec an unsigned image, read "
        "kernel memory through several debugging interfaces."
        + (" It is usually enabled automatically when Secure Boot is on; here "
           "Secure Boot is on but lockdown is not, which is unusual."
           if secure_boot_on else
           " On most distributions it turns itself on when Secure Boot is "
           "enabled, so this follows from Secure Boot being off."),
        impact="Anything that gets root once can modify the running kernel and "
               "survive in memory without touching a file — which means no "
               "file scanner, ClamGuard included, will ever see it.",
        value="none",
        expected="integrity",
        evidence=evidence,
        fixes=(Fix(
            title="Turn it on at the next boot",
            explanation=(
                "Add lockdown=integrity to the kernel command line. On a GRUB "
                "system that means editing GRUB_CMDLINE_LINUX_DEFAULT in "
                "/etc/default/grub and regenerating the configuration."
            ),
            command="sudo sed -i 's/\\(GRUB_CMDLINE_LINUX_DEFAULT=\"[^\"]*\\)/"
                    "\\1 lockdown=integrity/' /etc/default/grub && "
                    "sudo grub-mkconfig -o /boot/grub/grub.cfg",
            risk=(
                "Breaks anything that loads unsigned kernel modules, which "
                "includes the proprietary NVIDIA driver on most distributions, "
                "VirtualBox and DKMS builds in general. Check the taint finding "
                "above before doing this."
            ),
            reboot_required=True,
        ),),
        tags=frozenset({"kernel", "hardening"}),
    )


def _secure_boot_on(probe: Probe) -> bool:
    data = probe.read_bytes(
        "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
    return bool(data and len(data) >= 5 and data[4] == 1)


@check(
    "kernel.module-signing",
    title="Kernel module signature enforcement",
    category=Category.KERNEL,
    inspects="/sys/module/module/parameters/sig_enforce and the kernel command line.",
    worst=Severity.HIGH,
    tags=("kernel", "modules"),
)
def module_signing(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Whether the kernel will load a module nobody signed."""
    item = get("kernel.module-signing")
    enforce = probe.value("/sys/module/module/parameters/sig_enforce")
    if not enforce:
        raise SkipCheck("this kernel does not expose module signature enforcement")

    evidence = (
        Evidence("/sys/module/module/parameters/sig_enforce", enforce, kind="sysfs"),
        Evidence("/proc/cmdline", probe.kernel_cmdline()),
    )

    if enforce.strip().upper() in ("Y", "1"):
        yield passed(
            item, "enforced", "Only signed kernel modules will load",
            "sig_enforce is on, so a module the kernel cannot verify is "
            "refused rather than loaded with a taint flag.",
            value="enforced", evidence=evidence,
        )
        return

    yield finding(
        item, "not-enforced", policy.severity("module_signing_off"),
        "Unsigned kernel modules are allowed to load",
        "The kernel checks module signatures but does not insist on them: an "
        "unsigned module loads anyway and just sets a taint flag.",
        impact="Loading a kernel module is the cleanest way to hide from an "
               "antivirus, because the module can lie to every syscall "
               "ClamGuard makes. Enforcement is what turns that from 'allowed "
               "with a note in the log' into 'refused'.",
        value="not enforced",
        expected="enforced",
        evidence=evidence,
        fixes=(Fix(
            title="Require signatures at the next boot",
            explanation="Add module.sig_enforce=1 to the kernel command line.",
            command="sudo sed -i 's/\\(GRUB_CMDLINE_LINUX_DEFAULT=\"[^\"]*\\)/"
                    "\\1 module.sig_enforce=1/' /etc/default/grub && "
                    "sudo grub-mkconfig -o /boot/grub/grub.cfg",
            risk="Any out-of-tree driver you rely on will stop loading unless "
                 "you sign it yourself. If the taint check above lists modules, "
                 "those are the ones that will break.",
            reboot_required=True,
        ),),
        tags=frozenset({"kernel", "modules"}),
    )


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RiskyParameter:
    """A kernel command-line option worth objecting to."""

    name: str
    #: Values that make it risky. Empty means the option is risky at all.
    values: tuple[str, ...]
    policy_key: str
    floor: Severity
    summary: str
    impact: str

    def triggered_by(self, value: str) -> bool:
        return not self.values or value.lower() in self.values


#: Ordered roughly worst first. Everything here either switches off a defence
#: or hands out a shell; none of them appear on a normal desktop by accident.
RISKY_PARAMETERS: tuple[RiskyParameter, ...] = (
    RiskyParameter(
        "init", (), "cmdline_risky", Severity.HIGH,
        "boots a different program as PID 1",
        "Whoever set this chose what runs first in userspace. If you did not "
        "set it, something replaced your init.",
    ),
    RiskyParameter(
        "systemd.debug-shell", (), "cmdline_risky", Severity.HIGH,
        "starts a root shell on tty9 with no password",
        "Anyone who can reach the console gets root without authenticating.",
    ),
    RiskyParameter(
        "rd.break", (), "cmdline_risky", Severity.HIGH,
        "drops to a shell inside the initramfs",
        "A root shell before the real root filesystem is even mounted.",
    ),
    RiskyParameter(
        "mitigations", ("off",), "cmdline_risky", Severity.HIGH,
        "switches off every CPU vulnerability mitigation at once",
        "Spectre, Meltdown, MDS and the rest become exploitable again. On a "
        "machine that runs a browser or any untrusted code this is a real "
        "exposure, not a theoretical one.",
    ),
    RiskyParameter(
        "nopti", (), "cmdline_risky", Severity.HIGH,
        "disables page table isolation",
        "Meltdown becomes exploitable: any local process can read kernel memory.",
    ),
    RiskyParameter(
        "pti", ("off",), "cmdline_risky", Severity.HIGH,
        "disables page table isolation",
        "Meltdown becomes exploitable: any local process can read kernel memory.",
    ),
    RiskyParameter(
        "noexec", ("off",), "cmdline_risky", Severity.HIGH,
        "makes every writable page executable",
        "Removes the single most effective barrier against memory-corruption "
        "exploits.",
    ),
    RiskyParameter(
        "nosmap", (), "cmdline_risky", Severity.HIGH,
        "disables supervisor mode access prevention",
        "The kernel will follow pointers into userspace memory, which is how a "
        "large family of privilege-escalation bugs is exploited.",
    ),
    RiskyParameter(
        "nosmep", (), "cmdline_risky", Severity.HIGH,
        "disables supervisor mode execution prevention",
        "The kernel can be tricked into executing code from a userspace page.",
    ),
    RiskyParameter(
        "spectre_v2", ("off",), "cmdline_risky", Severity.MEDIUM,
        "disables the Spectre v2 mitigation",
        "Branch target injection across processes becomes possible again.",
    ),
    RiskyParameter(
        "selinux", ("0",), "cmdline_risky", Severity.MEDIUM,
        "disables SELinux entirely",
        "Mandatory access control is off, so a compromised service is confined "
        "only by file permissions.",
    ),
    RiskyParameter(
        "apparmor", ("0",), "cmdline_risky", Severity.MEDIUM,
        "disables AppArmor entirely",
        "Mandatory access control is off, so a compromised service is confined "
        "only by file permissions.",
    ),
    RiskyParameter(
        "vsyscall", ("native",), "cmdline_risky", Severity.MEDIUM,
        "maps the legacy vsyscall page as executable at a fixed address",
        "A reliable, address-space-layout-independent set of gadgets for "
        "return-oriented programming.",
    ),
    RiskyParameter(
        "nokaslr", (), "cmdline_risky", Severity.MEDIUM,
        "puts the kernel at a predictable address",
        "An exploit no longer has to work out where the kernel is.",
    ),
    RiskyParameter(
        "module.sig_enforce", ("0",), "module_signing_off", Severity.MEDIUM,
        "explicitly allows unsigned kernel modules",
        "Anything that reaches root can load a module the kernel cannot verify.",
    ),
    RiskyParameter(
        "iommu", ("off", "soft"), "no_iommu", Severity.MEDIUM,
        "disables the IOMMU",
        "A malicious device on Thunderbolt, PCIe or FireWire can read and write "
        "system memory directly, without the CPU's involvement.",
    ),
    RiskyParameter(
        "intel_iommu", ("off",), "no_iommu", Severity.MEDIUM,
        "disables the Intel IOMMU",
        "Peripherals can read and write system memory directly.",
    ),
    RiskyParameter(
        "amd_iommu", ("off", "fullflush=off"), "no_iommu", Severity.MEDIUM,
        "disables the AMD IOMMU",
        "Peripherals can read and write system memory directly.",
    ),
    RiskyParameter(
        "audit", ("0",), "cmdline_risky", Severity.LOW,
        "switches off the kernel audit subsystem",
        "Security-relevant events are not recorded, so an intrusion leaves "
        "less behind.",
    ),
    RiskyParameter(
        "lockdown", ("none",), "lockdown_none", Severity.LOW,
        "explicitly disables kernel lockdown",
        "Root can modify the running kernel.",
    ),
    RiskyParameter(
        "random.trust_cpu", ("off", "0"), "cmdline_risky", Severity.INFO,
        "refuses to seed the random pool from the CPU",
        "Early boot may block waiting for entropy. Chosen deliberately by "
        "people who do not trust RDRAND.",
    ),
    RiskyParameter(
        "debug", (), "cmdline_risky", Severity.INFO,
        "raises kernel log verbosity",
        "Noisier logs and marginally more information leaked to anyone who can "
        "read them.",
    ),
)

#: Single-word parameters that ask for a single-user or emergency boot.
EMERGENCY_WORDS = frozenset({"single", "s", "1", "emergency", "rescue", "init=/bin/sh",
                             "init=/bin/bash"})


@check(
    "kernel.cmdline",
    title="Risky kernel parameters",
    category=Category.KERNEL,
    inspects="/proc/cmdline, against a table of parameters that disable a defence.",
    worst=Severity.HIGH,
    tags=("kernel", "cmdline"),
)
def risky_cmdline(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Someone can weaken this kernel a lot with one word on the command line."""
    item = get("kernel.cmdline")
    raw = probe.kernel_cmdline()
    if not raw:
        raise SkipCheck("/proc/cmdline could not be read")

    parameters = probe.cmdline_parameters()
    evidence = (Evidence("/proc/cmdline", raw),)
    hits: list[tuple[RiskyParameter, str]] = []

    for risky in RISKY_PARAMETERS:
        if risky.name not in parameters:
            continue
        value = parameters[risky.name]
        if risky.triggered_by(value):
            hits.append((risky, value))

    emergency = sorted(EMERGENCY_WORDS & {token.lower() for token in raw.split()})
    if emergency:
        yield finding(
            item, "emergency", policy.at_least("cmdline_risky", Severity.HIGH),
            "This kernel was booted into single-user or emergency mode",
            f"The command line contains {listing(emergency)}. That starts a "
            "root shell instead of the normal boot, usually without asking for "
            "a password.",
            impact="Nothing that normally starts at boot is running — including "
                   "real-time protection, the firewall and the audit log.",
            value=", ".join(emergency),
            expected="a normal boot",
            evidence=evidence,
            tags=frozenset({"kernel", "cmdline"}),
        )

    for risky, value in hits:
        shown = f"{risky.name}={value}" if value else risky.name
        yield finding(
            item, risky.name.replace(".", "-").replace("_", "-"),
            policy.at_least(risky.policy_key, risky.floor),
            f"The kernel was booted with {shown}",
            f"This parameter {risky.summary}.",
            impact=risky.impact,
            value=shown,
            expected="absent",
            evidence=evidence,
            fixes=(Fix(
                title=f"Remove {risky.name} from the kernel command line",
                explanation=(
                    "It is set in your bootloader configuration. On a GRUB "
                    "system, edit GRUB_CMDLINE_LINUX_DEFAULT in "
                    "/etc/default/grub, then regenerate grub.cfg."
                ),
                command=f"grep -rn '{risky.name}' /etc/default/grub "
                        "/etc/kernel/cmdline /boot/loader/entries/ 2>/dev/null",
                risk="It was presumably added to work around something. Find "
                     "out what before removing it.",
                reboot_required=True,
            ),),
            tags=frozenset({"kernel", "cmdline"}),
        )

    if not hits and not emergency:
        yield passed(
            item, "clean", "No risky kernel parameters",
            f"Checked {len(RISKY_PARAMETERS)} parameters that disable a defence "
            "or hand out a shell. None of them are set.",
            value=f"{len(parameters)} parameters, none risky",
            evidence=evidence,
        )


# ---------------------------------------------------------------------------
# CPU vulnerabilities and microcode
# ---------------------------------------------------------------------------

VULNERABILITY_DIR = "/sys/devices/system/cpu/vulnerabilities"


@check(
    "kernel.mitigations",
    title="CPU vulnerability mitigations",
    category=Category.KERNEL,
    inspects=f"Every file in {VULNERABILITY_DIR}.",
    worst=Severity.HIGH,
    tags=("kernel", "cpu"),
)
def cpu_mitigations(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """The kernel's own verdict on each hardware vulnerability it knows about."""
    item = get("kernel.mitigations")
    names = probe.listdir(VULNERABILITY_DIR)
    if not names:
        raise SkipCheck("this kernel does not report CPU vulnerabilities")

    states: dict[str, str] = {}
    for name in names:
        states[name] = probe.value(f"{VULNERABILITY_DIR}/{name}") or "unknown"

    table = "\n".join(f"{name:<28} {state}" for name, state in sorted(states.items()))
    evidence = (Evidence(VULNERABILITY_DIR, table, kind="sysfs"),)

    vulnerable = sorted(name for name, state in states.items()
                        if state.lower().startswith("vulnerable"))
    partial = sorted(name for name, state in states.items()
                     if "vulnerable" in state.lower() and name not in vulnerable)

    if vulnerable:
        yield finding(
            item, "vulnerable", policy.severity("cpu_vulnerable"),
            f"The CPU is unmitigated against {plural(len(vulnerable), 'vulnerability', 'vulnerabilities')}",
            "The kernel reports no mitigation for " + listing(vulnerable) + ". "
            "That is either because the mitigation was switched off on the "
            "kernel command line, or because this processor needs a microcode "
            "update it has not had.",
            impact="These are the vulnerabilities that let one process read "
                   "another's memory — including a browser tab reading your "
                   "keys. They matter most on a machine that runs code from "
                   "the internet, which is every desktop.",
            value=listing(vulnerable, limit=3),
            expected="mitigated or not affected",
            evidence=evidence,
            fixes=(
                Fix(
                    title="Check whether mitigations were turned off deliberately",
                    explanation="mitigations=off on the kernel command line "
                                "disables all of these at once.",
                    command="cat /proc/cmdline",
                    recommended=True,
                ),
                Fix(
                    title="Install the microcode package for your processor",
                    explanation="Several mitigations need a CPU microcode "
                                "update to exist at all.",
                    command="# Debian/Ubuntu: sudo apt install intel-microcode amd64-microcode\n"
                            "# Fedora:        sudo dnf install microcode_ctl\n"
                            "# Arch:          sudo pacman -S intel-ucode amd-ucode",
                    reboot_required=True,
                ),
            ),
            references=(Reference("Kernel hardware vulnerabilities documentation",
                                  "https://docs.kernel.org/admin-guide/hw-vuln/"),),
            tags=frozenset({"kernel", "cpu"}),
        )
    elif partial:
        yield finding(
            item, "partial", Severity.LOW,
            "Some CPU mitigations are only partly effective",
            "The kernel reports a mitigation for " + listing(partial) + " but "
            "says it is incomplete — usually 'SMT vulnerable', meaning the "
            "mitigation holds between processes but not between the two threads "
            "of one physical core.",
            impact="Relevant if you run untrusted code in a VM or container "
                   "alongside something sensitive. Disabling SMT closes it, at "
                   "a substantial performance cost.",
            value=listing(partial, limit=3),
            evidence=evidence,
            tags=frozenset({"kernel", "cpu"}),
        )
    else:
        mitigated = sum(1 for state in states.values()
                        if state.lower().startswith("mitigation"))
        yield passed(
            item, "covered", "Every known CPU vulnerability is handled",
            f"{len(states)} checked: {mitigated} mitigated, "
            f"{len(states) - mitigated} not applicable to this processor.",
            value=f"{len(states)} checked", evidence=evidence,
        )


@check(
    "kernel.microcode",
    title="Processor microcode",
    category=Category.KERNEL,
    inspects="/proc/cpuinfo and this boot's kernel journal for microcode messages.",
    worst=Severity.HIGH,
    tags=("kernel", "cpu"),
)
def microcode(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Microcode is where most CPU vulnerability fixes actually live."""
    item = get("kernel.microcode")
    revision = ""
    for line in probe.file("/proc/cpuinfo").lines():
        if line.lower().startswith("microcode"):
            revision = line.split(":", 1)[-1].strip()
            break

    messages = [line for line in probe.kernel_journal() if "microcode" in line.lower()]
    loaded_early = any("updated early" in line.lower() for line in messages)
    old = probe.value(f"{VULNERABILITY_DIR}/old_microcode")

    evidence = (
        Evidence("/proc/cpuinfo", f"microcode: {revision or 'not reported'}"),
        Evidence("journalctl -b -k -g microcode",
                 "\n".join(messages[-6:]) or "no microcode messages this boot",
                 kind="command"),
    )

    if old and old.lower().startswith("vulnerable"):
        yield finding(
            item, "outdated", policy.at_least("microcode_stale", Severity.HIGH),
            "The processor is running outdated microcode",
            f"The kernel says so itself: old_microcode reports “{old}”. Your "
            "CPU vendor has published a newer revision than the one loaded.",
            impact="Several CPU vulnerability mitigations only work with "
                   "up-to-date microcode. Without it the kernel cannot fix them "
                   "no matter what it does.",
            value=revision or "unknown",
            expected="current",
            evidence=evidence,
            fixes=(Fix(
                title="Install your distribution's microcode package",
                explanation="It is loaded from the initramfs at every boot, so "
                            "the initramfs has to be regenerated afterwards.",
                command="# Debian/Ubuntu: sudo apt install intel-microcode amd64-microcode\n"
                        "# Fedora:        sudo dnf install microcode_ctl\n"
                        "# Arch:          sudo pacman -S intel-ucode amd-ucode",
                reboot_required=True,
                recommended=True,
            ),),
            tags=frozenset({"kernel", "cpu"}),
        )
        return

    if not messages and not revision:
        raise SkipCheck("this kernel does not report a microcode revision")

    if not loaded_early and messages:
        yield finding(
            item, "late", policy.severity("microcode_stale"),
            "Microcode was not loaded early in boot",
            "The kernel logged microcode messages but none of them say "
            "'Updated early'. Loading microcode from the initramfs, before the "
            "CPU is used for anything else, is what makes some mitigations "
            "possible at all.",
            impact="A late microcode update cannot fix everything an early one "
                   "can, because parts of the kernel have already made "
                   "decisions based on the old CPU capabilities.",
            value="loaded late",
            expected="loaded early from the initramfs",
            evidence=evidence,
            fixes=(Fix(
                title="Put the microcode into the initramfs",
                explanation="Most distributions do this automatically once the "
                            "microcode package is installed and the initramfs "
                            "is regenerated.",
                command="# Debian/Ubuntu: sudo update-initramfs -u\n"
                        "# Fedora:        sudo dracut --force\n"
                        "# Arch:          sudo mkinitcpio -P",
                reboot_required=True,
            ),),
            tags=frozenset({"kernel", "cpu"}),
        )
        return

    yield passed(
        item, "current", "Processor microcode is loaded and current",
        f"Revision {revision or 'unknown'}"
        + (", updated early from the initramfs." if loaded_early else "."),
        value=revision or "loaded", evidence=evidence,
    )


@check(
    "kernel.iommu",
    title="IOMMU and DMA protection",
    category=Category.KERNEL,
    inspects="/sys/class/iommu and this boot's kernel journal.",
    worst=Severity.HIGH,
    tags=("kernel", "dma"),
)
def iommu(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """The only thing standing between a hostile peripheral and your memory."""
    item = get("kernel.iommu")
    groups = probe.listdir("/sys/class/iommu")
    messages = [line for line in probe.kernel_journal()
                if any(word in line for word in ("DMAR", "AMD-Vi", "IOMMU", "iommu"))]
    remapping = any("interrupt remapping enabled" in line.lower() for line in messages)

    evidence = (
        Evidence("/sys/class/iommu",
                 ", ".join(groups) if groups else "empty", kind="sysfs"),
        Evidence("journalctl -b -k -g 'DMAR|AMD-Vi|IOMMU'",
                 "\n".join(messages[:8]) or "no IOMMU messages this boot",
                 kind="command"),
    )

    if groups:
        yield passed(
            item, "active", "The IOMMU is active",
            f"{plural(len(groups), 'IOMMU unit')} present"
            + (", with interrupt remapping enabled." if remapping else ".")
            + " Devices can only reach the memory the kernel maps for them.",
            value=", ".join(groups), evidence=evidence,
        )
        return

    has_thunderbolt = bool(probe.listdir("/sys/bus/thunderbolt/devices"))
    yield finding(
        item, "absent", policy.at_least(
            "no_iommu", Severity.MEDIUM if has_thunderbolt else Severity.LOW),
        "No IOMMU is active",
        "Nothing under /sys/class/iommu. Either the hardware has no IOMMU, it "
        "is disabled in firmware setup (look for VT-d, AMD-Vi or SVM), or it "
        "was turned off on the kernel command line."
        + (" This machine has Thunderbolt, which makes it matter more: a "
           "Thunderbolt device can issue arbitrary DMA."
           if has_thunderbolt else ""),
        impact="A malicious device plugged into Thunderbolt, PCIe or an "
               "ExpressCard slot can read and write system memory directly, "
               "bypassing the CPU and every software protection on this page.",
        value="none",
        expected="active",
        evidence=evidence,
        fixes=(Fix(
            title="Enable virtualisation support in firmware setup",
            explanation="The IOMMU is usually behind the same switch as "
                        "virtualisation: VT-d on Intel, AMD-Vi or IOMMU on AMD.",
            manual="Firmware setup → Advanced / CPU configuration → VT-d or "
                   "IOMMU → Enabled.",
            reboot_required=True,
        ),),
        tags=frozenset({"kernel", "dma"}),
    )


# ---------------------------------------------------------------------------
# The kernel on disk versus the kernel running
# ---------------------------------------------------------------------------


@check(
    "kernel.running-version",
    title="Running kernel versus installed kernel",
    category=Category.KERNEL,
    inspects="The modification time of the kernel images in /boot against this boot's start time.",
    worst=Severity.HIGH,
    tags=("kernel", "updates"),
)
def running_version(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """A kernel newer than the one running means an update is waiting.

    Compared by modification time rather than by parsing version numbers out of
    filenames, because those filenames are distribution-specific — Arch's
    ``vmlinuz-linux`` carries no version at all — while "the file on disk is
    newer than the boot that is running" is true everywhere.
    """
    item = get("kernel.running-version")
    release = probe.kernel_release()
    boot_time = _boot_time(probe)
    if not boot_time:
        raise SkipCheck("the boot time could not be read from /proc/stat")

    newest_name, newest_time = "", 0.0
    for name in probe.listdir("/boot"):
        if not name.startswith(("vmlinuz", "vmlinux", "kernel", "linux")):
            continue
        info = probe.stat(f"/boot/{name}")
        if info and info.st_mtime > newest_time:
            newest_name, newest_time = name, info.st_mtime

    modules_dir = f"/usr/lib/modules/{release}"
    modules_present = probe.exists(modules_dir) or probe.exists(f"/lib/modules/{release}")

    evidence = (
        Evidence("/proc/sys/kernel/osrelease", release, kind="sysfs"),
        Evidence("/proc/stat", f"btime {int(boot_time)}  "
                               f"({time.strftime('%Y-%m-%d %H:%M', time.localtime(boot_time))})"),
        Evidence(f"stat /boot/{newest_name}" if newest_name else "/boot",
                 (f"modified {time.strftime('%Y-%m-%d %H:%M', time.localtime(newest_time))}"
                  if newest_name else "no kernel image found"), kind="computed"),
    )

    if not modules_present:
        yield finding(
            item, "modules-gone", Severity.HIGH,
            "The running kernel's modules are no longer on disk",
            f"There is no {modules_dir}. The kernel package was upgraded while "
            f"{release} was running, and the old modules were removed with it.",
            impact=(
                "Any module not already loaded will now fail to load — which "
                "breaks plugging in new hardware, mounting an unusual "
                "filesystem, and starting a VPN. ClamAV's on-access scanning "
                "relies on fanotify, which is built in, so scanning keeps "
                "working; most other things do not."
            ),
            value=release,
            expected="present",
            evidence=evidence,
            fixes=(Fix(
                title="Reboot into the kernel that is installed",
                explanation="Nothing else fixes it. The modules for the running "
                            "kernel no longer exist.",
                command="systemctl reboot",
                risk="Save your work first.",
                reboot_required=True,
                recommended=True,
            ),),
            tags=frozenset({"kernel", "updates"}),
        )
        return

    pending_hours = policy.threshold("pending_reboot_hours")
    if newest_name and newest_time > boot_time + pending_hours * 3600:
        waited = (time.time() - newest_time) / 3600
        yield finding(
            item, "pending-reboot", policy.severity("stale_running_kernel"),
            "A newer kernel is installed than the one running",
            f"/boot/{newest_name} was written "
            f"{_relative(newest_time)}, after this boot started "
            f"{_relative(boot_time)}. You are still running {release}.",
            impact="Kernel security updates do nothing until the machine "
                   "restarts. If the update fixed a privilege-escalation bug, "
                   "that bug is still present right now.",
            value=f"waiting {waited:.0f}h",
            expected="running the newest installed kernel",
            evidence=evidence,
            fixes=(Fix(
                title="Restart to pick up the new kernel",
                explanation="Save your work first; there is no way to switch "
                            "kernels without rebooting.",
                command="systemctl reboot",
                reboot_required=True,
                recommended=True,
            ),),
            tags=frozenset({"kernel", "updates"}),
        )
        return

    yield passed(
        item, "current", f"Running the installed kernel, {release}",
        f"Booted {_relative(boot_time)}"
        + (f"; the newest image in /boot is {newest_name}." if newest_name else "."),
        value=release, evidence=evidence,
    )


def _boot_time(probe: Probe) -> float:
    for line in probe.file("/proc/stat").lines():
        if line.startswith("btime "):
            try:
                return float(line.split()[1])
            except (IndexError, ValueError):
                return 0.0
    return 0.0


def _relative(timestamp: float) -> str:
    from ..model import format_age

    return format_age(timestamp)


@check(
    "kernel.kexec",
    title="kexec",
    category=Category.KERNEL,
    inspects="/proc/sys/kernel/kexec_load_disabled.",
    worst=Severity.MEDIUM,
    tags=("kernel", "hardening"),
    enabled_by_default=True,
)
def kexec(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """kexec replaces the running kernel without any firmware verification."""
    item = get("kernel.kexec")
    value = probe.sysctl_int("kernel.kexec_load_disabled")
    if value is None:
        raise SkipCheck("this kernel does not expose kexec_load_disabled")

    evidence = (Evidence("/proc/sys/kernel/kexec_load_disabled", str(value), kind="sysfs"),)
    if value == 1:
        yield passed(
            item, "disabled", "kexec is disabled",
            "The running kernel cannot be replaced without a real reboot, so "
            "Secure Boot and the firmware get a say in what runs next.",
            value="disabled", evidence=evidence,
        )
        return

    yield finding(
        item, "enabled", policy.severity("kexec_enabled"),
        "kexec can load a replacement kernel",
        "Root can boot straight into another kernel image without going "
        "through the firmware. That is how kdump captures a crash, so it is "
        "on by default almost everywhere.",
        impact="On a machine with Secure Boot, kexec is a way around it unless "
               "kernel lockdown is also on: the new kernel never passes through "
               "the firmware's signature check.",
        value="enabled",
        expected="disabled, if you do not use kdump",
        evidence=evidence,
        fixes=(Fix(
            title="Disable it after boot",
            explanation="Once set to 1 it cannot be set back without a reboot, "
                        "which is the point.",
            command="echo 'kernel.kexec_load_disabled = 1' | "
                    "sudo tee /etc/sysctl.d/51-kexec.conf && "
                    "sudo sysctl --system",
            risk="Breaks kdump crash capture and any tooling that uses kexec "
                 "for fast reboots.",
        ),),
        tags=frozenset({"kernel", "hardening"}),
    )
