"""Switches that make a local exploit harder to land.

None of these stop an attack on their own. What they do is remove the cheap,
reliable steps an exploit chain depends on — reading a kernel pointer out of
/proc, attaching a debugger to another process, following a symlink planted in
/tmp. Turning them on costs nothing on a desktop and takes several rungs off
the ladder.

Each value is read from ``/proc/sys`` directly rather than by running
``sysctl``, because the file is the same answer without a subprocess and
``sysctl(8)`` is not installed everywhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from ..model import Category, Evidence, Finding, Fix, Reference, Severity
from ..probe import Probe
from ..profile import Policy
from ..registry import SkipCheck, check, finding, get, passed
from .common import listing, plural

SYSCTL_DOCS = Reference("Kernel sysctl documentation",
                        "https://docs.kernel.org/admin-guide/sysctl/kernel.html")


@dataclass(frozen=True)
class Expectation:
    """One sysctl, what it should be, and why anyone should care."""

    key: str
    #: "eq" exact, "ge" at least, "le" at most, "in" one of.
    compare: str
    want: int | tuple[int, ...]
    #: How it reads when the value is right, and when it is not. Both written
    #: out rather than derived, because negating an English sentence
    #: mechanically produces English nobody wants to read.
    title: str
    problem: str
    why: str
    #: What it costs to turn on. Empty means nothing noticeable.
    cost: str = ""

    def satisfied_by(self, value: int) -> bool:
        if self.compare == "ge":
            return value >= int(self.want)
        if self.compare == "le":
            return value <= int(self.want)
        if self.compare == "in":
            return value in tuple(self.want)  # type: ignore[arg-type]
        return value == int(self.want)

    @property
    def wanted_text(self) -> str:
        if self.compare == "ge":
            return f"{self.want} or more"
        if self.compare == "le":
            return f"{self.want} or less"
        if self.compare == "in":
            return " or ".join(str(item) for item in self.want)  # type: ignore[union-attr]
        return str(self.want)

    @property
    def sysctl_line(self) -> str:
        wanted = self.want[0] if isinstance(self.want, tuple) else self.want
        return f"{self.key} = {wanted}"


#: Ordered by how much difference each one makes in practice.
EXPECTATIONS: tuple[Expectation, ...] = (
    Expectation(
        "kernel.kptr_restrict", "ge", 1,
        "Kernel pointers are hidden from unprivileged programs",
        "Kernel pointers are readable by any program",
        "With this at 0, /proc/kallsyms and dozens of other files hand out the "
        "addresses of kernel symbols to any user. An exploit that needs to "
        "know where the kernel is can simply read them instead of guessing, "
        "which defeats the point of address space randomisation.",
    ),
    Expectation(
        "kernel.dmesg_restrict", "eq", 1,
        "The kernel log is not world-readable",
        "The kernel log is readable by any user",
        "The kernel ring buffer routinely contains addresses, hardware "
        "details and crash traces. Restricting it to root removes an easy "
        "source of the information an exploit needs.",
    ),
    Expectation(
        "kernel.yama.ptrace_scope", "ge", 1,
        "Processes cannot attach a debugger to each other",
        "Any process can attach a debugger to another you own",
        "At 0, any process you own can read the memory of any other process "
        "you own — which is how a compromised browser tab steals the contents "
        "of your password manager or your ssh agent.",
        cost="Debuggers need to be started as the parent, or run with sudo. "
             "Some crash reporters and game anti-cheat tools object.",
    ),
    Expectation(
        "fs.protected_symlinks", "eq", 1,
        "Symlink attacks in shared directories are blocked",
        "Symlink attacks in shared directories are not blocked",
        "Stops a program running as root from being tricked into following a "
        "symlink that another user planted in /tmp. This is the single most "
        "common shape of local privilege escalation in shell scripts.",
    ),
    Expectation(
        "fs.protected_hardlinks", "eq", 1,
        "Hard link attacks in shared directories are blocked",
        "Hard link attacks in shared directories are not blocked",
        "The same trick as symlinks, using hard links to files the attacker "
        "cannot read but a privileged program can.",
    ),
    Expectation(
        "fs.protected_regular", "ge", 1,
        "Writes to other people's files in shared directories are blocked",
        "Writes to other people's files in shared directories are not blocked",
        "Stops a privileged program being tricked into writing to a regular "
        "file another user placed in a world-writable directory.",
    ),
    Expectation(
        "fs.protected_fifos", "ge", 1,
        "Opening other people's FIFOs in shared directories is blocked",
        "Opening other people's FIFOs in shared directories is not blocked",
        "The same class of trap, using a named pipe, which can also make the "
        "privileged program block forever.",
    ),
    Expectation(
        "kernel.randomize_va_space", "eq", 2,
        "Full address space layout randomisation",
        "Address space layout randomisation is not at full strength",
        "At 2 the heap is randomised as well as the stack and libraries. "
        "Anything lower makes memory-corruption exploits substantially more "
        "reliable.",
    ),
    Expectation(
        "kernel.unprivileged_bpf_disabled", "ge", 1,
        "Unprivileged programs cannot load BPF",
        "Unprivileged programs can load BPF",
        "The BPF verifier has been a recurring source of kernel privilege "
        "escalation. Ordinary programs do not need to load BPF.",
        cost="Breaks unprivileged use of bpftrace and some profilers.",
    ),
    Expectation(
        "net.core.bpf_jit_harden", "ge", 1,
        "The BPF JIT is hardened against spraying",
        "The BPF JIT is not hardened against spraying",
        "Blinds the constants the JIT emits, so an attacker cannot use them to "
        "place chosen instructions in executable kernel memory.",
    ),
    Expectation(
        "kernel.perf_event_paranoid", "ge", 2,
        "Performance counters are not available to everyone",
        "Performance counters are available to every user",
        "The perf subsystem can observe other processes and has had its own "
        "privilege escalations. Restricting it removes both.",
        cost="Unprivileged profiling stops working; perf then needs sudo.",
    ),
    Expectation(
        "vm.mmap_min_addr", "ge", 65536,
        "The lowest memory pages cannot be mapped",
        "The lowest memory pages can be mapped by a program",
        "Makes kernel NULL-pointer-dereference bugs unexploitable rather than "
        "merely a crash.",
    ),
    Expectation(
        "dev.tty.ldisc_autoload", "eq", 0,
        "Rarely used TTY line disciplines are not auto-loaded",
        "Rarely used TTY line disciplines load on demand",
        "Line discipline modules are old, little-reviewed kernel code that any "
        "user could previously load on demand. Several exploits have used them.",
    ),
    Expectation(
        "fs.suid_dumpable", "in", (0, 2),
        "Setuid programs do not write readable core dumps",
        "Setuid programs write core dumps their caller can read",
        "At 1, a crashing setuid program writes a core dump readable by the "
        "user who ran it — which can contain the contents of files that user "
        "cannot read.",
    ),
)


@check(
    "hardening.sysctl",
    title="Kernel hardening switches",
    category=Category.HARDENING,
    inspects=f"{len(EXPECTATIONS)} values under /proc/sys.",
    worst=Severity.MEDIUM,
    tags=("hardening", "sysctl"),
)
def sysctl_expectations(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """One finding per weak setting, so each can be muted on its own."""
    item = get("hardening.sysctl")
    weak: list[tuple[Expectation, int]] = []
    fine: list[Expectation] = []
    absent: list[Expectation] = []

    for expectation in EXPECTATIONS:
        value = probe.sysctl_int(expectation.key)
        if value is None:
            absent.append(expectation)
        elif expectation.satisfied_by(value):
            fine.append(expectation)
        else:
            weak.append((expectation, value))

    table = "\n".join(
        f"{expectation.key:<36} {probe.sysctl(expectation.key) or '(absent)':>10}"
        f"   want {expectation.wanted_text}"
        for expectation in EXPECTATIONS
    )
    shared_evidence = (Evidence("/proc/sys", table, kind="sysfs"),)

    for expectation, value in weak:
        yield finding(
            item, expectation.key.replace(".", "-"),
            policy.severity("sysctl_weak"),
            expectation.problem,
            expectation.why,
            impact=f"{expectation.key} is {value}; it should be "
                   f"{expectation.wanted_text}."
                   + (f" Cost of changing it: {expectation.cost}"
                      if expectation.cost else ""),
            value=str(value),
            expected=expectation.wanted_text,
            evidence=(Evidence(f"/proc/sys/{expectation.key.replace('.', '/')}",
                               str(value), kind="sysfs"),) + shared_evidence,
            fixes=(Fix(
                title=f"Set {expectation.key}",
                explanation="Written to a file under /etc/sysctl.d so it "
                            "survives a reboot, then applied immediately.",
                command=f"echo '{expectation.sysctl_line}' | "
                        f"sudo tee /etc/sysctl.d/60-clamguard-hardening.conf -a && "
                        f"sudo sysctl --system",
                risk=expectation.cost or "No practical cost on a desktop.",
                recommended=True,
            ),),
            references=(SYSCTL_DOCS,),
            tags=frozenset({"hardening", "sysctl"}),
        )

    if not weak:
        yield passed(
            item, "all", "Kernel hardening switches are set",
            f"{plural(len(fine), 'setting')} checked and correct"
            + (f"; {len(absent)} not present in this kernel." if absent else "."),
            value=f"{len(fine)}/{len(EXPECTATIONS)}",
            evidence=shared_evidence,
        )
    elif absent:
        yield finding(
            item, "absent", Severity.INFO,
            f"{plural(len(absent), 'hardening switch', 'hardening switches')} "
            "do not exist in this kernel",
            "Not a problem — they are compile-time features this kernel was "
            "built without: " + listing([e.key for e in absent]) + ".",
            value=str(len(absent)),
            evidence=shared_evidence,
            tags=frozenset({"hardening", "sysctl"}),
        )


@check(
    "hardening.lsm",
    title="Mandatory access control",
    category=Category.HARDENING,
    inspects="/sys/kernel/security/lsm and the kernel command line.",
    worst=Severity.HIGH,
    tags=("hardening", "lsm"),
)
def mandatory_access_control(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Whether anything confines a service beyond ordinary file permissions."""
    item = get("hardening.lsm")
    raw = probe.value("/sys/kernel/security/lsm")
    if not raw:
        raise SkipCheck("this kernel does not list its security modules")

    active = [name.strip() for name in raw.split(",") if name.strip()]
    mac = [name for name in active
           if name in ("selinux", "apparmor", "smack", "tomoyo")]
    extras = [name for name in active if name in ("yama", "landlock", "lockdown", "bpf")]
    evidence = (
        Evidence("/sys/kernel/security/lsm", raw, kind="sysfs"),
        Evidence("/proc/cmdline", probe.kernel_cmdline()),
    )

    if mac:
        enforcing = ""
        if "selinux" in mac:
            enforcing = probe.value("/sys/fs/selinux/enforce")
            if enforcing == "0":
                yield finding(
                    item, "selinux-permissive", policy.severity("no_mac_lsm"),
                    "SELinux is loaded but only logging, not enforcing",
                    "In permissive mode SELinux records what it would have "
                    "blocked and then allows it anyway. That is a useful state "
                    "for debugging a policy and a useless one for security.",
                    impact="A compromised service is confined by nothing but "
                           "file permissions, while the logs suggest otherwise.",
                    value="permissive", expected="enforcing",
                    evidence=evidence + (Evidence("/sys/fs/selinux/enforce", "0",
                                                  kind="sysfs"),),
                    fixes=(Fix(
                        title="Switch to enforcing",
                        explanation="Try it for the current boot first; make it "
                                    "permanent in /etc/selinux/config only once "
                                    "nothing has broken.",
                        command="sudo setenforce 1",
                        risk="Anything the permissive log was quietly allowing "
                             "will now fail. Read the audit log first: "
                             "sudo ausearch -m avc -ts recent",
                    ),),
                    tags=frozenset({"hardening", "lsm"}),
                )
                return
        yield passed(
            item, "present", f"{mac[0].capitalize()} is active",
            "Services are confined by policy, not only by file permissions"
            + (f". Also loaded: {listing(extras)}." if extras else "."),
            value=", ".join(mac), evidence=evidence,
        )
        return

    yield finding(
        item, "none", policy.severity("no_mac_lsm"),
        "No mandatory access control is active",
        "Neither SELinux nor AppArmor is loaded. "
        + (f"The kernel does have {listing(extras)}, which help, but none of "
           "them confine a service to a policy." if extras else ""),
        impact=(
            "A compromised network-facing service can reach anything the user "
            "it runs as can reach. Mandatory access control is what limits a "
            "web server to its own document root even when it is running as "
            "root."
        ),
        value="none",
        expected="selinux or apparmor",
        evidence=evidence,
        fixes=(Fix(
            title="Install your distribution's AppArmor or SELinux packages",
            explanation=(
                "Which one is right depends on the distribution: Debian, Ubuntu "
                "and openSUSE ship AppArmor; Fedora and RHEL ship SELinux. "
                "Retrofitting either onto a running system takes care."
            ),
            command="# Debian/Ubuntu: sudo apt install apparmor apparmor-profiles\n"
                    "# Arch:          sudo pacman -S apparmor  "
                    "# then add lsm=landlock,lockdown,yama,apparmor,bpf to the cmdline",
            risk="A policy that does not match your system will block things "
                 "that used to work. Start in complain/permissive mode.",
            reboot_required=True,
        ),),
        tags=frozenset({"hardening", "lsm"}),
    )


@check(
    "hardening.userns",
    title="Unprivileged user namespaces",
    category=Category.HARDENING,
    inspects="user.max_user_namespaces and kernel.unprivileged_userns_clone.",
    worst=Severity.MEDIUM,
    tags=("hardening",),
)
def user_namespaces(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """A trade-off, not a mistake — so it is reported as one."""
    item = get("hardening.userns")
    maximum = probe.sysctl_int("user.max_user_namespaces")
    clone = probe.sysctl_int("kernel.unprivileged_userns_clone")
    if maximum is None and clone is None:
        raise SkipCheck("this kernel does not expose user namespace limits")

    allowed = (maximum is None or maximum > 0) and (clone is None or clone == 1)
    evidence = (
        Evidence("/proc/sys/user/max_user_namespaces",
                 str(maximum) if maximum is not None else "(absent)", kind="sysfs"),
        Evidence("/proc/sys/kernel/unprivileged_userns_clone",
                 str(clone) if clone is not None else "(absent)", kind="sysfs"),
    )

    if not allowed:
        yield passed(
            item, "restricted", "Unprivileged user namespaces are disabled",
            "Ordinary users cannot create a namespace in which they are root, "
            "which closes off a long list of kernel privilege escalations.",
            value="disabled", evidence=evidence,
        )
        return

    yield finding(
        item, "allowed", policy.severity("unprivileged_userns"),
        "Any user can create a user namespace",
        "Inside a user namespace an ordinary user is root, which gives them "
        "reach into kernel code paths that normally require privilege. A large "
        "share of Linux privilege-escalation exploits in the last decade "
        "started here.",
        impact=(
            "This is a genuine trade-off rather than a misconfiguration. "
            "Flatpak, Podman, Bubblewrap, Chrome's and Firefox's sandboxes all "
            "need it. Turning it off hardens the kernel and breaks those. "
            "Reported so that it is a decision you have made."
        ),
        value="allowed",
        expected="depends on whether you use containers or Flatpak",
        evidence=evidence,
        fixes=(Fix(
            title="Disable them, if nothing here needs them",
            explanation="Check first: `flatpak list` and `podman ps -a` having "
                        "output means you need this left alone.",
            command="echo 'user.max_user_namespaces = 0' | "
                    "sudo tee /etc/sysctl.d/61-userns.conf && sudo sysctl --system",
            risk="Breaks Flatpak, Podman, Bubblewrap, and the sandboxes in "
                 "Chrome and Firefox. On a desktop this is usually the wrong "
                 "trade.",
        ),),
        tags=frozenset({"hardening"}),
    )


@check(
    "hardening.coredumps",
    title="Core dump handling",
    category=Category.HARDENING,
    inspects="kernel.core_pattern and fs.suid_dumpable.",
    worst=Severity.MEDIUM,
    tags=("hardening",),
)
def core_dumps(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """A core dump is a copy of a program's memory, keys included."""
    item = get("hardening.coredumps")
    pattern = probe.sysctl("kernel.core_pattern")
    dumpable = probe.sysctl_int("fs.suid_dumpable")
    if not pattern:
        raise SkipCheck("kernel.core_pattern could not be read")

    evidence = (
        Evidence("/proc/sys/kernel/core_pattern", pattern, kind="sysfs"),
        Evidence("/proc/sys/fs/suid_dumpable",
                 str(dumpable) if dumpable is not None else "(absent)", kind="sysfs"),
    )

    if dumpable == 1:
        yield finding(
            item, "suid-dumpable", policy.severity("suid_dumpable"),
            "Setuid programs write core dumps readable by the user who ran them",
            "fs.suid_dumpable is 1. When a setuid program crashes it dumps its "
            "memory to a file the calling user can read.",
            impact="A setuid program's memory can contain the contents of files "
                   "the user is not allowed to read. Crashing one on purpose "
                   "then becomes a way to read them.",
            value="1", expected="0 or 2",
            evidence=evidence,
            fixes=(Fix(
                title="Stop setuid programs dumping readable cores",
                explanation="0 refuses the dump entirely; 2 writes it root-only.",
                command="echo 'fs.suid_dumpable = 0' | "
                        "sudo tee /etc/sysctl.d/62-coredumps.conf && sudo sysctl --system",
                recommended=True,
            ),),
            tags=frozenset({"hardening"}),
        )
        return

    if pattern.startswith("|"):
        handler = pattern[1:].split()[0]
        yield passed(
            item, "handled", "Core dumps go to a handler, not to the filesystem",
            f"They are piped to {handler}, which decides where they land and "
            "who may read them.",
            value=handler, evidence=evidence,
        )
        return

    yield finding(
        item, "to-disk", Severity.INFO,
        "Core dumps are written straight to the filesystem",
        f"kernel.core_pattern is “{pattern}”, so a crashing program writes a "
        "copy of its memory next to wherever it was running.",
        impact="Those files can contain passwords, keys and decrypted "
               "documents, and they inherit the directory's permissions.",
        value=pattern,
        evidence=evidence,
        fixes=(Fix(
            title="Disable core dumps for interactive sessions",
            explanation="systemd-coredump, where available, is the better "
                        "answer: it stores dumps root-only and expires them.",
            command="echo '* hard core 0' | sudo tee -a /etc/security/limits.conf",
        ),),
        tags=frozenset({"hardening"}),
    )
