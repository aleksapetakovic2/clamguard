"""Working out *why* something is broken, and what would fix it.

A service that says "failed" is not useful. This module reads the actual
configuration and the actual journal and turns that into a sentence a person
can act on, plus a concrete set of configuration changes that would fix it.

Every remedy is a plain dictionary of option -> value. Nothing here writes
anything; the UI turns a remedy into a diff, shows it, and only then asks the
privileged helper to apply it.

The rules encoded here come from ClamAV's own documentation and from clamd's
startup checks. Where a rule is a judgement call rather than a hard
requirement, the severity says so.
"""

from __future__ import annotations

import pwd
from dataclasses import dataclass, field
from pathlib import Path

from .conf_file import ConfFile
from .logging_setup import get_logger
from .services import Role, ServiceStatus

log = get_logger(__name__)

#: Paths that should not be watched with prevention enabled. Blocking access to
#: a binary in /usr while a process is executing it deadlocks that process, and
#: watching /var makes package installs unbearably slow — both are called out in
#: ClamAV's shipped configuration.
RISKY_PREVENTION_PATHS = ("/", "/usr", "/etc", "/var", "/bin", "/lib", "/sbin")


@dataclass(frozen=True)
class Remedy:
    """A concrete change that would fix a problem."""

    title: str
    explanation: str
    #: Which configuration file to edit.
    file: Path
    #: Option -> value. A value of None removes the option. A list sets a
    #: repeatable option to exactly those values.
    changes: dict[str, object] = field(default_factory=dict)
    #: Units to restart afterwards, in order.
    restart: tuple[Role, ...] = ()
    #: True when this is the option ClamGuard would pick by default.
    recommended: bool = False

    def apply_to(self, conf: ConfFile) -> ConfFile:
        """Return the given ConfFile with this remedy's changes applied."""
        for key, value in self.changes.items():
            if value is None:
                conf.remove(key)
            elif isinstance(value, list):
                conf.set_all(key, [str(item) for item in value])
            else:
                conf.set(key, value)
        return conf


@dataclass(frozen=True)
class Diagnosis:
    """One thing that is wrong, why it matters, and how to fix it."""

    id: str
    severity: str           # "danger" | "warn" | "info"
    title: str
    detail: str
    remedies: tuple[Remedy, ...] = ()
    #: Raw evidence — journal lines, config values — shown under "details".
    evidence: tuple[str, ...] = ()

    @property
    def fixable(self) -> bool:
        return bool(self.remedies)

    def recommended_remedy(self) -> Remedy | None:
        for remedy in self.remedies:
            if remedy.recommended:
                return remedy
        return self.remedies[0] if self.remedies else None


def daemon_user(conf: ConfFile) -> str:
    """The account clamd runs as, which is what on-access must exclude."""
    return conf.get("User") or "clamav"


def diagnose_on_access(
    conf: ConfFile,
    status: ServiceStatus,
    daemon_status: ServiceStatus,
    journal_lines: list[str],
    conf_path: Path,
) -> list[Diagnosis]:
    """Everything wrong with the real-time scanner, in order of severity."""
    found: list[Diagnosis] = []

    include_paths = conf.get_all("OnAccessIncludePath")
    mount_paths = conf.get_all("OnAccessMountPath")
    prevention = conf.get_bool("OnAccessPrevention", False)
    user = daemon_user(conf)

    has_exclusion = bool(
        conf.get_all("OnAccessExcludeUID")
        or conf.get_all("OnAccessExcludeUname")
        or conf.get_bool("OnAccessExcludeRootUID", False)
    )

    # -- 1. The startup check that stops clamonacc dead ---------------------
    if not has_exclusion:
        evidence = tuple(
            line for line in journal_lines
            if "OnAccessExclude" in line or "at least one of" in line
        )[-3:]
        found.append(Diagnosis(
            id="onaccess-no-exclusion",
            severity="danger",
            title="On-access scanning has no exclusions, so it refuses to start",
            detail=(
                "clamonacc will not run unless at least one of OnAccessExcludeUID, "
                "OnAccessExcludeUname or OnAccessExcludeRootUID is set. Without an "
                "exclusion the scanner would see its own reads as file access and "
                f"scan itself forever. Excluding the {user} account — the one clamd "
                "runs as — is the standard fix."
            ),
            evidence=evidence,
            remedies=(
                Remedy(
                    title=f"Exclude the {user} account",
                    explanation=(
                        f"Adds OnAccessExcludeUname {user}, so file access by the "
                        "scanner itself does not trigger another scan. This is what "
                        "ClamAV's own documentation suggests."
                    ),
                    file=conf_path,
                    changes={"OnAccessExcludeUname": [user]},
                    restart=(Role.DAEMON, Role.ONACCESS),
                    recommended=True,
                ),
                Remedy(
                    title="Exclude everything running as root",
                    explanation=(
                        "Adds OnAccessExcludeRootUID yes. Broader: no root-owned "
                        "process triggers a scan at all, which covers the scanner "
                        "but also covers package managers and system services."
                    ),
                    file=conf_path,
                    changes={"OnAccessExcludeRootUID": True},
                    restart=(Role.DAEMON, Role.ONACCESS),
                ),
            ),
        ))

    # -- 2. Nothing is actually being watched -------------------------------
    if not include_paths and not mount_paths:
        home = str(Path.home())
        found.append(Diagnosis(
            id="onaccess-nothing-watched",
            severity="danger",
            title="On-access scanning is not watching anything",
            detail=(
                "Neither OnAccessIncludePath nor OnAccessMountPath is set, so even "
                "when clamonacc starts it has nothing to do."
            ),
            remedies=(
                Remedy(
                    title=f"Watch {home}",
                    explanation=(
                        "Watches your home directory, which is where downloaded and "
                        "received files land. System directories are left alone, "
                        "which is what makes prevention safe to enable."
                    ),
                    file=conf_path,
                    changes={"OnAccessIncludePath": [home]},
                    restart=(Role.DAEMON, Role.ONACCESS),
                    recommended=True,
                ),
            ),
        ))

    # -- 3. Prevention does not work with mount paths -----------------------
    if prevention and mount_paths:
        found.append(Diagnosis(
            id="onaccess-prevention-mountpath",
            severity="warn",
            title="Blocking is enabled but cannot work on the watched mount points",
            detail=(
                "OnAccessPrevention only blocks access for paths listed under "
                "OnAccessIncludePath. Everything covered by OnAccessMountPath "
                f"({', '.join(mount_paths)}) is reported but never blocked, so "
                "protection is weaker than it looks."
            ),
            evidence=tuple(f"OnAccessMountPath {path}" for path in mount_paths),
            remedies=(
                Remedy(
                    title="Report only, do not block",
                    explanation=(
                        "Turns OnAccessPrevention off and keeps the mount point "
                        "watched. Detections are still logged, notified and shown "
                        "here — nothing is silently unprotected — but access is "
                        "never denied. This keeps the coverage you have."
                    ),
                    file=conf_path,
                    changes={"OnAccessPrevention": False},
                    restart=(Role.DAEMON, Role.ONACCESS),
                    recommended=True,
                ),
                Remedy(
                    title="Watch directories instead of whole mount points",
                    explanation=(
                        "Removes OnAccessMountPath so blocking applies to everything "
                        f"still watched. Be careful: watching directories places one "
                        f"kernel watch per directory ({_describe_watch_cost(include_paths)}), re-walked "
                        "every time the scanner restarts, whereas a mount point needs "
                        "a single watch and covers everything immediately. On a large "
                        "home directory this can mean minutes with no protection after "
                        "each restart, and files missed if the watch limit is reached."
                    ),
                    file=conf_path,
                    changes={"OnAccessMountPath": None},
                    restart=(Role.DAEMON, Role.ONACCESS),
                ),
            ),
        ))

    # -- 4. Blocking on system directories is dangerous ---------------------
    risky = [path for path in include_paths if path.rstrip("/") in
             [p.rstrip("/") for p in RISKY_PREVENTION_PATHS] or path == "/"]
    if prevention and risky:
        found.append(Diagnosis(
            id="onaccess-risky-prevention",
            severity="warn",
            title="Blocking is enabled on system directories",
            detail=(
                f"OnAccessIncludePath covers {', '.join(risky)} with prevention "
                "turned on. Denying access to a binary while it is executing can "
                "hang the process, and watching /var makes package installation "
                "roughly a thousand times slower. ClamAV's own configuration warns "
                "against both."
            ),
            evidence=tuple(f"OnAccessIncludePath {path}" for path in risky),
            remedies=(
                Remedy(
                    title=f"Watch only {Path.home()}",
                    explanation=(
                        "Replaces the system paths with your home directory, which "
                        "is where files arrive from outside."
                    ),
                    file=conf_path,
                    changes={"OnAccessIncludePath": [str(Path.home())]},
                    restart=(Role.DAEMON, Role.ONACCESS),
                    recommended=True,
                ),
                Remedy(
                    title="Keep the paths but stop blocking",
                    explanation="Turns OnAccessPrevention off and reports instead.",
                    file=conf_path,
                    changes={"OnAccessPrevention": False},
                    restart=(Role.DAEMON, Role.ONACCESS),
                ),
            ),
        ))

    # -- 5. Reporting only ---------------------------------------------------
    if not prevention and (include_paths or mount_paths) and has_exclusion:
        if mount_paths:
            # Prevention has no effect on mount-point coverage, so offering to
            # turn it on would promise blocking that would never happen.
            found.append(Diagnosis(
                id="onaccess-report-only",
                severity="info",
                title="Real-time scanning reports, and cannot block",
                detail=(
                    f"Mount points are watched ({', '.join(mount_paths)}), which "
                    "gives complete and immediate coverage — but OnAccessPrevention "
                    "does not apply to them, so infected files are reported rather "
                    "than blocked. ClamGuard shows every detection as it happens, "
                    "and you choose what to do with it.\n\n"
                    "To get blocking as well, add an OnAccessIncludePath for the "
                    "directories that matter — your home folder, not the whole "
                    "filesystem — and turn prevention on. Keep the mount point for "
                    "everything else."
                ),
            ))
        else:
            found.append(Diagnosis(
                id="onaccess-report-only",
                severity="info",
                title="Real-time scanning reports but does not block",
                detail=(
                    "OnAccessPrevention is off, so an infected file is logged and "
                    "you are notified, but nothing stops it being opened."
                ),
                remedies=(
                    Remedy(
                        title="Block access to infected files",
                        explanation=(
                            "Sets OnAccessPrevention yes. Safe here, because only "
                            "directories are watched and none of them are system "
                            "directories."
                        ),
                        file=conf_path,
                        changes={"OnAccessPrevention": True},
                        restart=(Role.DAEMON, Role.ONACCESS),
                        recommended=not risky,
                    ),
                ),
            ))

    # -- 6. The daemon has to be up ------------------------------------------
    if status.exists and not daemon_status.running:
        found.append(Diagnosis(
            id="onaccess-daemon-down",
            severity="danger",
            title="The scanning daemon is not running",
            detail=(
                "clamonacc sends every file it sees to clamd. With clamd stopped, "
                "real-time protection cannot work at all."
            ),
        ))

    # -- 7. Kernel watch limits ----------------------------------------------
    watches = _inotify_watch_limit()
    if watches and watches < 65536 and (include_paths or mount_paths):
        found.append(Diagnosis(
            id="onaccess-watch-limit",
            severity="info",
            title="The kernel's inotify watch limit is low",
            detail=(
                f"fs.inotify.max_user_watches is {watches:,}. clamonacc places a "
                "watch on every directory it monitors, so on a large tree it can "
                "run out and silently stop noticing new folders. Raising it is a "
                "sysctl change, which ClamGuard does not make for you."
            ),
            evidence=(f"fs.inotify.max_user_watches = {watches}",
                      "Raise it with: sudo sysctl fs.inotify.max_user_watches=524288"),
        ))

    return found


def diagnose_service(role: Role, status: ServiceStatus,
                     journal_lines: list[str]) -> list[Diagnosis]:
    """Generic reporting for a unit that is not doing what it should."""
    if not status.exists:
        return [Diagnosis(
            id=f"{role.value}-missing",
            severity="info",
            title=f"No {role.title.lower()} service on this machine",
            detail=("ClamGuard could not find a systemd unit for this. It may not be "
                    "packaged on your distribution, or it may be started another way."),
        )]

    if status.masked:
        return [Diagnosis(
            id=f"{role.value}-masked",
            severity="warn",
            title=f"{status.unit} is masked",
            detail=("A masked unit cannot be started at all until it is unmasked, "
                    "which is a deliberate administrative action ClamGuard will not "
                    "undo for you."),
            evidence=(f"systemctl unmask {status.unit}",),
        )]

    if status.failed:
        return [Diagnosis(
            id=f"{role.value}-failed",
            severity="danger",
            title=f"{status.unit} failed to start",
            detail=(f"The unit exited with status {status.exit_status}. The last "
                    "lines from its journal are below."),
            evidence=tuple(journal_lines[-6:]),
        )]

    if not status.running and not status.one_shot_ok:
        return [Diagnosis(
            id=f"{role.value}-stopped",
            severity="warn",
            title=f"{status.unit} is not running",
            detail=role.explanation,
        )]

    return []


#: Bounds on the directory count used in the mount-path explanation. This runs
#: while a page is rendering, so it is capped by both count and elapsed time —
#: the number only has to convey an order of magnitude.
_WATCH_COUNT_CAP = 20_000
_WATCH_TIME_CAP_SECONDS = 0.75


def _describe_watch_cost(include_paths: list[str]) -> str:
    """Roughly how many directories a directory-based watch would cover."""
    import os
    import time

    deadline = time.monotonic() + _WATCH_TIME_CAP_SECONDS
    counted = 0
    for root in include_paths or [str(Path.home())]:
        for _directory, subdirectories, _files in os.walk(root, topdown=True,
                                                          onerror=lambda _e: None):
            counted += len(subdirectories)
            if counted >= _WATCH_COUNT_CAP or time.monotonic() > deadline:
                return f"more than {_WATCH_COUNT_CAP:,} under {root}"
    return f"about {counted:,}"


def _inotify_watch_limit() -> int:
    try:
        return int(Path("/proc/sys/fs/inotify/max_user_watches")
                   .read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return 0


def user_exists(name: str) -> bool:
    """Does this account exist? Used to sanity-check an exclusion before writing it."""
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False
