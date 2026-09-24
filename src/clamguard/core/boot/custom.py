"""Checks the user writes, without writing Python.

Drop a JSON file into ``~/.config/clamguard/boot-checks.d/`` and it becomes a
check, listed alongside the built-in ones and subject to the same mutes and
severity overrides::

    {
      "id": "site.ssh-no-root-login",
      "title": "SSH refuses root logins",
      "category": "hardening",
      "severity": "high",
      "kind": "file_contains",
      "path": "/etc/ssh/sshd_config",
      "pattern": "^PermitRootLogin\\\\s+no",
      "regex": true,
      "expect": "present",
      "summary": "An organisation baseline: root must not log in over SSH.",
      "fix_command": "sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config"
    }

**There is deliberately no "run this command" kind.** Six declarative kinds
cover the things a site baseline actually asserts, and none of them turn a
configuration file into a way to execute something. A user who wants to run
arbitrary commands already can; what they should not be able to do by accident
is hand somebody else a JSON file that runs commands when opened.

The one sharp edge is ``regex``. A pathological pattern can make Python's
regex engine take a very long time, and there is no timeout available. Patterns
are capped at :data:`MAX_PATTERN` characters and the whole thing runs on a
worker thread, so the window stays responsive — but a bad pattern in your own
file is your own foot.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .. import paths
from ..logging_setup import get_logger
from .model import Category, Evidence, Finding, Fix, Severity
from .probe import Probe
from .profile import Policy
from .registry import Check, SkipCheck

log = get_logger(__name__)

CHECKS_DIRNAME = "boot-checks.d"
MAX_PATTERN = 200

#: What a custom check may assert. Each one reads state; none executes anything.
KINDS = ("sysctl", "file_exists", "file_mode", "file_contains",
         "cmdline", "unit_state")


@dataclass(frozen=True)
class Definition:
    """One user-written check, validated."""

    id: str
    title: str
    kind: str
    category: Category = Category.HARDENING
    severity: Severity = Severity.MEDIUM
    summary: str = ""
    impact: str = ""
    #: Which thing to look at — meaning depends on the kind.
    path: str = ""
    key: str = ""
    unit: str = ""
    parameter: str = ""
    pattern: str = ""
    regex: bool = False
    #: "present" | "absent" for the existence kinds.
    expect: str = "present"
    #: "eq" | "ne" | "ge" | "le" for sysctl.
    compare: str = "eq"
    value: str = ""
    mode: int = 0
    fix_title: str = ""
    fix_command: str = ""
    fix_explanation: str = ""
    source_file: str = ""

    def describe(self) -> str:
        """The `inspects` line shown in the Checks tab."""
        return {
            "sysctl": f"The sysctl {self.key}, expected {self.compare} {self.value}.",
            "file_exists": f"Whether {self.path} is {self.expect}.",
            "file_mode": f"The permissions of {self.path}, expected no looser "
                         f"than {self.mode:04o}.",
            "file_contains": f"Whether {self.path} contains "
                             f"{'the pattern' if self.regex else 'the text'} "
                             f"“{self.pattern}” ({self.expect}).",
            "cmdline": f"Whether the kernel command line has {self.parameter} "
                       f"({self.expect}).",
            "unit_state": f"Whether {self.unit} is {self.value or 'active'}.",
        }.get(self.kind, "A user-defined check.")


class DefinitionError(ValueError):
    """A user-written check file that cannot be used, with the reason."""


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def directory() -> Path:
    return paths.CONFIG_DIR / CHECKS_DIRNAME


def load(from_directory: Path | None = None) -> tuple[list[Check], list[str]]:
    """Every valid custom check, plus a list of problems to show the user.

    Never raises. A malformed file produces a message, not a crash, because the
    file is hand-written and getting it wrong is expected.
    """
    base = from_directory or directory()
    checks: list[Check] = []
    problems: list[str] = []
    if not base.is_dir():
        return checks, problems

    for path in sorted(base.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            problems.append(f"{path.name}: {exc}")
            continue
        entries = raw if isinstance(raw, list) else [raw]
        for entry in entries:
            try:
                definition = parse(entry, source=str(path))
            except DefinitionError as exc:
                problems.append(f"{path.name}: {exc}")
                continue
            checks.append(build(definition))
    return checks, problems


def parse(raw: object, source: str = "") -> Definition:
    """Validate one dictionary into a Definition, or say exactly what is wrong."""
    if not isinstance(raw, dict):
        raise DefinitionError("each check must be a JSON object")

    def need(field: str) -> str:
        value = str(raw.get(field, "")).strip()
        if not value:
            raise DefinitionError(f"{field!r} is required")
        return value

    check_id = need("id")
    if not re.fullmatch(r"[a-z0-9]+(?:[.\-_][a-z0-9]+)*", check_id):
        raise DefinitionError(
            f"id {check_id!r} must be lowercase words joined by . - or _")

    kind = need("kind")
    if kind not in KINDS:
        raise DefinitionError(
            f"kind {kind!r} is not one of: {', '.join(KINDS)}")

    category = Category.parse(str(raw.get("category", "hardening")))
    if category is None:
        raise DefinitionError(
            f"category {raw.get('category')!r} is not one of: "
            + ", ".join(item.value for item in Category))

    pattern = str(raw.get("pattern", ""))
    if len(pattern) > MAX_PATTERN:
        raise DefinitionError(
            f"pattern is {len(pattern)} characters; the limit is {MAX_PATTERN}")
    if raw.get("regex") and pattern:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise DefinitionError(f"pattern is not a valid regex: {exc}") from exc

    expect = str(raw.get("expect", "present")).lower()
    if expect not in ("present", "absent"):
        raise DefinitionError("expect must be 'present' or 'absent'")

    compare = str(raw.get("compare", "eq")).lower()
    if compare not in ("eq", "ne", "ge", "le"):
        raise DefinitionError("compare must be one of: eq, ne, ge, le")

    mode = raw.get("mode", 0)
    if isinstance(mode, str):
        try:
            mode = int(mode, 8)
        except ValueError as exc:
            raise DefinitionError(f"mode {mode!r} is not an octal number") from exc

    definition = Definition(
        id=check_id,
        title=need("title"),
        kind=kind,
        category=category,
        severity=Severity.parse(str(raw.get("severity", "medium")), Severity.MEDIUM),
        summary=str(raw.get("summary", "")),
        impact=str(raw.get("impact", "")),
        path=str(raw.get("path", "")),
        key=str(raw.get("key", "")),
        unit=str(raw.get("unit", "")),
        parameter=str(raw.get("parameter", "")),
        pattern=pattern,
        regex=bool(raw.get("regex", False)),
        expect=expect,
        compare=compare,
        value=str(raw.get("value", "")),
        mode=int(mode),
        fix_title=str(raw.get("fix_title", "")),
        fix_command=str(raw.get("fix_command", "")),
        fix_explanation=str(raw.get("fix_explanation", "")),
        source_file=source,
    )
    _require_fields(definition)
    return definition


_REQUIRED = {
    "sysctl": ("key", "value"),
    "file_exists": ("path",),
    "file_mode": ("path",),
    "file_contains": ("path", "pattern"),
    "cmdline": ("parameter",),
    "unit_state": ("unit",),
}


def _require_fields(definition: Definition) -> None:
    """Name every missing field at once.

    Reporting them one at a time makes fixing a hand-written file a guessing
    game: you add `path`, save, and are told you also needed `pattern`.
    """
    missing = [field for field in _REQUIRED[definition.kind]
               if not getattr(definition, field)]
    if missing:
        names = " and ".join(repr(field) for field in missing)
        raise DefinitionError(f"a {definition.kind} check needs {names}")


# ---------------------------------------------------------------------------
# Turning one into a Check
# ---------------------------------------------------------------------------


def build(definition: Definition) -> Check:
    """Wrap a Definition in the same Check object the built-ins use."""

    def run(probe: Probe, policy: Policy) -> Iterator[Finding]:
        yield from evaluate(definition, probe, policy)

    return Check(
        id=definition.id,
        title=definition.title,
        category=definition.category,
        inspects=definition.describe(),
        function=run,
        worst=definition.severity,
        tags=frozenset({"custom"}),
    )


def evaluate(definition: Definition, probe: Probe,
             policy: Policy) -> Iterator[Finding]:
    """Run one custom check. Yields one finding, pass or fail."""
    satisfied, observed, evidence = _EVALUATORS[definition.kind](definition, probe)

    if satisfied:
        yield Finding(
            id=f"{definition.id}.ok",
            check_id=definition.id,
            category=definition.category,
            severity=Severity.PASS,
            title=definition.title,
            summary=definition.summary or "This site check is satisfied.",
            value=observed,
            evidence=evidence,
            tags=frozenset({"custom"}),
        )
        return

    fixes = ()
    if definition.fix_command or definition.fix_title:
        fixes = (Fix(
            title=definition.fix_title or "Suggested fix",
            explanation=definition.fix_explanation,
            command=definition.fix_command,
            recommended=True,
        ),)

    yield Finding(
        id=f"{definition.id}.failed",
        check_id=definition.id,
        category=definition.category,
        severity=definition.severity,
        title=definition.title,
        summary=definition.summary or "This site check is not satisfied.",
        impact=definition.impact or (
            f"Defined locally in {Path(definition.source_file).name}. "
            "ClamGuard has no opinion of its own about this one."),
        value=observed,
        evidence=evidence,
        fixes=fixes,
        tags=frozenset({"custom"}),
    )


def _eval_sysctl(definition: Definition, probe: Probe):
    raw = probe.sysctl(definition.key)
    evidence = (Evidence(f"/proc/sys/{definition.key.replace('.', '/')}",
                         raw or "(absent)", kind="sysfs"),)
    if not raw:
        raise SkipCheck(f"this kernel has no {definition.key}")
    try:
        actual, wanted = float(raw.split()[0]), float(definition.value)
        satisfied = {
            "eq": actual == wanted, "ne": actual != wanted,
            "ge": actual >= wanted, "le": actual <= wanted,
        }[definition.compare]
    except (ValueError, IndexError):
        satisfied = (raw.strip() == definition.value) == (definition.compare == "eq")
    return satisfied, raw.strip(), evidence


def _eval_file_exists(definition: Definition, probe: Probe):
    result = probe.file(definition.path)
    present = result.exists
    evidence = (Evidence(definition.path,
                         "present" if present else "no such file"),)
    return present == (definition.expect == "present"), \
        "present" if present else "absent", evidence


def _eval_file_mode(definition: Definition, probe: Probe):
    info = probe.stat(definition.path, follow=True)
    if info is None:
        raise SkipCheck(f"{definition.path} does not exist")
    actual = info.st_mode & 0o7777
    evidence = (Evidence(f"stat {definition.path}", f"mode {actual:04o}",
                         kind="computed"),)
    # Satisfied when the file grants nothing the allowed mode does not.
    return (actual & ~definition.mode) == 0, f"{actual:04o}", evidence


def _eval_file_contains(definition: Definition, probe: Probe):
    result = probe.file(definition.path)
    if not result.ok:
        raise SkipCheck(f"{definition.path}: {result.error or 'not readable'}")
    if definition.regex:
        found = re.search(definition.pattern, result.text, re.MULTILINE) is not None
    else:
        found = definition.pattern in result.text
    evidence = (Evidence(definition.path,
                         _matching_lines(result.text, definition) or
                         "(no matching line)"),)
    return found == (definition.expect == "present"), \
        "found" if found else "not found", evidence


def _matching_lines(text: str, definition: Definition, limit: int = 6) -> str:
    matched = []
    for line in text.splitlines():
        hit = (re.search(definition.pattern, line) if definition.regex
               else definition.pattern in line)
        if hit:
            matched.append(line.strip())
        if len(matched) >= limit:
            break
    return "\n".join(matched)


def _eval_cmdline(definition: Definition, probe: Probe):
    parameters = probe.cmdline_parameters()
    present = definition.parameter in parameters
    if present and definition.value:
        present = parameters[definition.parameter] == definition.value
    evidence = (Evidence("/proc/cmdline", probe.kernel_cmdline()),)
    observed = (f"{definition.parameter}={parameters[definition.parameter]}"
                if definition.parameter in parameters else "absent")
    return present == (definition.expect == "present"), observed, evidence


def _eval_unit_state(definition: Definition, probe: Probe):
    wanted = definition.value or "active"
    verb = "is-enabled" if wanted in ("enabled", "disabled") else "is-active"
    result = probe.run("systemctl", verb, definition.unit)
    observed = (result.stdout or result.stderr).strip() or "unknown"
    evidence = (Evidence(f"systemctl {verb} {definition.unit}", observed,
                         kind="command"),)
    return observed == wanted, observed, evidence


_EVALUATORS = {
    "sysctl": _eval_sysctl,
    "file_exists": _eval_file_exists,
    "file_mode": _eval_file_mode,
    "file_contains": _eval_file_contains,
    "cmdline": _eval_cmdline,
    "unit_state": _eval_unit_state,
}


#: Written into the checks directory the first time the user opens it, so
#: there is a working example to copy rather than a blank folder.
EXAMPLE = """\
[
  {
    "id": "site.ssh-no-root-login",
    "title": "SSH refuses root logins",
    "category": "hardening",
    "severity": "high",
    "kind": "file_contains",
    "path": "/etc/ssh/sshd_config",
    "pattern": "^PermitRootLogin\\\\s+no",
    "regex": true,
    "expect": "present",
    "summary": "Our baseline says root must never log in over SSH directly.",
    "impact": "A brute-force attempt against root needs no username guess.",
    "fix_title": "Set PermitRootLogin no",
    "fix_command": "sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload sshd"
  },
  {
    "id": "site.firewall-running",
    "title": "The firewall is running",
    "category": "services",
    "severity": "high",
    "kind": "unit_state",
    "unit": "firewalld.service",
    "value": "active",
    "summary": "This machine should never be on a network without a firewall."
  }
]
"""


def write_example(target: Path | None = None) -> Path:
    """Create the checks directory with one worked example inside."""
    base = target or directory()
    base.mkdir(parents=True, exist_ok=True)
    sample = base / "example.json"
    if not sample.exists():
        sample.write_text(EXAMPLE, encoding="utf-8")
    return sample
