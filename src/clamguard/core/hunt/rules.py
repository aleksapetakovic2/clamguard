"""Analytics rules: a KQL query, a threshold, and what it means if it fires.

The query editor answers questions you thought to ask. This answers the ones
you did not. A rule is nothing but a query plus a threshold plus an
explanation, which has two consequences worth stating plainly:

* **A rule cannot do anything a query cannot do.** There is no code in a rule.
  It cannot run a command, write a file or reach the network, because the
  engine it runs on cannot. That is what makes it safe to let the user write
  their own, in ``~/.config/clamguard/hunt-rules.d/*.json``.
* **Every finding is reproducible.** The query is shown next to the result, so
  "Hunt says X" is always one click away from "here is exactly why", and a
  rule you disagree with can be edited rather than argued with.

The risk levels are deliberately parallel to the Boot Analyzer's severities
without being the same type: the two features have no reason to be coupled,
and a shared enum would make one page's vocabulary change the other's.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Iterable

from .. import paths
from ..logging_setup import get_logger
from .model import ResultTable, TimeRange

log = get_logger(__name__)

#: Where user-written rules live.
RULES_DIRECTORY = paths.CONFIG_DIR / "hunt-rules.d"

#: How many evidence rows a finding keeps.
EVIDENCE_ROWS = 25


class Risk(IntEnum):
    """How much a finding is worth looking at."""

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40

    @property
    def label(self) -> str:
        return {Risk.INFO: "Worth knowing", Risk.LOW: "Low",
                Risk.MEDIUM: "Medium", Risk.HIGH: "High"}[self]

    @property
    def tone(self) -> str:
        return {Risk.INFO: "info", Risk.LOW: "muted",
                Risk.MEDIUM: "warn", Risk.HIGH: "danger"}[self]

    @property
    def icon(self) -> str:
        return {Risk.INFO: "info", Risk.LOW: "info",
                Risk.MEDIUM: "alert-triangle", Risk.HIGH: "alert-circle"}[self]

    @classmethod
    def parse(cls, text: Any) -> "Risk":
        if isinstance(text, Risk):
            return text
        word = str(text).strip().lower()
        return {"info": cls.INFO, "informational": cls.INFO, "low": cls.LOW,
                "medium": cls.MEDIUM, "moderate": cls.MEDIUM,
                "high": cls.HIGH, "critical": cls.HIGH}.get(word, cls.LOW)


@dataclass(frozen=True, slots=True)
class Rule:
    """One thing Hunt checks for."""

    id: str
    title: str
    question: str
    query: str
    risk: Risk = Risk.LOW
    #: Fires when the query returns at least this many rows.
    minimum_rows: int = 1
    #: What it means, in a sentence or two.
    explanation: str = ""
    #: What to do about it, when there is something to do.
    advice: str = ""
    category: str = "General"
    #: True for rules loaded from the user's own directory.
    custom: bool = False
    #: Which column, if any, holds the count that makes the headline.
    count_column: str = ""

    @property
    def source(self) -> str:
        return "yours" if self.custom else "built in"


@dataclass(slots=True)
class Finding:
    """One rule that fired, with the rows that made it fire."""

    rule: Rule
    rows: int = 0
    table: ResultTable | None = None
    headline: str = ""
    elapsed: float = 0.0
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    def evidence(self) -> list[tuple]:
        return list(self.table.rows[:EVIDENCE_ROWS]) if self.table else []

    def columns(self) -> tuple:
        return self.table.columns if self.table else ()


@dataclass(slots=True)
class Review:
    """A whole pass over the rule set."""

    findings: list[Finding] = field(default_factory=list)
    checked: int = 0
    elapsed: float = 0.0
    range: TimeRange | None = None
    problems: list[str] = field(default_factory=list)

    @property
    def fired(self) -> list[Finding]:
        return sorted((item for item in self.findings if item.rows and item.ok),
                      key=lambda item: (-int(item.rule.risk), -item.rows))

    @property
    def quiet(self) -> list[Finding]:
        return [item for item in self.findings if not item.rows and item.ok]

    @property
    def failed(self) -> list[Finding]:
        return [item for item in self.findings if item.error]

    @property
    def worst(self) -> Risk | None:
        fired = self.fired
        return max((item.rule.risk for item in fired), default=None)

    def summary(self) -> str:
        fired = self.fired
        if not fired:
            return (f"Nothing stood out. {self.checked} rules ran against "
                    f"{(self.range.describe().lower() if self.range else 'the index')}.")
        counts: dict[Risk, int] = {}
        for item in fired:
            counts[item.rule.risk] = counts.get(item.rule.risk, 0) + 1
        parts = [f"{count} {risk.label.lower()}"
                 for risk, count in sorted(counts.items(), reverse=True)]
        return f"{len(fired)} of {self.checked} rules matched: " + ", ".join(parts)


# ---------------------------------------------------------------------------
# The built-in rules
# ---------------------------------------------------------------------------

BUILT_IN: tuple[Rule, ...] = (
    Rule(
        id="shell-pipeline",
        title="A download was piped straight into a shell",
        question="Did anything run `curl … | sh`?",
        risk=Risk.HIGH,
        category="Execution",
        # `has` matches whole terms and throws punctuation away, so
        # has_any("| sh") is really has_any("sh") — and has_any("| python")
        # matched every pacman line that mentioned a python package. The pipe
        # patterns have to be `contains`, which is punctuation-exact.
        query='Logs\n| where Message has_any ("curl", "wget")\n'
              '| where Message contains "| sh" or Message contains "|sh"\n'
              '      or Message contains "| bash" or Message contains "|bash"\n'
              '      or Message contains "| python" or Message contains "|python"\n'
              '      or Message contains "bash -c" or Message contains "sh -c"\n'
              "| project Timestamp, App, Message, Source\n"
              "| sort by Timestamp desc\n| take 100",
        explanation="Fetching a script and executing it in one step means "
                    "whatever was at that address ran with your privileges, "
                    "with nothing in between to look at it.",
        advice="Check the address it fetched from. If you ran an installer "
               "this way yourself, it is probably what you meant to do; if "
               "you did not, this is worth tracing."),
    Rule(
        id="encoded-payload",
        title="Encoded or obfuscated commands",
        question="Is anything hiding a command inside Base64?",
        risk=Risk.MEDIUM,
        category="Execution",
        query='Logs\n| where Message has_any ("base64 -d", "base64 --decode",\n'
              '                            "-EncodedCommand", "FromBase64String",\n'
              '                            "eval(atob", "echo | base64")\n'
              "| project Timestamp, App, Message, Source\n"
              "| sort by Timestamp desc\n| take 100",
        explanation="Encoding a command is not itself suspicious — plenty of "
                    "tools do it — but it is how a command avoids being read "
                    "by whoever looks at the log afterwards.",
        advice="Decode it: `base64_decode_tostring()` works inside a query."),
    Rule(
        id="crash-cluster",
        title="Something is crashing repeatedly",
        question="Has the same program crashed more than a few times?",
        risk=Risk.MEDIUM,
        category="Stability",
        count_column="Crashes",
        query='Logs\n| where Message has_any ("segfault", "SIGSEGV", "SIGABRT",\n'
              '                            "core dumped", "panic", "Fatal Error",\n'
              '                            "has crashed", "abnormal termination")\n'
              "| summarize Crashes = count(), Last = max(Timestamp),\n"
              "            Sample = any(Message) by App\n"
              "| where Crashes >= 3\n| sort by Crashes desc",
        explanation="A program that crashes once had a bad day. A program "
                    "that crashes repeatedly is either broken or being made "
                    "to crash.",
        advice="Look at the sample message, then query that application's "
               "own log around the time in Last."),
    Rule(
        id="auth-failures",
        title="Repeated authentication failures",
        question="Is something failing to authenticate over and over?",
        risk=Risk.MEDIUM,
        category="Access",
        count_column="Failures",
        query='Logs\n| where Message has_any ("authentication failure",\n'
              '                            "authentication failed", "login failed",\n'
              '                            "invalid password", "permission denied",\n'
              '                            "access denied", "unauthorized")\n'
              "| summarize Failures = count(), First = min(Timestamp),\n"
              "            Last = max(Timestamp) by App\n"
              "| where Failures >= 5\n| sort by Failures desc",
        explanation="A handful of failures is a mistyped password. A run of "
                    "them in a short window is something trying repeatedly.",
        advice="Check whether the failures cluster in time; if they do, look "
               "at what was running then."),
    Rule(
        id="error-storm",
        title="An error storm",
        question="Is one message being written hundreds of times?",
        risk=Risk.LOW,
        category="Stability",
        count_column="Count",
        query="Logs\n| where Level in (\"error\", \"critical\")\n"
              "| extend Template = replace_regex(Message, @\"\\d+\", \"N\")\n"
              "| summarize Count = count(), Apps = dcount(App),\n"
              "            Last = max(Timestamp) by Template\n"
              "| where Count >= 500\n| sort by Count desc\n| take 20",
        explanation="One message repeated hundreds of times is filling the "
                    "log and hiding everything else in it.",
        advice="Fix it or filter it. Either way it is the reason the rest of "
               "the log is hard to read."),
    Rule(
        id="new-log-sources",
        title="Log files that appeared in the last week",
        question="Is anything writing logs that was not here before?",
        risk=Risk.INFO,
        category="Change",
        count_column="",
        query="Sources\n| where FirstSeen > ago(7d)\n"
              "| project FirstSeen, App, Path, Format, Events\n"
              "| sort by FirstSeen desc\n| take 50",
        explanation="A new log file belongs to something new: an application "
                    "you installed, an update that changed where it writes, "
                    "or something you did not put there.",
        advice="Recognise the names. Anything you do not recognise is worth "
               "a look at the file itself."),
    Rule(
        id="disk-and-memory",
        title="The machine ran out of something",
        question="Did anything report being out of memory or disk?",
        risk=Risk.MEDIUM,
        category="Resources",
        count_column="Count",
        query='Logs\n| where Message has_any ("no space left", "disk full",\n'
              '                            "out of memory", "cannot allocate",\n'
              '                            "ENOSPC", "ENOMEM", "oom-kill")\n'
              "| summarize Count = count(), Last = max(Timestamp),\n"
              "            Sample = any(Message) by App\n| sort by Count desc",
        explanation="Resource exhaustion looks like a dozen unrelated "
                    "failures unless you go looking for the cause directly.",
        advice="Check free space and memory. The failures around the same "
               "time are probably consequences, not separate problems."),
    Rule(
        id="external-addresses",
        title="Connections to addresses outside your network",
        question="Which public addresses appear in the logs?",
        risk=Risk.INFO,
        category="Network",
        count_column="Count",
        query='Logs\n| where Message matches regex @"\\b\\d{1,3}(\\.\\d{1,3}){3}\\b"\n'
              '| extend Address = extract(@"\\b(\\d{1,3}(?:\\.\\d{1,3}){3})\\b", 1, Message)\n'
              "| where isnotempty(Address) and not(ipv4_is_private(Address))\n"
              "| summarize Count = count(), Apps = make_set(App, 8),\n"
              "            Last = max(Timestamp) by Address\n"
              "| sort by Count desc\n| take 40",
        explanation="Addresses in a log are usually the machine's own "
                    "traffic. Private ranges are filtered out, so what is "
                    "left is where it went on the internet.",
        advice="Most of these will be services you use. One you do not "
               "recognise, mentioned by an application that has no business "
               "talking to it, is the interesting case."),
    Rule(
        id="privilege-use",
        title="Privilege escalation tools were used",
        question="Did anything ask for root?",
        risk=Risk.LOW,
        category="Access",
        count_column="Count",
        query='Logs\n| where Message has_any ("sudo", "pkexec", "polkit",\n'
              '                            "gained root", "setuid")\n'
              "| summarize Count = count(), Last = max(Timestamp),\n"
              "            Sample = any(Message) by App\n| sort by Count desc\n| take 30",
        explanation="Normal on a desktop — a package manager, a polkit "
                    "prompt. Worth reading because the unexpected entry in "
                    "this list is the one that matters.",
        advice="Match each application against something you did."),
    Rule(
        id="log-gap",
        title="A log stopped and started again",
        question="Did a busy log go silent for hours?",
        risk=Risk.LOW,
        category="Change",
        query="Logs\n| where isnotnull(Timestamp)\n"
              "| summarize Events = count() by Source, Hour = bin(Timestamp, 1h)\n"
              "| where Events > 5\n| sort by Source asc, Hour asc\n| serialize\n"
              "| extend Gap = iif(prev(Source) == Source,\n"
              "                   Hour - prev(Hour), totimespan(0))\n"
              "| where Gap > 12h\n"
              "| project Source, Resumed = Hour, Gap\n"
              "| sort by Gap desc\n| take 25",
        explanation="Usually the machine was switched off. Occasionally it "
                    "means a log was truncated, which is what somebody does "
                    "after doing something they do not want read.",
        advice="Compare the gap against when the machine was actually "
               "running. The Boot Analyzer's timeline knows that."),
    Rule(
        id="unreadable-growth",
        title="A log file is growing unusually fast",
        question="Is one file taking over the index?",
        risk=Risk.INFO,
        category="Resources",
        count_column="Events",
        query="Sources\n| where Events > 0\n"
              "| extend PerMegabyte = Events * 1000000 / max_of(Bytes, 1)\n"
              "| project App, Path, Events, Bytes, PerMegabyte\n"
              "| sort by Events desc\n| take 10",
        explanation="The files producing the most events. Not a problem by "
                    "itself, but it is where your retention budget goes.",
        advice="Turn a source off in the Sources dialog if it is noise."),
    Rule(
        id="clamav-detections",
        title="ClamAV found something",
        question="Has the scanner flagged a file?",
        risk=Risk.HIGH,
        category="ClamAV",
        count_column="Count",
        query="Detections\n"
              "| summarize Count = count(), Last = max(Detected),\n"
              "            Paths = make_set(Path, 10) by Threat\n"
              "| sort by Last desc\n| take 25",
        explanation="Straight from ClamGuard's own history. A detection that "
                    "is still 'reported' rather than quarantined is still on "
                    "the disk.",
        advice="The Quarantine page is where these are dealt with."),
    Rule(
        id="odd-hours",
        title="Activity while you were probably asleep",
        question="What happened between 01:00 and 05:00?",
        risk=Risk.INFO,
        category="Change",
        count_column="Events",
        query="Logs\n| where isnotnull(Timestamp)\n"
              "| extend Hour = hourofday(Timestamp)\n"
              "| where Hour >= 1 and Hour <= 5\n"
              "| summarize Events = count(), Apps = dcount(App)\n"
              "         by Day = startofday(Timestamp)\n"
              "| where Events > 200\n| sort by Events desc\n| take 20",
        explanation="Times are UTC. Scheduled updates and backups live here "
                    "legitimately; so does anything that waited until you "
                    "were not watching.",
        advice="Adjust the hours to your own time zone, then look at which "
               "applications were awake."),
    Rule(
        id="certificate-and-tls",
        title="Certificate and TLS failures",
        question="Did any connection fail to verify?",
        risk=Risk.MEDIUM,
        category="Network",
        count_column="Count",
        query='Logs\n| where Message has_any ("certificate verify failed",\n'
              '                            "SSL_ERROR", "TLS handshake",\n'
              '                            "self signed certificate",\n'
              '                            "certificate has expired",\n'
              '                            "unable to get local issuer")\n'
              "| summarize Count = count(), Last = max(Timestamp),\n"
              "            Sample = any(Message) by App\n| sort by Count desc\n| take 25",
        explanation="Usually an expired certificate or a captive portal. It "
                    "is also exactly what a connection being intercepted "
                    "looks like.",
        advice="If it is one application and one address, check that address "
               "from another machine."),
    Rule(
        id="persistence-words",
        title="Mentions of things that start automatically",
        question="Did anything write about autostart, cron or systemd units?",
        risk=Risk.LOW,
        category="Execution",
        count_column="Count",
        # ".desktop" is `contains` rather than `has_any` for the same reason:
        # as a term it is just "desktop", which every window manager writes
        # several hundred times an hour.
        query='Logs\n| where Message has_any ("crontab", "systemd --user",\n'
              '                            "autostart", "enable --now",\n'
              '                            "systemctl enable", "ld.so.preload")\n'
              '      or Message contains ".desktop"\n'
              "| summarize Count = count(), Last = max(Timestamp),\n"
              "            Sample = any(Message) by App\n| sort by Count desc\n| take 25",
        explanation="Persistence is the step after a compromise: making sure "
                    "the thing comes back. The Boot Analyzer inspects the "
                    "actual entries; this finds the moment one was created.",
        advice="Cross-check anything unexpected against the Boot Analyzer's "
               "Startup surface tab."),
    Rule(
        id="mass-file-errors",
        title="A burst of file errors",
        question="Did something fail to read or write a lot of files at once?",
        risk=Risk.LOW,
        category="Stability",
        count_column="Count",
        query='Logs\n| where Message has_any ("No such file or directory",\n'
              '                            "Input/output error", "Read-only file system",\n'
              '                            "Structure needs cleaning", "EIO")\n'
              "| summarize Count = count(), Last = max(Timestamp) by App\n"
              "| where Count >= 50\n| sort by Count desc",
        explanation="Input/output errors in bulk usually mean failing "
                    "hardware. The rest usually mean a path changed.",
        advice="If it is I/O errors, check the disk before anything else."),
)


# ---------------------------------------------------------------------------
# User rules
# ---------------------------------------------------------------------------

_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

REQUIRED_FIELDS = ("id", "title", "query")


class RuleError(ValueError):
    """A user-written rule file that could not be read."""


def parse_rule(data: Any, origin: str = "") -> Rule:
    """Turn one JSON object into a Rule, or say exactly what is wrong."""
    where = f" in {origin}" if origin else ""
    if not isinstance(data, dict):
        raise RuleError(f"A rule{where} has to be a JSON object.")

    missing = [name for name in REQUIRED_FIELDS if not str(data.get(name, "")).strip()]
    if missing:
        raise RuleError(f"The rule{where} is missing "
                        + ", ".join(f"'{name}'" for name in missing) + ".")

    identifier = str(data["id"]).strip().lower()
    if not _ID.match(identifier):
        raise RuleError(f"'{identifier}'{where} is not a usable id — use "
                        "lowercase letters, digits, hyphens and underscores.")

    minimum = data.get("minimum_rows", data.get("threshold", 1))
    if not isinstance(minimum, (int, float)) or isinstance(minimum, bool):
        minimum = 1

    return Rule(
        id=identifier,
        title=str(data["title"]).strip()[:200],
        question=str(data.get("question") or "")[:300],
        query=str(data["query"])[:20_000],
        risk=Risk.parse(data.get("risk", "low")),
        minimum_rows=max(1, int(minimum)),
        explanation=str(data.get("explanation") or "")[:2000],
        advice=str(data.get("advice") or "")[:2000],
        category=str(data.get("category") or "Yours")[:80],
        count_column=str(data.get("count_column") or "")[:80],
        custom=True,
    )


def load_custom(directory: Path | None = None) -> tuple[list[Rule], list[str]]:
    """Read every rule file the user has written. Never raises."""
    folder = directory or RULES_DIRECTORY
    rules: list[Rule] = []
    problems: list[str] = []
    if not folder.is_dir():
        return rules, problems

    for path in sorted(folder.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            problems.append(f"{path.name}: {error}")
            continue
        entries = payload if isinstance(payload, list) else [payload]
        if isinstance(payload, dict) and isinstance(payload.get("rules"), list):
            entries = payload["rules"]
        for entry in entries:
            try:
                rules.append(parse_rule(entry, path.name))
            except RuleError as error:
                problems.append(str(error))
    return rules, problems


def catalogue(directory: Path | None = None) -> tuple[list[Rule], list[str]]:
    """Every rule: the built-in set plus the user's, the user's winning ties."""
    custom, problems = load_custom(directory)
    by_id: dict[str, Rule] = {rule.id: rule for rule in BUILT_IN}
    for rule in custom:
        by_id[rule.id] = rule
    return list(by_id.values()), problems


EXAMPLE_RULE = """\
{
  "id": "my-first-rule",
  "title": "Something I care about",
  "question": "Did the thing I care about happen?",
  "risk": "medium",
  "category": "Yours",
  "query": "Logs\\n| where Message has \\"the thing\\"\\n| summarize Count = count() by App\\n| sort by Count desc",
  "minimum_rows": 1,
  "count_column": "Count",
  "explanation": "What it means when this matches.",
  "advice": "What to do about it."
}
"""


def write_example(directory: Path | None = None) -> Path:
    """Drop a commented example into the rules directory and return its path."""
    folder = directory or RULES_DIRECTORY
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / "example.json"
    if not target.exists():
        target.write_text(EXAMPLE_RULE, encoding="utf-8")
    readme = folder / "README.txt"
    if not readme.exists():
        readme.write_text(
            "Rules in this directory are run by ClamGuard's Hunt page.\n\n"
            "A rule is a JSON object with an id, a title and a KQL query.\n"
            "It fires when the query returns at least `minimum_rows` rows.\n\n"
            "A rule cannot run a command, write a file or make a network\n"
            "request: it is a query, and the query engine can only read the\n"
            "local log index. That is deliberate.\n\n"
            "Fields:\n"
            "  id            lowercase name, unique\n"
            "  title         one line, shown as the heading\n"
            "  question      the question it answers\n"
            "  query         KQL\n"
            "  risk          info | low | medium | high\n"
            "  minimum_rows  how many rows count as a match (default 1)\n"
            "  count_column  a column whose value goes in the headline\n"
            "  explanation   what a match means\n"
            "  advice        what to do about it\n"
            "  category      how it is grouped in the list\n",
            encoding="utf-8")
    return target


# ---------------------------------------------------------------------------
# Running them
# ---------------------------------------------------------------------------


def evaluate(rules: Iterable[Rule], connection, *, options=None,
             on_progress=None, should_stop=None) -> Review:
    """Run every rule and collect what fired.

    Each rule is run on its own and a failure is recorded against that rule
    rather than abandoning the pass: one bad user-written query must not cost
    you the other twenty.
    """
    import time

    from .kql import KqlError
    from .kql.engine import Options, run as run_query

    options = options or Options()
    review = Review(range=options.time_range)
    started = time.monotonic()
    items = list(rules)

    for index, rule in enumerate(items, start=1):
        if should_stop is not None and should_stop():
            break
        review.checked += 1
        began = time.monotonic()
        finding = Finding(rule=rule)
        try:
            table = run_query(rule.query, connection, options)
        except KqlError as error:
            finding.error = str(error)
        except Exception as error:  # noqa: BLE001 - one rule must not stop a pass
            log.exception("hunt rule %s failed", rule.id)
            finding.error = str(error)
        else:
            finding.table = table
            finding.rows = len(table.rows)
            if finding.rows < rule.minimum_rows:
                finding.rows = 0
            finding.headline = _headline(rule, table, finding.rows)
        finding.elapsed = time.monotonic() - began
        review.findings.append(finding)
        if on_progress is not None:
            on_progress(index, len(items), rule.title)

    review.elapsed = time.monotonic() - started
    return review


def _headline(rule: Rule, table: ResultTable, rows: int) -> str:
    """``3 applications, 412 events`` — the line under a finding's title."""
    if not rows:
        return "Nothing matched."
    plural = "" if rows == 1 else "s"
    if rule.count_column:
        position = table.index_of(rule.count_column)
        if position >= 0:
            total = 0
            for row in table.rows:
                value = row[position]
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    total += value
            if total:
                name = rule.count_column.lower()
                unit = "in total" if name in ("count", "events", "total") \
                    else name
                return f"{rows} result{plural}, {int(total):,} {unit}"
    return f"{rows} result{plural}"
