"""The queries that ship with Hunt, grouped the way the left rail lists them.

These exist for two reasons. The obvious one is that a query language with an
empty editor is a wall; the first ten minutes of Sentinel are spent reading
other people's queries. The less obvious one is that they are *tests*:
``tests/test_hunt_library.py`` parses and runs every single one against a
synthetic store, so a change to the parser or the function library that breaks
a real query breaks the build.

Each entry says what question it answers, not what it does. "Errors in the
last day, by application" is a question; "summarize count() by App" is not.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Example:
    """One query in the library."""

    id: str
    name: str
    category: str
    text: str
    description: str = ""
    #: True for the handful that are worth showing on an empty page.
    starter: bool = False

    @property
    def one_line(self) -> str:
        return " ".join(self.text.split())


CATEGORIES: tuple[str, ...] = (
    "Getting started",
    "Errors and failures",
    "Security",
    "Applications",
    "Volume and timing",
    "The index itself",
    "The journal",
    "ClamAV",
)


LIBRARY: tuple[Example, ...] = (
    # -- Getting started ---------------------------------------------------
    Example(
        "recent", "Everything, newest first", "Getting started",
        "Logs\n| where isnotnull(Timestamp)\n| sort by Timestamp desc\n| take 200",
        "The plain view. Start here and add filters.", starter=True),
    Example(
        "recent-errors", "Errors and worse, newest first", "Getting started",
        'Logs\n| where Level in ("error", "critical")\n'
        "| sort by Timestamp desc\n| project Timestamp, Level, App, Message\n| take 200",
        "Anything an application called an error.", starter=True),
    Example(
        "by-app", "Which applications are the noisiest", "Getting started",
        "Logs\n| summarize Events = count() by App\n| sort by Events desc",
        "How the index is made up.", starter=True),
    Example(
        "search-text", "Find a word anywhere", "Getting started",
        'search "segfault"\n| sort by Timestamp desc\n| take 100',
        "A bare search goes through the full-text index, so it is fast even "
        "over millions of lines.", starter=True),
    Example(
        "timechart", "Events per hour", "Getting started",
        "Logs\n| where isnotnull(Timestamp)\n"
        "| summarize Events = count() by bin(Timestamp, 1h)\n"
        "| sort by Timestamp asc\n| render timechart",
        "The shape of the day.", starter=True),

    # -- Errors and failures ----------------------------------------------
    Example(
        "error-rate", "Error rate per application", "Errors and failures",
        'Logs\n| summarize Total = count(), Errors = countif(Level in ("error", "critical"))\n'
        "         by App\n"
        "| extend Percent = round(100.0 * Errors / Total, 1)\n"
        "| where Total > 50\n| sort by Percent desc",
        "Not who writes the most errors — who writes the highest proportion "
        "of them."),
    Example(
        "error-storms", "The same error over and over", "Errors and failures",
        'Logs\n| where Level in ("error", "critical")\n'
        "| extend Template = replace_regex(Message, @\"\\d+\", \"N\")\n"
        "| summarize Count = count(), Apps = dcount(App), First = min(Timestamp),\n"
        "            Last = max(Timestamp) by Template\n"
        "| where Count > 20\n| sort by Count desc\n| take 50",
        "Numbers are stripped out so that the same message with different "
        "ids, ports and pids collapses into one row."),
    Example(
        "crashes", "Crashes, panics and fatal errors", "Errors and failures",
        'Logs\n| where Message has_any ("segfault", "SIGSEGV", "SIGABRT", "core dumped",\n'
        '                            "panic", "fatal", "assertion failed",\n'
        '                            "unhandled exception", "Traceback")\n'
        "| sort by Timestamp desc\n"
        "| project Timestamp, App, Level, Message, Source\n| take 200",
        "The words that mean a program stopped rather than complained."),
    Example(
        "out-of-memory", "Out of memory and disk full", "Errors and failures",
        'Logs\n| where Message has_any ("out of memory", "oom", "cannot allocate",\n'
        '                            "no space left", "disk full", "ENOSPC", "ENOMEM")\n'
        "| sort by Timestamp desc\n| project Timestamp, App, Message\n| take 100",
        "Resource exhaustion, which shows up as a dozen unrelated failures "
        "if you do not look for it directly."),
    Example(
        "first-seen", "Messages that have never appeared before", "Errors and failures",
        'let recent = 1d;\n'
        "Logs\n| where isnotnull(Timestamp)\n"
        "| extend Template = replace_regex(Message, @\"[0-9a-fA-F]{6,}|\\d+\", \"*\")\n"
        "| summarize First = min(Timestamp), Count = count(), Sample = any(Message)\n"
        "         by Template, App\n"
        "| where First > ago(recent)\n| sort by Count desc\n| take 100",
        "Novelty detection. A message whose first appearance is recent is "
        "either a new version or a new problem."),
    Example(
        "failed-units", "systemd and service failures", "Errors and failures",
        'Logs\n| where Message has_any ("Failed to start", "Failed with result",\n'
        '                            "entered failed state", "Start request repeated")\n'
        "| sort by Timestamp desc\n| project Timestamp, App, Message\n| take 100",
        "Written to whatever log the service manager was using."),

    # -- Security ----------------------------------------------------------
    Example(
        "auth-failures", "Authentication failures", "Security",
        'Logs\n| where Message has_any ("authentication failure", "auth fail",\n'
        '                            "permission denied", "unauthorized", "401",\n'
        '                            "invalid password", "login failed",\n'
        '                            "access denied", "forbidden")\n'
        "| sort by Timestamp desc\n"
        "| project Timestamp, App, Message, Source\n| take 200",
        "Across every application at once, which is the thing no single "
        "application's log can show you."),
    Example(
        "shell-pipelines", "Downloads piped into a shell", "Security",
        'Logs\n| where Message has_any ("curl", "wget")\n'
        '| where Message contains "| sh" or Message contains "|sh"\n'
        '      or Message contains "| bash" or Message contains "|bash"\n'
        '      or Message contains "bash -c" or Message contains "sh -c"\n'
        "| sort by Timestamp desc\n| project Timestamp, App, Message, Source",
        "The single most common installation instruction on the internet, "
        "and the single most common way a machine is compromised. Note the "
        "second filter uses `contains` rather than `has`: `has` matches whole "
        "words and would read \"| sh\" as just \"sh\"."),
    Example(
        "encoded-commands", "Base64 and encoded payloads", "Security",
        'Logs\n| where Message has_any ("base64", "EncodedCommand",\n'
        '                            "FromBase64String", "atob")\n'
        "         or (strlen(Message) > 120 and entropy(Message) > 5.0)\n"
        "| project Timestamp, App, Entropy = round(entropy(Message), 2), Message\n"
        "| sort by Entropy desc\n| take 100",
        "High entropy means the text is random or encoded. Most log lines "
        "sit near 4; a Base64 blob sits above 5."),
    Example(
        "network-addresses", "Every address mentioned in the logs", "Security",
        'Logs\n| where Message matches regex @"\\b\\d{1,3}(\\.\\d{1,3}){3}\\b"\n'
        '| extend Address = extract(@"\\b(\\d{1,3}(?:\\.\\d{1,3}){3})\\b", 1, Message)\n'
        "| where isnotempty(Address) and not(ipv4_is_private(Address))\n"
        "| summarize Count = count(), Apps = make_set(App), Last = max(Timestamp)\n"
        "         by Address\n| sort by Count desc\n| take 100",
        "Private ranges are dropped, so what is left is the machine talking "
        "to the outside world."),
    Example(
        "urls", "Every URL mentioned in the logs", "Security",
        'Logs\n| where Message contains "://"\n'
        '| extend Url = extract(@"(https?://[^\\s<>)\\]]+)", 1, Message)\n'
        "| where isnotempty(Url)\n"
        "| extend Host = tostring(parse_url(Url).Host)\n"
        "| summarize Count = count(), Apps = make_set(App, 10) by Host\n"
        "| sort by Count desc\n| take 100",
        "Grouped by host, so a hundred requests to one place is one row."),
    Example(
        "sudo-and-privilege", "Privilege escalation", "Security",
        'Logs\n| where Message has_any ("sudo", "pkexec", "polkit", "setuid",\n'
        '                            "root privileges", "CAP_SYS_ADMIN")\n'
        "| sort by Timestamp desc\n| project Timestamp, App, Message, Source\n| take 200",
        "Every use of a privilege-raising tool that anything wrote down."),
    Example(
        "odd-hours", "Activity in the middle of the night", "Security",
        "Logs\n| where isnotnull(Timestamp)\n"
        "| extend Hour = hourofday(Timestamp)\n"
        "| where Hour >= 1 and Hour <= 5\n"
        "| summarize Events = count() by App, Day = startofday(Timestamp)\n"
        "| sort by Events desc\n| take 100",
        "Times are shown in UTC. Adjust the hours to your own time zone."),
    Example(
        "new-sources", "Log files that appeared recently", "Security",
        "Sources\n| where FirstSeen > ago(7d)\n"
        "| project FirstSeen, App, Path, Format, Events\n| sort by FirstSeen desc",
        "A log file that was not there last week belongs to something that "
        "was not there last week."),
    Example(
        "gaps", "Gaps where a log stopped being written", "Security",
        "Logs\n| where isnotnull(Timestamp)\n"
        "| summarize Events = count() by Source, Hour = bin(Timestamp, 1h)\n"
        "| sort by Source asc, Hour asc\n| serialize\n"
        "| extend Gap = iif(prev(Source) == Source, Hour - prev(Hour), totimespan(0))\n"
        "| where Gap > 6h\n"
        "| project Source, Resumed = Hour, Gap\n| sort by Gap desc\n| take 50",
        "A log that goes quiet for hours and then comes back either means "
        "the machine was off, or means something truncated it."),

    # -- Applications ------------------------------------------------------
    Example(
        "one-app", "Everything one application wrote", "Applications",
        'Logs\n| where App == "discord"\n| sort by Timestamp desc\n'
        "| project Timestamp, Level, Message\n| take 300",
        "Change the name. The Tables list on the left has all of them."),
    Example(
        "app-levels", "Level breakdown per application", "Applications",
        "Logs\n| summarize Events = count() by App, Level\n"
        "| sort by App asc, Events desc",
        "Which applications actually use log levels and which ones write "
        "everything at the same one."),
    Example(
        "app-first-last", "When each application last said anything",
        "Applications",
        "Logs\n| where isnotnull(Timestamp)\n"
        "| summarize First = min(Timestamp), Last = max(Timestamp), Events = count()\n"
        "         by App\n"
        "| extend Silent = now() - Last\n| sort by Last desc",
        "An application that has been silent for a long time either is not "
        "running or has stopped writing."),
    Example(
        "chatty-files", "The files producing the most lines", "Applications",
        "Logs\n| summarize Events = count() by Source\n"
        "| sort by Events desc\n| take 40",
        "Useful before turning retention down: these are where the space is "
        "going."),
    Example(
        "extra-fields", "What extra fields a format carries", "Applications",
        'Logs\n| where isnotnull(Extra)\n| take 2000\n'
        "| mv-expand Field = bag_keys(Extra)\n"
        "| summarize Count = count() by Format, Field = tostring(Field)\n"
        "| sort by Count desc",
        "Which structured fields are available to filter on, per format."),

    # -- Volume and timing -------------------------------------------------
    Example(
        "per-day", "Events per day", "Volume and timing",
        "Logs\n| where isnotnull(Timestamp)\n"
        "| summarize Events = count() by Day = bin(Timestamp, 1d)\n"
        "| sort by Day asc\n| render columnchart",
        "The long view."),
    Example(
        "errors-over-time", "Errors over time, by application",
        "Volume and timing",
        'Logs\n| where Level in ("error", "critical") and isnotnull(Timestamp)\n'
        "| summarize Errors = count() by App, Hour = bin(Timestamp, 1h)\n"
        "| sort by Hour asc\n| render timechart",
        "One line per application."),
    Example(
        "busiest-hours", "Which hour of the day is busiest",
        "Volume and timing",
        "Logs\n| where isnotnull(Timestamp)\n"
        "| summarize Events = count() by Hour = hourofday(Timestamp)\n"
        "| sort by Hour asc\n| render columnchart",
        "In UTC."),
    Example(
        "spikes", "Hours with far more events than usual",
        "Volume and timing",
        "Logs\n| where isnotnull(Timestamp)\n"
        "| summarize Events = count() by Hour = bin(Timestamp, 1h)\n"
        "| sort by Hour asc\n| serialize\n"
        "| extend Change = Events - prev(Events, 1, 0)\n"
        "| where Events > 1000 and Change > 0\n"
        "| sort by Change desc\n| take 30",
        "A crude spike detector: hours that are both busy and busier than "
        "the hour before them."),
    Example(
        "level-share", "How much of the index is each level",
        "Volume and timing",
        "Logs\n| summarize Events = count() by Level\n"
        "| sort by Events desc\n| render piechart",
        "A lot of formats do not record a level at all; those land in "
        "'unknown' rather than being guessed at."),

    # -- The index itself --------------------------------------------------
    Example(
        "sources-list", "Every indexed file", "The index itself",
        "Sources\n| project App, Path, Format, Confidence, Events, Bytes, LastIndexed\n"
        "| sort by Events desc",
        "What Hunt is actually reading."),
    Example(
        "format-breakdown", "Which formats were recognised", "The index itself",
        "Sources\n| summarize Files = count(), Events = sum(Events),\n"
        "            Bytes = sum(Bytes) by Format\n| sort by Events desc",
        "A lot of 'plain' means a lot of logs with no recognised structure, "
        "which is normal for games and for anything written with printf."),
    Example(
        "low-confidence", "Files whose format was a guess", "The index itself",
        "Sources\n| where Confidence < 0.8 and Events > 0\n"
        "| project App, Path, Format, Confidence, Events\n| sort by Confidence asc",
        "Worth a look: these are the ones most likely to have their "
        "timestamps or levels wrong."),
    Example(
        "unread", "Files that are only partly indexed", "The index itself",
        "Sources\n| where Indexed < Bytes\n"
        "| extend Remaining = Bytes - Indexed\n"
        "| project App, Path, Bytes, Indexed, Remaining\n| sort by Remaining desc",
        "Normally empty. Anything here grew since the last index."),
    Example(
        "no-timestamps", "Files whose lines have no time", "The index itself",
        "Logs\n| summarize Total = count(), Timed = countif(isnotnull(Timestamp))\n"
        "         by Source, Format\n"
        "| extend Untimed = Total - Timed\n| where Untimed > 0\n"
        "| sort by Untimed desc\n| take 50",
        "These lines are still searchable, but the time-range picker cannot "
        "see them, so widen it to All time when hunting in one of these."),

    # -- The journal -------------------------------------------------------
    Example(
        "journal-units", "Which systemd units are noisiest", "The journal",
        'Logs\n| where Location == "journal"\n'
        "| summarize Entries = count(), Errors = countif(Level in (\"error\", \"critical\")),\n"
        "            Last = max(Timestamp) by App\n"
        "| sort by Entries desc",
        "Every unit that wrote to the journal. `App` names the unit because "
        "each one becomes its own source."),
    Example(
        "journal-failures", "Units that failed to start", "The journal",
        'Logs\n| where Location == "journal"\n'
        '      and Message has_any ("Failed to start", "Failed with result",\n'
        '                            "entered failed state", "Start request repeated",\n'
        '                            "Main process exited")\n'
        "| project Timestamp, App, Level, Message\n"
        "| sort by Timestamp desc\n| take 100",
        "systemd's own account of what would not run."),
    Example(
        "journal-kernel", "What the kernel said", "The journal",
        'Logs\n| where Location == "journal" and App == "kernel"\n'
        '      and Level in ("warning", "error", "critical")\n'
        "| project Timestamp, Level, Message\n"
        "| sort by Timestamp desc\n| take 200",
        "Hardware, drivers, filesystems and the out-of-memory killer."),
    Example(
        "journal-authentication", "Logins, sudo and polkit", "The journal",
        'Logs\n| where Location == "journal"\n'
        '      and (App has_any ("sshd", "sudo", "polkit", "systemd-logind",\n'
        '                         "login", "sddm", "gdm")\n'
        '           or Message has_any ("authentication failure", "session opened",\n'
        '                                "session closed", "incorrect password",\n'
        '                                "a password is required"))\n'
        "| project Timestamp, Level, App, Message\n"
        "| sort by Timestamp desc\n| take 200",
        "Who signed in, who asked for root, and who was refused. This is the "
        "query the journal is worth indexing for."),
    Example(
        "journal-vs-files", "Journal against log files", "The journal",
        "Logs\n| summarize Events = count(), Apps = dcount(App) by Location\n"
        "| sort by Events desc\n| render piechart",
        "How the index divides between the journal and the files on disk."),
    Example(
        "journal-boot", "This boot, minute by minute", "The journal",
        'Logs\n| where Location == "journal" and isnotnull(Timestamp)\n'
        "| summarize Entries = count() by Minute = bin(Timestamp, 1m)\n"
        "| sort by Minute asc\n| render timechart",
        "The shape of a start-up. A flat stretch is idle; a spike is "
        "something retrying."),

    # -- ClamAV ------------------------------------------------------------
    Example(
        "detections", "Every threat ClamAV has found", "ClamAV",
        "Detections\n| project Detected, Threat, Path, Action, Bytes\n"
        "| sort by Detected desc",
        "From ClamGuard's own history database, attached read-only."),
    Example(
        "detections-in-context", "What the logs said around a detection",
        "ClamAV",
        "Detections\n"
        "| extend Bucket = bin(Detected, 1h)\n"
        "| join kind=inner (\n"
        "    Logs\n"
        "    | where isnotnull(Timestamp)\n"
        "    | extend Bucket = bin(Timestamp, 1h)\n"
        "  ) on Bucket\n"
        '| where abs(datetime_diff("second", Timestamp, Detected)) <= 300\n'
        "| project Timestamp, App, Level, Message, Threat, Path\n"
        "| sort by Timestamp asc\n| take 300",
        "Every log line from five minutes either side of a detection. The "
        "join is on the hour so that it stays a hash join rather than "
        "comparing every line against every detection. This is the query the "
        "whole page exists for."),
    Example(
        "scan-history", "Scan results over time", "ClamAV",
        "Scans\n| where isnotnull(Started)\n"
        "| project Started, Kind, Status, Files, Threats, Duration\n"
        "| sort by Started desc\n| take 50",
        "Every scan ClamGuard has run."),
    Example(
        "clamav-log", "ClamAV's own log lines", "ClamAV",
        'Logs\n| where App has_any ("clamav", "clamd", "clamguard", "freshclam")\n'
        "      or Source contains \"clam\"\n"
        "| sort by Timestamp desc\n| project Timestamp, Level, Source, Message",
        "If ClamAV writes to a file rather than the journal, Hunt indexes it "
        "like any other."),
)


def by_category() -> dict[str, list[Example]]:
    groups: dict[str, list[Example]] = {name: [] for name in CATEGORIES}
    for item in LIBRARY:
        groups.setdefault(item.category, []).append(item)
    return {name: entries for name, entries in groups.items() if entries}


def get(example_id: str) -> Example | None:
    return next((item for item in LIBRARY if item.id == example_id), None)


def starters() -> tuple[Example, ...]:
    return tuple(item for item in LIBRARY if item.starter)


def search(text: str) -> tuple[Example, ...]:
    """Filter the library by a word, matching names, notes and query text."""
    needle = text.strip().lower()
    if not needle:
        return LIBRARY
    return tuple(item for item in LIBRARY
                 if needle in item.name.lower()
                 or needle in item.description.lower()
                 or needle in item.category.lower()
                 or needle in item.text.lower())
