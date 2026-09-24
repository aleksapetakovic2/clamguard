# ClamGuard — Architecture

A map of the codebase for someone reading it for the first time.

---

## The one rule

```
core/  ──▶ may import: stdlib, PySide6.QtCore
       ──▶ must NOT import: PySide6.QtWidgets, PySide6.QtGui, anything in ui/

ui/    ──▶ may import: anything, including core/
```

If you keep that rule, all the logic stays testable without a display, and the
test suite can run on a headless machine. `tests/` enforces it.

---

## Layers

```
┌──────────────────────────────────────────────────────────────┐
│  ui/                                                         │
│    main_window.py   window frame, sidebar, page stack, tray  │
│    pages/           one file per screen                      │
│    widgets/         reusable pieces (cards, badges, rings)   │
│    theme.py         design tokens → QSS                      │
│    icons.py         bundled SVG → recoloured QIcon           │
└───────────────┬──────────────────────────────────────────────┘
                │ Qt signals only — pages never poke each other
┌───────────────▼──────────────────────────────────────────────┐
│  core/                                                       │
│    AppContext        one object that owns every service      │
│    scanner, quarantine, freshclam, services, history, ...    │
│    boot/             the Boot Analyzer — read-only, its own  │
│                      package, see below                      │
│    hunt/             log discovery, the event store, and a   │
│                      KQL engine — see below                  │
│    units/            the Services page's unit explorer       │
│    single_instance   one ClamGuard per login — see below     │
└───────────────┬──────────────────────────────────────────────┘
                │ QProcess / files / sqlite3
┌───────────────▼──────────────────────────────────────────────┐
│  The system: clamscan, clamdscan, freshclam, sigtool,        │
│  systemctl, journalctl, /etc/clamav, /var/lib/clamav         │
│  and — only for privileged writes — pkexec clamguard-helper  │
└──────────────────────────────────────────────────────────────┘
```

### `AppContext` (core/context.py)

Constructed once in `app.py` and passed to the main window, which passes it to
every page. It holds the long-lived services:

| Attribute | Type | What it does |
|---|---|---|
| `settings` | `Settings` | user preferences, JSON-backed |
| `clamav` | `ClamAV` | which binaries exist, versions, is clamd reachable |
| `database` | `DatabaseInfo` | signature db versions and age |
| `scanner` | `Scanner` | runs one scan at a time, emits progress |
| `quarantine` | `Quarantine` | the vault |
| `history` | `History` | SQLite scan log |
| `freshclam` | `Freshclam` | signature updates |
| `services` | `ServiceManager` | systemd unit state and control |
| `privileged` | `PrivilegedHelper` | the pkexec bridge |
| `scheduler` | `Scheduler` | scheduled scans |
| `realtime` | `RealtimeMonitor` | watches clamd's journal for on-access detections |

The Boot Analyzer is deliberately **not** in `AppContext`. It owns nothing
long-lived, costs three seconds to run, and is only interesting while its page
is open, so `ui/pages/boot.py` constructs its own `BootAnalyzer` and `Profile`
and throws them away with the page.

There is no global singleton and no import-time state. If you need a service in
a page, it came in through the constructor.

---

## Launching, and one instance per login

`app.main()` turns its arguments into one small request — show the window,
scan these paths, run a quick scan, open this page — and offers it to a
running ClamGuard first (`core/single_instance.py`). Only if none answers does
it start up itself, and then it listens for later launches.

A second launch is the ordinary case for a tray application that starts at
login: the menu entry, "Open with ClamGuard" on a folder and the desktop
file's right-click actions all launch the program again. Without the hand-over
each was a complete second copy with its own scheduler, so scheduled scans ran
twice.

- **The socket is private.** A Unix socket in `$XDG_RUNTIME_DIR` (per user,
  mode 0700), created with `UserAccessOption`; never /tmp, where another
  account could claim the name first. Its path must stay under ~90 bytes —
  `sockaddr_un` holds 108, and Qt builds the socket under a longer temporary
  name before renaming it — and falls back to the data directory otherwise.
- **Check before listening.** That rename silently replaces an existing
  socket, so "listen fails if someone is there" never happens; `listen()`
  connects first and only removes a socket file nobody answers on.
- **Requests are input.** `clean_request()` keeps four typed fields and drops
  everything else; paths are made absolute by the launch that received them,
  because the running instance's working directory is not the caller's.
- **Read synchronously.** A request is one line written on connect. Reading it
  with a bounded wait avoids per-connection signals and closures, whose
  ambiguous ownership between PySide and Qt ended in a double delete.

The desktop file's `Exec` lines are part of this contract and are tested: each
must parse, with its field codes expanded to nothing, and the application's
`desktopFileName` must match the installed file's name — on Wayland that is
the window's app_id, and a mismatch costs the window its icon.

## Threading model

ClamAV work is slow and must never freeze the window. Two mechanisms, nothing
else:

1. **`QProcess`** for anything that is an external command (`clamscan`,
   `freshclam`, `systemctl`, `journalctl`). Output arrives on the Qt event loop
   via `readyReadStandardOutput`. No threads involved. This is the default.
2. **`QThreadPool` + `QRunnable`** for blocking Python work — hashing a file,
   walking a directory tree, SQLite queries over large result sets. Results come
   back through a signal, never by touching a widget from the worker.

`core/process.py` wraps (1) so no page ever constructs a `QProcess` itself.

One consequence worth knowing: Qt signal arguments declared `int` are 32-bit.
Anything carrying a byte count is declared `"qint64"` instead, or a scan of more
than 2 GB overflows it.

---

## Data on disk

Everything ClamGuard owns lives under XDG paths. Uninstalling is `rm -rf` on
three directories; nothing is written to `/etc` or `/usr` by the app itself.

```
~/.config/clamguard/
    settings.json        preferences
    schedules.json       scheduled scans
    boot-profile.json    Boot Analyzer preset, mutes, tuning
    boot-checks.d/       user-written boot checks
    hunt.json            Hunt: roots, limits, retention
    hunt-queries.json    Hunt: saved queries
    hunt-history.json    Hunt: the last hundred queries run
    hunt-rules.d/        user-written analytics rules
~/.local/share/clamguard/
    history.db           SQLite: scans + detections
    hunt.db              SQLite: indexed events — files and journal,
                         schema version 2, mode 0600
    boot-baseline.json   hash snapshot of the boot chain
    quarantine/
        vault/<id>.quar  the neutralised file payload
        meta/<id>.json   original path, hash, threat, timestamps
    logs/clamguard.log   the app's own rotating log
~/.cache/clamguard/
    generated/           stylesheet glyphs rendered for the current palette
    scan-list.txt        the file list for a scan in progress
```

`hunt.db` is the only file here that can reach a gigabyte. It is roughly twice
the size of the logs it indexed — the events themselves, a full-text index
over the messages, and three b-trees — and it is mode 0600 because log lines
occasionally contain credentials. Retention caps it; the Hunt page can empty
it.

### Quarantine format

A quarantined file is **moved** (or copied+shredded if cross-device) into
`vault/<id>.quar` with mode `0600`, owned by the user, with the execute bit
gone. The payload is XOR-obfuscated with a fixed key so that a re-scan of the
vault does not re-detect it and so a double-click cannot execute it. This is
*neutralisation, not encryption* — it is documented as such in the UI. The
sidecar JSON records the original absolute path, original mode/uid/gid, SHA-256
of the original bytes, threat name, engine, and timestamps, which is everything
`restore()` needs.

---

## Privilege boundary

`core/privileged.py` is the only module that knows how to become root, and it
does exactly one thing: run

```
pkexec /usr/local/lib/clamguard/clamguard-helper <verb> [args...]
```

The helper (`packaging/clamguard-helper`) is a short, readable Python script —
standard library only, importing nothing from ClamGuard — installed by hand. It
accepts a closed verb list and refuses anything else:

| Verb | Effect |
|---|---|
| `status` | print helper version — used to probe availability |
| `read-file` | print one of a fixed allow-list of config files, or the last 4 MB of a log |
| `write-config` | validate with `clamconf`, back up, then replace a conf file |
| `service` | `systemctl start/stop/restart/enable/disable` on clamav units only |
| `update-db` | run `freshclam` |
| `quarantine` | move a root-owned file into the user's vault — **only after ClamAV itself confirms the file is infected** |
| `restore` | put one back, at the path in the helper's *own* root-owned record |

Paths and unit names are matched against allow-lists inside the helper. Every
call is logged by polkit and by the helper itself to
`/var/log/clamguard-helper.log`.

### What the helper is and is not a barrier against

pkexec has already authenticated the caller as an administrator, and an
administrator can run `sudo` anyway. So the helper is **not** a boundary
against a user who wants root.

It is a boundary against a *compromised or buggy GUI* — which matters, because
the polkit policy uses `auth_admin_keep`, leaving a few minutes after any
legitimate action in which further calls need no password. Malware running as
the user could wait for that window. Two properties close it:

* **`quarantine` moves only files ClamAV independently flags.** The helper reads
  the file and has ClamAV scan *those bytes*, on stdin, rather than trusting the
  caller or scanning a path that could be repointed between the scan and the
  read. So the verb cannot be turned into "read and delete any file as root".
  It fails closed if no scanner works.
* **`restore` takes an entry id, never a path.** Destination, owner and mode
  come from a record the helper wrote itself into `/var/lib/clamguard/records/`
  (root-owned, mode 0700). The metadata in the user's home directory is for
  display only and is never trusted, because the user can edit it. setuid,
  setgid and sticky bits are stripped on the way in *and* masked again on the
  way out — restoring a root-owned setuid binary would be an immediate root
  shell. And a file only ever goes back into the directory it came from, as
  that directory resolves *now*: one that has since become a symlink to
  somewhere else is refused. A blocklist of dangerous destinations backs this
  up, but no blocklist can name every directory where a file is dangerous
  (`/etc/modprobe.d`, `/etc/udev/rules.d`, …) and this rule does not need to.

**No path is trusted twice.** The user can swap *any* directory on a path for
a symlink between the helper checking it and using it, not only the last
component, so `O_NOFOLLOW` on its own is not enough. The helper resolves a path
once, walks the result from `/` a directory at a time with `O_NOFOLLOW`, and
does everything after that through the directory's descriptor — open, write,
`fchown`, rename, unlink. A symlink that was there all along (Silverblue's
`/home`) is resolved first and keeps working; one swapped in mid-operation makes
the walk fail. The quarantined file is only unlinked if its name still refers
to the file that was read: same inode, size and timestamps — the inode number
alone is not proof, because ext4 hands a freed one straight to the next file. `tests/test_security.py::TestHelperRaces` stages
each of these swaps against the real helper code.

**The GUI never calls a privileged verb without a confirmation dialog that shows
the exact change** — a unified diff for config writes, the unit name for service
actions.

---

## The Boot Analyzer (core/boot/)

The tenth page is a package rather than a module, because it is really a small
rule engine. It answers "is there anything wrong with how this machine boots?"
— firmware, bootloader, kernel, and everything set to start automatically.

```
core/boot/
    model.py      Severity, Category, Finding, Fix, Evidence, Report, the score
    probe.py      the ONLY way a check reads the system, plus FakeProbe
    registry.py   the @check decorator and the catalogue
    profile.py    presets, per-condition severities, thresholds, mutes
    custom.py     user-written declarative checks (no way to run a command)
    baseline.py   a hash snapshot of the boot chain, and drift against it
    report.py     Markdown / HTML / JSON / commented-out-shell exports
    analyzer.py   the QObject that runs the catalogue off the UI thread
    checks/       firmware, bootchain, kernel, hardening, persistence,
                  services, performance, integrity
```

### The two ideas worth knowing

**A check is a pure function.** `f(Probe, Policy) -> Iterable[Finding]`. It
reads the machine only through the Probe and decides severity only through the
Policy, so every check can be driven by `FakeProbe(files={...})` with no
machine state at all. That is why `tests/test_boot_checks.py` can assert what
the analyzer says about a world-writable `/boot` on a machine that has none.

**Nothing writes.** This is the feature that inspects bootloaders, kernel
command lines and ESP permissions, which is exactly where a well-meant
automatic fix becomes an unbootable machine. So:

* `Probe` has no method that writes, and its command runner takes only an
  allow-list of inspection tools (`ALLOWED_COMMANDS`).
* No privileged verb was added to the helper. The Boot Analyzer never calls it.
* A `Fix` carries a command and a **Copy** button, never a Run button. The
  shell-script export arrives with every line commented out.
* `tests/test_security.py::TestBootAnalyzerIsReadOnly` asserts all of that
  structurally, so a refactor cannot quietly reopen it.

The four modules that do write — `profile.py`, `baseline.py`, `custom.py`,
`report.py` — write only to XDG directories or to a directory the user picked
in a file dialog, and a test asserts that none of them names an absolute path
as a write destination.

### The score

`Report.score` starts at 100 and subtracts a published weight per finding:
critical 25, high 12, medium 5, low 2, info 0. Muted findings cost nothing.
`Report.score_explanation()` returns the arithmetic as a sentence, and the page,
the Markdown export and the HTML export all print that same string — so the
number can be checked rather than believed.

---

## Hunt (core/hunt/)

The eleventh page. It finds every log file on the machine, converts twenty-odd
formats into one event schema in a local SQLite store, and runs Kusto Query
Language over it.

```
core/hunt/
    model.py       Level, Event, Column, ResultTable, TimeRange
    formats.py     the format registry: one parser per dialect
    discovery.py   where logs hide, what to skip, and why
    journal.py     the systemd journal — the one module that runs a command
    store.py       SQLite: schema, incremental ingest, rotation, retention
    catalogue.py   the tables KQL sees, and how each column maps to SQL
    indexer.py     the QObject that crawls, indexes and queries off the UI thread
    library.py     forty-five worked queries, shown in the left rail
    rules.py       analytics rules: a query, a threshold, an explanation
    saved.py       the user's saved queries and their run history
    settings.py    roots, limits, retention — one JSON file
    export.py      CSV / TSV / JSON / Markdown
    kql/
        lexer.py      tokens, with positions for editor squiggles
        ast.py        node types
        parser.py     recursive descent, Kusto precedence
        values.py     the type system, null semantics, dynamic access
        functions.py  ~135 scalars, 28 aggregates, 5 window functions
        compiler.py   the pushdown planner: AST -> one SELECT where possible
        engine.py     execution: SQL below, streaming generators above
        errors.py     KqlError with a position, a caret and a suggestion
        complete.py   context-aware completion for the editor
```

### Why its own KQL engine

The obvious existing engine, `kusto-loco`, is the right project on the wrong
runtime: it is C#/.NET, and ClamGuard is Python with PySide6 and a rule against
new dependencies. So the engine is ClamGuard's own. `kusto-loco`'s operator
coverage is the target it aims at, and its error messages are the standard to
meet.

### The four ideas worth knowing

**A parser that admits when it does not match.** Format detection is not a
separate guess: every parser is run over a sample of the file and the one that
understood the most wins. That makes it impossible for detection and parsing
to disagree, which is the failure mode that produces a table full of nulls.
Lines a format rejects are folded into the event before them when the format
says so, which is how a stack trace stays attached to its message.

**Re-indexing costs only the new bytes.** Each source records the byte offset
it was read to and a SHA-256 of the *fixed* prefix it has already consumed —
the smaller of 4 KB and the bytes read, never "the first 4 KB of whatever is
there now", because a 200-byte log that grows to 300 would otherwise hash
differently and be re-read as a rotation. A changed hash, a changed inode or a
file shorter than its own offset all mean rotation, and the source is re-read
from the start. Indexing 200 MB twice costs 200 MB and then a tenth of a
second.

**Pushdown, then stream.** `compiler.py` translates the longest prefix of the
pipeline it is *certain* about into one SELECT — `where` into `WHERE`,
`summarize` into `GROUP BY`, `take` into `LIMIT`, `search` and `has` into an
FTS5 `MATCH`, `Extra.pid` into `json_extract` — and stops at the first thing
it is unsure of. Everything above runs as Python generators over the cursor.
So correctness depends only on the evaluator in `engine.py`; the planner can
make a query faster or leave it alone, and
`tests/test_hunt_kql_engine.py::TestPushdown` asserts that by running a corpus
of queries both ways and requiring identical results.

**Only one thing can run a command.** `tests/test_security.py::
TestHuntCannotWriteOrEscape` asserts that nothing under `core/hunt` imports
`subprocess`, `pty`, `shlex`, `multiprocessing` or `ctypes`, or calls
`eval`/`exec`/`os.system`, with exactly one named exemption — `journal.py` —
which is held to four stricter tests instead: one program, no shell, every
argument on the allow-list for every combination of settings, and nothing in
the allow-list that could rotate, vacuum or erase the journal.

**A query cannot write.** `Store.reader()` opens the connection `mode=ro` with
`PRAGMA query_only`, so an INSERT fails in the VFS before it reaches the file.
The compiler only ever emits SELECT, `evaluate`/`externaldata`/`invoke` are
refused by name in the parser, and nothing in `core/hunt/` imports
`subprocess` or anything that can reach the network. `tests/test_security.py::
TestHuntCannotWriteOrEscape` asserts all of that structurally.

### The systemd journal

`journal.py` is the one module in `core/hunt` allowed to execute anything, and
it is written to be the kind of exception that stays safe: one program
(`journalctl`, resolved through `shutil.which`, never a path from settings or
the database), an allow-list every argument is checked against before the
process starts, no shell, and a streaming read so an 11-million-entry journal
is never buffered whole.

Three measured behaviours of `journalctl` shape it, and each is a comment in
the code and a test in `tests/test_hunt_journal.py`:

* **A stale cursor fails almost silently.** `--after-cursor` with a cursor
  that no longer exists prints the reason on *stderr*, prints nothing on
  stdout and exits non-zero — indistinguishable from "nothing new" unless
  somebody looks. The reader reports it and the caller re-reads the window.
* **`--no-tail` is load-bearing.** With it, `--lines=N` returns the *oldest* N
  of the window, so a capped read plus the cursor it leaves behind resumes
  exactly where it stopped. Without it the same flag returns the newest N and
  everything older is lost the moment the cursor is saved past it.
* **`MESSAGE` is not always a string.** 26 entries in a 20,000-entry sample
  were lists of integers — raw bytes, used whenever the message is not valid
  UTF-8, in practice whenever it contains colour escapes.

**Each systemd unit becomes its own source row**, `journal:<unit>`, with the
unit in `sources.app`. That is the whole reason the journal is worth indexing:
the KQL `App` column reads from the source, so grouping by it names
`sshd.service` and `kernel` instead of saying "journal" a hundred thousand
times. The cursor lives in a one-row `journal_state` table, because a cursor
is a position in the journal as a whole while the sources are per unit.

### Threading

`indexer.py` is the only module here that knows about Qt. The store keeps one
SQLite connection **per thread** — a connection belongs to the thread that
made it, and this store is built on the UI thread and written from a worker —
and WAL mode is what makes the split safe: the reader on the UI thread and the
writer on the worker do not block each other. A worker closes its connection
when its job ends, so the handle count stays flat over a long session.

### Adding a log format

One `LogFormat` entry in `core/hunt/formats.py`: an id, a title, a
description, an example, a `parse(line, context) -> Event | None`, and a
priority for ties. Detection, the Sources dialog and the `Format` column all
pick it up. `tests/test_hunt_formats.py` asserts that every registered format
can parse its own advertised example.

### Adding a KQL function

One `@scalar(...)` or `@aggregate(...)` in `core/hunt/kql/functions.py`. The
Functions tab, completion, the signature hint and the documentation all read
the same registry, and the tests assert that every entry has a signature and
survives being handed a null.

---

## Services (core/units/)

The twelfth page. It reads every systemd unit on the machine and answers, for
each one, "what is this, why is it here, and do I need it?"

```
core/units/
    model.py       Unit, UnitKind, Enablement, Provenance, Exposure, Inventory
    inventory.py   the two listings, the one batch `show`, and the parser
    enrich.py      package ownership, man summaries, sandboxing, boot cost, ports
    purpose.py     synthesis: headline, structural notes, reasons, flags
    manager.py     the QObject that gathers off the UI thread and caches
```

### One batch, not N calls

`systemctl show` accepts every unit name at once. 460 units with 35 properties
is **one second**; the same information one unit at a time is 460 forks and a
frozen window. Every other source is batched the same way — one `pacman -Qo`
for every unit file, one `whatis` for every candidate man page — so a complete
picture of the machine costs about 2.6 seconds and nine processes.

Reverse dependencies need no work at all. `RequiredBy` and `WantedBy` come back
from that same call as *real* reverse edges, not merely what a unit's
`[Install]` section declared: `dbus.socket` reports a dozen services under
`RequiredBy`. An earlier version inverted the forward edges by hand and was cut
as a redundant second source of truth.

### Read-only, and why it has to stay that way

`packaging/clamguard-helper` holds an allow-list of ClamAV unit names and
refuses everything else. A unit browser is exactly the feature that would want
that widened, and exactly the wrong reason to do it — the helper would go from
"controls ClamAV" to "controls this machine". So the page starts and stops
nothing. It offers the `systemctl` command with a Copy button, the way the Boot
Analyzer offers its remedies. `tests/test_security.py::TestServicesAreReadOnly`
asserts all of it: no import of `privileged`, no state-changing verb anywhere in
the strings, no writes, and the helper's allow-list unchanged.

### Five traps, all found by probing

- **`--` before the unit names.** `-.mount` is the root filesystem's unit and
  parses as a malformed option without a separator, failing the whole batch.
- **Aliases resolve on the way in.** Asking about `dbus.service` returns a
  record whose `Id` is `dbus-broker.service`. Units are keyed on `Id`, and a
  roster holding both names produced two identical rows until `_deduplicate`.
- **Templates have no state.** 86 of 546 unit *files* are templates
  (`getty@.service`) and cannot be shown; their instances appear only in
  `list-units`, so both listings are needed.
- **`ExecStart` is a struct whose `argv[]` contains bare semicolons** — a
  `while [ ! -S … ]; do sleep 1; done` has two — so it is bounded by the fixed
  ` ; ignore_errors=` field that always follows it, never by splitting on `;`.
- **List properties are shell-quoted.** Any entry with an escaped character —
  most mounts and devices — comes back as `"blockdev@dev-disk-by\\x2duuid-….target"`.
  Splitting on whitespace kept the quotes and the doubled backslash, which on
  the development machine broke 87 dependency edges and made 98 units list
  their own name as an alias. `model.as_list` undoes POSIX double-quote quoting with `shlex`.

### Two managers, and the names they share

The page reads either the system manager or the session's (`systemctl --user`),
and 36 unit names exist in both trees on an ordinary desktop — `dbus-broker.service`
and `dbus.socket` among them. So every `Unit` carries `user_manager`, and
everything that turns a unit into a command or a judgement reads it:

- **Commands.** A session unit's command gets `--user` and never `sudo`; without
  the flag, "restart dbus-broker.service" copied off the session list names the
  *system* message bus. Reading verbs (`status`, `cat`) never get `sudo` either.
- **Privilege.** An empty `User=` means root to the system manager and *you* to
  the session's, so "runs as root" flags use `Unit.runs_as_root`, not the field.
- **Enrichment.** Sandboxing scores and boot times are per manager; a session
  inventory asks `systemd-analyze --user`, or it would inherit the system
  units' numbers by name.
- **Presets.** "Changed from the distribution default" is only said when a
  preset rule actually names the unit (`Unit.preset_ruled`, read from the
  preset files). The session manager reports "enabled" for any unit no rule
  mentions — systemd's built-in default, nobody's decision — which put 37
  untouched session units on that list; Arch's system presets end in an
  explicit `disable *`, so system units are still judged against it.
- **Provenance.** "No package owns it" is only said when a package manager was
  actually asked (`Unit.package_checked`), so a distribution ClamGuard cannot
  query does not have every unit reported as hand-written; and on Debian the
  `/usr`-merge alias of each path is asked too, because `dpkg -S` does not
  resolve `/lib` ↔ `/usr/lib` itself.

### Thresholds are measured, not guessed

A flag that fires on two thirds of the list is decoration. Every threshold in
`purpose.py` was set against a real machine's 627 units:

- **Unmet `Condition=`** was 446 units before it was narrowed to units that are
  *enabled and did not start*. For a `static` unit nobody pulled in, an unmet
  condition is how systemd works, not a finding.
- **Sandboxing** is only flagged at 9.0+ *and* running *and* as root. systemd
  calls 6+ "exposed", but the median scored unit on a desktop is 9.4 — almost
  nothing outside systemd's own units is sandboxed at all.
- **Boot cost** is flagged above five seconds. A hundred units report a second
  or more and 97 of them report the same 2.717 s, because `systemd-analyze
  blame` gives units that finished together identical figures.

Together these took "worth a look" from 262 units of noise to 82 of signal.

### Degrading

`pacman`/`dpkg`/`rpm`, `whatis`, `ss` and `systemd-analyze` are each optional.
A missing one removes a row from the detail pane and adds a sentence to the
page's notice saying why — an unexplained gap reads as a bug. `ss` gets this
treatment even when present: unprivileged it lists every listening socket but
names the process for none of them, so the page says ports need root rather
than implying nothing is listening.

## Adding a new page

1. Create `ui/pages/yourpage.py` with a class deriving from `Page`
   (`ui/pages/base.py`). It gets `AppContext` in `__init__`.
2. Register it in `ui/main_window.py`: a `NavItem` in `NAV_ITEMS` and an entry
   in `_page_classes()`.
3. If it needs new system access, put that in a `core/` module — not in the page.

## Adding a new ClamAV config option to the editor

Add one `ConfOption(...)` entry to `core/conf_schema.py`. The settings page,
validation, help text and diff all come from it automatically. No UI code.
