# Working on ClamGuard

Written for someone who has just cloned this and wants to change something.

---

## Get it running

```bash
./clamguard          # start it
./clamguard -v       # with debug output on the terminal
./run-tests          # the whole suite
./run-tests -v conf_file    # one module, verbosely
```

No build step and no package to install. You need Python 3.11+ and PySide6
6.8+; the launcher finds an interpreter that has it, including one in a `.venv`
inside the checkout — which is how to get PySide6 where the distribution does
not package it (see the README). If you have several Pythons, pin one:

```bash
CLAMGUARD_PYTHON=/usr/bin/python3.12 ./clamguard
```

---

## The layout

```
clamguard                 the launcher (bash)
install.sh                user-level install, no root
run-tests                 the test runner
src/clamguard/
    app.py                bootstrap
    core/                 logic. No widgets. Testable headless.
    core/boot/            the Boot Analyzer. Read-only, see below.
    core/hunt/            log discovery, the event store, the KQL engine
    core/hunt/journal.py  the systemd journal — the ONE module that may run
                          a command; see the rule below before touching it
    core/hunt/kql/        lexer, parser, planner, evaluator, functions
    ui/                   everything you can see
        main_window.py    window frame, sidebar, tray, page registry
        pages/            one file per screen
        widgets/          reusable pieces
        theme.py          every colour in the application
        icons.py          bundled SVG, recoloured at load time
    resources/icons/      the icons: hand-written SVG
packaging/
    clamguard-helper      the only thing that runs as root
    install-helper.sh     installs it (you run this, the app never does)
tests/                    unittest, standard library only
```

---

## The rules

### 1. `core/` must not import `QtWidgets`, `QtGui`, or anything from `ui/`

This is what keeps the logic testable without a display. `tests/test_layering.py`
enforces it and will fail the build if you break it.

`core/` *may* use `QtCore` — `QObject`, `Signal`, `QProcess`, `QTimer` — because
the alternative is hand-rolling an event system that Qt already has.

### 2. Nothing privileged happens without a confirmation showing the change

Every route to root goes through `core/privileged.py`, and every caller shows
the user what will happen first: the unified diff for a config write, the unit
name for a service action. If you add a privileged operation, add it to the
helper's verb list *and* give it a confirmation that shows real content, not a
generic "are you sure?".

`ui/config_apply.py` exists so this cannot be forgotten: use `ConfigApplier`
for config writes and `ServiceController` for service actions rather than
calling the helper directly.

### 3. Never block the UI thread

Use `core/process.Command` for external programs (it is built on `QProcess`,
so it needs no threads) and `core/process.run_in_background` for slow Python
work. `core/process.run()` blocks and is only for commands that finish in
milliseconds — always with a timeout.

### 4. No new dependencies without a written reason

The whole thing is Python standard library plus PySide6, which means it
installs with one package on most distributions and has no supply chain to
speak of. Adding a dependency needs a reason written down — in the pull
request, and in `ARCHITECTURE.md` if it stays.

### 5. Errors are shown, not swallowed

If something fails, say what failed and what to do about it, next to the thing
that failed. `MessageBar` inside the page for anything the user must act on;
`self.notify.emit(...)` for a transient message. A page that silently shows
nothing when it cannot read something is a bug.

---

## Common tasks

### Add a configuration option to the editor

One line in `core/conf_schema.py`:

```python
opt("MyNewOption", BOOL, "What it does in plain words", "Detection", CLAMD,
    default=False, hint="Anything ClamGuard wants to add on top."),
```

The widget, the validation, the grouping, the search index and the diff all
follow. Do not write help text — `ConfFile.documentation()` reads ClamAV's own
description out of the config file's comments at runtime, which means it always
matches the installed version.

### Add a page

1. `ui/pages/yourpage.py`, subclassing `Page`:

```python
class YourPage(Page):
    PAGE_ID = "yours"
    TITLE = "Your page"
    SUBTITLE = "What it is for"
    ICON = "activity"          # any file in resources/icons/

    def build(self) -> None:
        self.body.addWidget(Card("Something", icon="info"))
        self.add_stretch()

    def on_shown(self) -> None:
        self.refresh()
```

2. Add a `NavItem` to `NAV_ITEMS` in `ui/main_window.py` and an entry to
   `_page_classes()`.

Pages talk to the rest of the app through signals — `navigate`, `notify`,
`badge_changed`, `request_scan`, `theme_refresh_requested` — and never by
reaching for the window.

### Add an icon

Drop a 24×24 SVG into `src/clamguard/resources/icons/`. Use
`stroke="currentColor"`, `stroke-width="1.8"`, round caps and joins, and no
fill. It is then available as `icons.icon("yourname")` and
`IconLabel("yourname")`.

### Change how it looks

`ui/theme.py` and nothing else. The two `Palette` objects hold every colour;
`_QSS` is the stylesheet, written as a `string.Template` because QSS is full of
braces. `ACCENTS` is the user-selectable highlight colour.

Widgets that paint themselves (`ProgressRing`, `ToggleSwitch`) cannot read a
stylesheet, so they take a palette through `apply_palette()`. If you write
another one, give it that method and emit `theme_refresh_requested` after
creating it.

### Add a Boot Analyzer check

One function, in the file for its category under `core/boot/checks/`:

```python
@check(
    "kernel.something",
    title="Something about the kernel",
    category=Category.KERNEL,
    inspects="/proc/sys/kernel/something.",     # shown in the Checks tab
    worst=Severity.HIGH,
    tags=("kernel",),
)
def something(probe: Probe, policy: Policy) -> Iterator[Finding]:
    item = get("kernel.something")
    value = probe.sysctl_int("kernel.something")
    if value is None:
        raise SkipCheck("this kernel does not expose kernel.something")
    if value == 1:
        yield passed(item, "on", "Something is on", "Why that is good.")
        return
    yield finding(
        item, "off", policy.severity("some_policy_key"),
        "Something is off",
        "What is true, in a sentence or two.",
        impact="What an attacker gains, or what breaks.",
        value=str(value), expected="1",
        evidence=(Evidence("/proc/sys/kernel/something", str(value), kind="sysfs"),),
        fixes=(Fix("Turn it on", "How, and what it costs.",
                   command="…", risk="…"),),
    )
```

Five rules, all enforced by tests:

1. **Read only through the `Probe`.** It caches, it records what it touched for
   the audit panel, and it is what makes `FakeProbe` work. A check that calls
   `open()` or `subprocess` directly fails `tests/test_security.py`.
2. **Ask the `Policy` for severity**, not a literal, wherever the answer is a
   judgement call. Add a key to `BASE_SEVERITIES` in `core/boot/profile.py`
   and set it in the presets that disagree. The presets are checked for
   monotonicity, so relaxed must never be harsher than paranoid.
3. **Carry the evidence.** Every finding shows the file or command it came
   from. A finding without evidence is asking to be believed.
4. **A fix is a command to copy.** Never make the analyzer act. If a fix can
   break the boot, say so in `risk=` — that text sits next to the command.
5. **Raise `SkipCheck` when it cannot run here**, with a reason. "This machine
   has no UEFI" is a skip; "everything is fine" is a `passed()`.

Then add the case to `tests/test_boot_checks.py`, driving it with a
`FakeProbe`. Every check already has one, and the module-level tests will
automatically cover your new check for crashes, metadata and finding ids.

### Add a log format to Hunt

One entry in `core/hunt/formats.py`:

```python
def parse_mything(line: str, context: ParseContext) -> Event | None:
    match = _MYTHING.match(line)
    if match is None:
        return None          # saying no is what makes detection work
    return _event(timestamp, level, message, extra, line)


register(LogFormat(
    id="mything", title="MyThing", priority=80, parse=parse_mything,
    description="What writes this and what it looks like.",
    example="2026-09-21 [info] a real line, copied from a real file",
))
```

Four things to get right:

1. **Return `None` for a line you do not understand.** Detection works by
   running every parser over a sample and keeping the one that understood the
   most, so a parser that accepts everything wins every file.
2. **The example must be a line that parses.** A test asserts it, because the
   example is shown in the Sources dialog and a wrong one teaches the user
   something false.
3. **Priority breaks ties only.** It is not a preference; the proportion
   understood decides first.
4. **`continuation=False`** for formats where every line stands alone (JSON
   Lines, access logs). The default joins unparsed lines onto the event before
   them, which is right for anything that can emit a stack trace.

Then add a case to `tests/test_hunt_formats.py` — with a line copied out of a
real file, not one you made up.

### Add a KQL function

One decorator in `core/hunt/kql/functions.py`:

```python
@scalar("thing_of", "thing_of(value)", "What it does, in one line.",
        "string", min_args=1, max_args=1, example='thing_of(Message)')
def _thing_of(value):
    return None if value is None else do_something(V.to_string(value))
```

The Functions tab, completion, the signature hint and the hover documentation
all read the same registry, so there is nothing else to update. Two rules the
tests enforce: the signature has to start with the function's own name, and
the function has to survive being handed a null — half the columns in a log
store are null half the time.

If it is not a Kusto function, pass `extension=True`. It will be labelled as a
ClamGuard extension everywhere it is shown.

### Add a KQL operator

Harder, and worth understanding the split first. `core/hunt/kql/engine.py`
implements the whole language in Python; `compiler.py` is an optimiser that
translates a prefix of the pipeline into SQL and may only ever make a query
*faster*.

So: add the node to `ast.py`, parse it in `parser.py`, implement it in
`engine.py`'s `_OPERATORS`, and **stop**. Pushing it into SQL is a separate,
optional step. When you do add it to `compiler.py`, add the query to
`TestPushdown.QUERIES` in `tests/test_hunt_kql_engine.py`, which runs the
corpus both ways and requires identical results.

### Add a Hunt analytics rule

Either a `Rule(...)` in `core/hunt/rules.py`'s `BUILT_IN`, or a JSON file in
`~/.config/clamguard/hunt-rules.d/` — the two are the same shape. A rule is a
query, a threshold and an explanation; it cannot run anything, because the
engine it runs on cannot.

The mistake to avoid: **`has` matches whole terms and throws punctuation
away.** `has_any("| sh")` is really `has_any("sh")`, and `has(".desktop")` is
really `has("desktop")`. When the punctuation is the point, use `contains`.
A test in `tests/test_hunt_library.py` checks the shipped rules for it.

### Run a command from Hunt (don't)

`core/hunt/journal.py` is the only module in the package permitted to execute
anything, and `tests/test_security.py` enforces that by name. If you think you
need a second one, you almost certainly want to put the work in `journal.py`
or in `core/process.py` instead.

If you genuinely do, the four properties the exemption is granted on have to
hold for yours too, and you have to add it to `COMMAND_RUNNER` deliberately:

1. **One program**, resolved with `shutil.which` at call time — never a path
   from settings, from the database, or from a log line.
2. **Every argument checked against an allow-list** before the process starts,
   with a test that walks the full product of every setting that can reach it.
3. **No shell**, and a fixed, boring environment.
4. **Nothing in the allow-list that changes state.** `journalctl` can rotate
   and vacuum the journal; none of those flags is expressible.

### Add a privileged operation

1. Add a verb to `packaging/clamguard-helper` — validate every argument against
   an allow-list *inside the helper*, not in the caller.
2. Add it to `VERBS` and `HANDLERS`, and to `describe()` in
   `core/privileged.py` so the confirmation reads properly.
3. Add a convenience method on `PrivilegedHelper`.
4. Add a test to `tests/test_privileged.py`.

Assume the GUI is compromised. The helper's allow-lists are the actual
boundary.

---

## Style

Nothing exotic. Follow what is already there:

- One module-level docstring per file, explaining *why* the module exists, not
  restating its name.
- Comments explain decisions and non-obvious constraints, not mechanics. If a
  line needs a comment saying what it does, rename something instead.
- Explicit names. `configured_endpoints()`, not `get_eps()`.
- Small functions. If it does not fit on a screen, it is probably two things.
- Type hints on public functions; `from __future__ import annotations` at the
  top so they stay cheap.
- British or American spelling — the codebase uses British, keep it consistent.

The audience for this code is a person reading it at 2am because their antivirus
did something surprising. Optimise for that.

---

## Testing

```bash
./run-tests                 # about 1,500 tests, two minutes or so
./run-tests quarantine      # one module
./run-tests -v scanner      # with names
./run-tests boot_checks     # every Boot Analyzer check, against fake machines
```

The suite is standard-library `unittest`. It runs headless on Qt's offscreen
platform and never touches your real `~/.config` — `TempHomeTestCase` redirects
the XDG variables and reloads `core.paths`.

Some tests adapt to the machine: they skip when ClamAV is not installed, and
`tests/test_conf_schema.py` compares the option catalogue against whatever
`clamconf` actually reports, so it catches a ClamAV upgrade adding or removing
an option.

`tests/test_ui_smoke.py` builds the real window, visits every page, and runs a
real scan against a real EICAR file. It is slow and worth it.

GitHub Actions runs the whole suite on every push and pull request, on Ubuntu,
twice: with the oldest Python and PySide6 ClamGuard supports (3.11 and 6.8),
and with the newest. ClamAV is not installed there, so the tests that need it
skip — run the suite locally too if you touched scanning.

When you fix a bug, add the test that would have caught it. Several tests in
here exist for exactly that reason and say so in their names — for example
`test_prose_comments_are_not_mistaken_for_options`, which is a real bug the
config parser had.

---

## Things that look wrong but are not

**Scans enumerate every file before scanning.** It costs a directory walk. It
buys a real progress bar, and it is the only way to get per-file output from
`clamdscan`, which prints one line per *directory* when given a directory.

**The quarantine XOR key is in the source.** It is neutralisation, not
encryption. Its job is to stop accidental execution and stop re-detection, and
both work fine with a public key. The UI says so too.

**`core/` uses QtCore.** See rule 1.

**The helper duplicates the XOR function.** Deliberately — it must not import
from ClamGuard. `tests/test_quarantine.py` checks the two implementations
produce identical bytes, so they cannot drift.

**Tables set their own row heights.** Qt does not measure a cell *widget* when
sizing a row, so a row containing a button is too short unless the height is
set. `widgets.fit_table()` does that, and sizes the table to its content.

**Word-wrapped labels set a height-for-width policy.** Without it, Qt clips
long text mid-sentence at whatever width the layout first guessed.

**The Boot Analyzer has no Apply button.** Deliberately. It inspects the
settings where an automatic fix turns into an unbootable machine, so it shows
the command and leaves the typing to the person who has to live with the
result. `tests/test_security.py::TestBootAnalyzerIsReadOnly` keeps it that way.

**Hunt indexes about twice as many bytes as it read.** The events, a full-text
index over the messages, and three b-trees. That ratio is measured and printed
in the toolbar rather than hidden, and retention caps the total.

**Two thirds of Hunt's events have no timestamp.** Not a parsing failure —
half the log formats on a Linux desktop genuinely do not write one. They are
indexed and searchable; the time-range picker cannot see them, and the page
says so in a chip rather than letting the user conclude the index is empty.

**Hunt binds SQL parameters per clause, not in one list.** The planner walks
the pipeline in pipeline order — `where` before `summarize` — while the
statement puts the select list first. A single flat parameter list therefore
bound them backwards the moment a pushed `summarize` carried a parameter of
its own, and the query returned nothing at all rather than failing.
`_Builder.section()` is what keeps the two orders apart.

**Hunt's query planner is allowed to be incomplete.** `compiler.py` stops at
the first operator it is not certain about and lets Python do the rest. That
is the design: correctness lives in one implementation, and the optimiser can
only be a performance decision.

**Boot findings are emitted for things that passed, too.** They are hidden
until you press "Show passed". "We looked and it is fine" and "we did not look"
are different answers, and a security tool that conflates them is less useful
than one that does not.

**`systemctl --state=<x>` exits non-zero when nothing matches.** So "no masked
units" arrives looking like a failure. The boot checks treat a non-zero exit
with empty stderr as "none", not as "could not check".
