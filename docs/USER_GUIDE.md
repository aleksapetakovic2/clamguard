# ClamGuard — User Guide

Everything the application does, and what it deliberately does not do.

---

## Contents

1. [Getting started](#1-getting-started)
2. [The dashboard](#2-the-dashboard)
3. [Scanning](#3-scanning)
4. [When something is found](#4-when-something-is-found)
5. [Quarantine](#5-quarantine)
6. [Signature updates](#6-signature-updates)
7. [Real-time protection](#7-real-time-protection)
8. [The Boot Analyzer](#8-the-boot-analyzer)
9. [Hunt — querying your logs](#9-hunt--querying-your-logs)
10. [Services — what is running, and why](#10-services--what-is-running-and-why)
11. [Scheduled scans](#11-scheduled-scans)
12. [History and logs](#12-history-and-logs)
13. [Editing ClamAV's configuration](#13-editing-clamavs-configuration)
14. [Administrator rights](#14-administrator-rights)
15. [Your data](#15-your-data)
16. [Troubleshooting](#16-troubleshooting)

---

## 1. Getting started

### Running it

```bash
./clamguard
```

There is no build step. The launcher finds a Python that has PySide6 and starts
the app. If there is none, it prints the command that installs PySide6 on your
distribution — and for Ubuntu 24.04, which does not package PySide6, how to put
it in a `.venv` inside the checkout, which the launcher then finds by itself.
The [README](../README.md#getting-it-running) has the same table.

To add it to your application menu:

```bash
./install.sh
```

That installs three things, all inside your home directory: a symlink in
`~/.local/bin`, an icon, and a `.desktop` entry. Nothing needs root.

### What you get without doing anything else

Straight away, with no extra setup:

- scanning, including quarantine and history
- seeing the state of ClamAV's services and signature databases
- reading ClamAV's logs through the systemd journal
- browsing every configuration option, and previewing changes

### What needs one more step

Three things write outside your home directory and therefore need
administrator rights:

- editing `/etc/clamav/clamd.conf` and `freshclam.conf`
- starting, stopping or enabling ClamAV's systemd services
- running `freshclam` to download new signatures

ClamGuard does not run as root to do these. A separate helper script does, and
**you install it yourself** so you can read it first:

```bash
less packaging/clamguard-helper     # read it
sudo ./packaging/install-helper.sh  # then install it
```

Until you do, those features are visible but disabled, and each one tells you
what it would have done.

---

## 2. The dashboard

One headline, and the reasons behind it.

| Status | What it means |
|---|---|
| **Protected** | Signatures are current and nothing is misconfigured. |
| **Needs attention** | Scanning works, but something is missing — real-time protection is off, signatures are getting old, files are sitting in quarantine. |
| **At risk** | Something makes scanning ineffective: no signatures at all, signatures weeks out of date, or ClamAV missing entirely. |

Each item under "what needs your attention" carries a button that goes to the
page that fixes it. The status is honest: ClamGuard will say "at risk" on a
machine with a working scanner but month-old signatures, because that scanner
will not find anything recent.

---

## 3. Scanning

### Choosing what to scan

| Scope | Covers |
|---|---|
| **Quick scan** | Downloads, Desktop, Documents, the trash, `/tmp`, `/var/tmp`, `/dev/shm` — where files from outside actually land. Takes seconds to minutes. |
| **Full system scan** | Every file on every local filesystem, skipping `/proc`, `/sys`, `/dev` and the like. Hours. |
| **Home folder scan** | Everything under your home directory. |
| **Removable media scan** | USB sticks and external drives mounted right now. |
| **Custom scan** | Folders or files you pick — or drag onto the window from a file manager. |

You can also scan from a terminal, or from a file manager with **Open with →
ClamGuard** on any folder:

```bash
clamguard --scan ~/Downloads /media/usb
```

`clamguard ~/Downloads` does the same — that is the form a file manager uses.
`clamguard --scan` with no paths runs a quick scan, and `clamguard --page updates`
opens straight onto a page. The menu entry's right-click actions use exactly
these.

**One ClamGuard at a time.** If ClamGuard is already running — in the tray,
say — launching it again does not start a second copy: the new launch hands its
request to the one that is running, which comes to the front and does it, and
the new launch exits. Two copies would have meant two tray icons and two
schedulers running every scheduled scan twice.

### Choosing how deep

| Depth | Trade-off |
|---|---|
| **Fast** | Skips archives and anything over 25 MB. Good for a quick look at a downloads folder. |
| **Balanced** | ClamAV's normal settings. The right choice almost always. |
| **Thorough** | Deep archive recursion, unwanted-program detection, alerts on encrypted archives and documents with macros. Slower, and more false alarms. |

### Choosing the engine — and one thing worth understanding

| Engine | Speed | Uses your depth setting? |
|---|---|---|
| **Through the daemon** (`clamdscan`) | Much faster — the signature database is already in memory | **No.** The daemon uses `clamd.conf`. |
| **Directly** (`clamscan`) | Slower; loads ~3.6 million signatures on every run | **Yes.** |

This is a property of ClamAV, not of ClamGuard, and the scan page says so
rather than pretending the depth setting always applies. If a particular depth
setting matters to you, choose **Directly**. If you want those settings to
apply to daemon scans too, set them in `clamd.conf` on the Configuration page.

### While it runs

The ring shows real progress, because ClamGuard lists every file before it
starts scanning. You get an accurate percentage, a real estimate of the time
left, the file being read right now, and the throughput.

- **Pause** suspends the scan. With `clamscan` this is exact. Through the
  daemon it takes a second or two to take effect, because clamd finishes what
  is already queued.
- **Stop** ends the scan and keeps everything found so far.

---

## 4. When something is found

Nothing is deleted or moved automatically unless you ask for it. A finished
scan lists every detection with the file, the threat name and two buttons:

- **Quarantine** — move it into the vault, where it cannot run. Reversible.
- **Delete** — remove it permanently. Not reversible.

Right-clicking a detection also offers **Copy file path**, **Copy threat name**
and **Show containing folder** (which opens the folder, never the file).

### Before you delete something

ClamAV does produce false positives, particularly with **Thorough** depth, with
`DetectPUA` turned on, and on files that are not malware but resemble it —
packers, keygens, remote-access tools, security tools. Quarantine is reversible
and delete is not. Quarantine first, check, then delete.

To check a detection, search the threat name on
[clamav.net](https://www.clamav.net/) or look up the file's SHA-256 (shown on
the quarantine details panel). ClamGuard does not send anything anywhere,
including hashes, so any lookup is yours to make.

---

## 5. Quarantine

A quarantined file is moved out of its original location into
`~/.local/share/clamguard/quarantine/vault/` and rewritten XOR'd against a
fixed key. That does three things:

1. the file cannot be executed or opened by accident;
2. a later scan does not re-detect it and pile up duplicate alerts;
3. the original bytes are recoverable exactly, because XOR is its own inverse.

**This is neutralisation, not encryption.** The key is in the source code. The
point is that the file cannot run and cannot be re-detected — not that it is
secret. Anyone with access to your account could reverse it.

| Action | Effect |
|---|---|
| **Restore** | Writes the original file back where it came from, with its original permissions. The checksum is verified first. |
| **Restore somewhere else** | Same, to a location you choose. Useful when the original directory is gone or is not yours to write to. |
| **Delete** | Overwrites the vault copy and removes it. Not reversible. |
| **Check the vault** | Re-hashes every quarantined file and compares it with what was recorded. |
| **Export list** | A CSV of everything in the vault, with paths, threat names and hashes. |

Restoring a file puts live malware back on your disk. ClamGuard says this, in
those words, and the confirmation does not default to yes.

---

## 6. Signature updates

The page leads with the age of the **daily** database, because that is the one
that carries new threats. `main.cvd` changes a few times a year and
`bytecode.cvd` less often; both being months old is normal and not a problem.

- **Update now** runs `freshclam`. It needs the privileged helper.
- Each database can be verified against its digital signature with **Verify
  signature** — slow, because it hashes the whole file, but conclusive.
- After a successful update, ClamGuard asks the running daemon to reload, so
  new signatures take effect without a restart.

### "The automatic updater is already running"

Most distributions run `clamav-freshclam` as a background daemon that checks
several times a day. It holds freshclam's lock file, so a manual update usually
refuses to start — which is not a fault, it means updates are already happening.
ClamGuard recognises this specific error and says so. If you really want to run
one by hand, stop the service on the Protection page first.

---

## 7. Real-time protection

On-access scanning (`clamonacc`) checks files as they are opened, created or
moved, rather than only when you run a scan. It is the single biggest
difference between "I have an antivirus installed" and "I am protected".

It is also the part of ClamAV most likely to be misconfigured, so the Protection
page diagnoses it rather than just reporting `failed`. Each finding explains
what is wrong, shows the relevant journal lines, and offers one or two concrete
fixes. **Review and apply** shows the exact diff before anything is written.

### The problems it recognises

| Problem | Why it matters |
|---|---|
| No exclusions set | `clamonacc` exits immediately. Without an exclusion the scanner sees its own file reads as access events and scans itself forever. Excluding the account clamd runs as is the standard fix. |
| Nothing being watched | Neither `OnAccessIncludePath` nor `OnAccessMountPath` is set, so even when it starts it does nothing. |
| Blocking enabled with mount paths | `OnAccessPrevention` only blocks for `OnAccessIncludePath`. Anything covered by `OnAccessMountPath` is reported but never blocked — protection weaker than it looks. |
| Blocking on system directories | Denying access to a binary while it is executing can hang the process, and watching `/var` makes package installs about a thousand times slower. |
| Report-only mode | Detections are logged, notified and shown on this page, but access is not denied. |
| The daemon is down | `clamonacc` sends every file to `clamd`. Without it, nothing works. |
| A low inotify watch limit | One watch per directory; on a large tree it can run out and silently stop noticing new folders. Raising it is a `sysctl` change, which ClamGuard does not make for you. |

### Seeing what it catches

ClamGuard follows the daemon's journal while real-time protection is running,
so anything the on-access scanner finds appears on the Protection page under
**Caught by real-time protection** the moment it happens — with a desktop
notification and a Quarantine button, and a record in History.

This matters because without it real-time protection is invisible: it can be
working perfectly and the only evidence is a line in a log file you cannot
read. The card says **Watching** when ClamGuard is following the log, and says
so plainly when it is not.

Detections from scans you start yourself are not double-counted here — those
are already reported by the scan.

### Choosing between coverage and blocking

There are two ways to tell the on-access scanner what to watch, and they are
not interchangeable:

| | `OnAccessMountPath` | `OnAccessIncludePath` |
|---|---|---|
| How it watches | One kernel mark on the whole filesystem | One watch per directory |
| Coverage after a restart | Immediate | Only once the tree has been walked — minutes on a large home directory |
| Can block access? | **No.** Detections are reported only. | Yes, with `OnAccessPrevention yes` |
| Risk | None | Can exhaust the kernel watch limit and silently miss new folders |

So it is a real trade: complete, instant, report-only coverage, or blocking on
a narrower set of directories. You can have both by listing a mount point for
breadth and an include path for the directories where blocking matters.

Two configurations that make sense:

```
# Broad and reliable — everything is seen, nothing is blocked.
OnAccessMountPath /
OnAccessExcludeUname clamav
OnAccessPrevention no
OnAccessExtraScanning yes
```

```
# Narrower, but infected files cannot be opened.
OnAccessIncludePath /home/yourname
OnAccessExcludeUname clamav
OnAccessPrevention yes
OnAccessExtraScanning yes
```

Never put `/`, `/usr`, `/etc` or `/var` in `OnAccessIncludePath` with
prevention on — blocking a binary mid-execution hangs the process.

---

## 8. The Boot Analyzer

An antivirus checks files. The Boot Analyzer checks the thing that decides
which files get to run in the first place — the firmware, the bootloader, the
kernel, and everything on this machine that is set to start by itself.

It answers three questions that scanning cannot:

* **Is the boot chain trustworthy?** Secure Boot, the TPM, kernel lockdown,
  module signatures, `/boot` permissions, disk encryption.
* **Does anything untrustworthy start on its own?** Enabled services, desktop
  autostart entries, cron jobs, `/etc/ld.so.preload`, modprobe hooks, udev
  rules. This is the list malware wants to be on.
* **Is anything broken or slow?** Failed units, a degraded system, a pile of
  errors in the journal, and a breakdown of where the boot time went.

Press **Analyse**. It takes about three seconds and reads roughly two hundred
files.

### It changes nothing. Ever.

This is the one page in ClamGuard with no Apply button anywhere on it.

Everything it inspects — bootloader configuration, the kernel command line, ESP
permissions, sysctls — is somewhere a well-meant automatic fix turns into a
machine that will not start. So when the analyzer knows what would fix
something, it shows you the exact command, tells you what the command costs,
and gives you a **Copy** button. You run it, or you do not.

Even the "export as a shell script" option arrives with **every line commented
out**. It is a worksheet to read through, not an installer.

### Reading the result

The number at the top is out of 100, and it shows its own arithmetic
underneath — `100 − 12 (1 high) − 6 (3 low) = 82`. Every finding costs its
severity's weight: critical 25, high 12, medium 5, low 2. Nothing is hidden in
the formula.

Click a finding to open it. Inside you get:

* **What it means**, in a sentence or two.
* **Why it matters** — what an attacker actually gains, or what breaks. If a
  finding is a trade-off rather than a mistake, this is where it says so.
* **What would change it**, with the command and its risks.
* **The evidence** — the exact file or command the finding came from, and what
  it said. This is the part that lets you check ClamGuard's work rather than
  take its word.

The chips under the score (`2 medium`, `14 low`, …) filter the list. So do the
search box, the area dropdown, and the two toggles for passed and muted
findings.

> **"Show passed" is worth pressing once.** "We looked and it is fine" is not
> the same as "we did not look", and the passed list is where the difference
> shows.

### The other four tabs

| Tab | What it is for |
|---|---|
| **Boot time** | Where the seconds went, as a bar. Then the slowest units, then the critical chain — the only units that actually delayed your login screen. |
| **Service exposure** | systemd's own score, 0 to 10, for how much of the system each service could reach if something got into it. Select one to see exactly which protections it is missing. |
| **Startup surface** | Every automatic start-up on the machine in one list, whatever mechanism it uses. Flagged rows are marked. |
| **Checks** | Every check, what it reads, and a tick box to turn it off. Below that, the knobs the presets are built from. |

### Making it yours

**The preset** in the header is the quickest control. Four positions, and they
are genuinely different rather than cosmetic:

| Preset | For |
|---|---|
| **Relaxed** | A desktop that never leaves the house. Reports what is broken and what is dangerous; stays quiet about hardening you have chosen not to do. |
| **Balanced** | The default. |
| **Strict** | A machine that travels, or one you would rather over-report. |
| **Paranoid** | Treats every unverified link in the boot chain as a finding. Expect a long list — that is the point of the setting. |

**Muting** a finding keeps it in the list but stops it counting towards the
score. Use it for something you have decided about — Secure Boot off on a board
that cannot support it. It is not the same as turning the check off: the check
still runs, so if the situation changes you will still see it.

**Treat as** on any finding pins its severity, if you disagree with ClamGuard's
judgement about your particular machine.

**Savvy mode**, the switch in the header, expands the raw evidence under every
finding and adds a panel listing every file the analyzer read and every command
it ran, in order.

### Writing your own checks

⋯ → **Open the checks folder** creates `~/.config/clamguard/boot-checks.d/`
with a worked example in it. Any JSON file you put there becomes a check,
listed alongside the built-in ones and subject to the same mutes and overrides.

Six kinds are available: a sysctl value, whether a file exists, a file's
permissions, a file's contents (plain text or a regex), a kernel parameter, and
a unit's state. For example:

```json
{
  "id": "site.ssh-no-root-login",
  "title": "SSH refuses root logins",
  "category": "hardening",
  "severity": "high",
  "kind": "file_contains",
  "path": "/etc/ssh/sshd_config",
  "pattern": "^PermitRootLogin\\s+no",
  "regex": true,
  "expect": "present",
  "summary": "Our baseline says root must never log in over SSH directly."
}
```

There is deliberately **no "run this command" kind**. A check file describes
what should be true; it can never be a way to make something happen.

### Baselines: telling whether anything changed

Without a TPM measuring your boot, the practical way to answer "has my
bootloader changed?" is to write down what is there now and compare later.

⋯ → **Record a baseline** hashes everything in `/boot`,
`/etc/systemd/system`, `/etc/modprobe.d`, `/etc/udev/rules.d`, `/etc/cron.d`,
`/etc/ld.so.preload` and your own autostart directories. Do it when you have
reason to believe the machine is in a good state — straight after an install,
say.

From then on, every analysis tells you what changed. If a kernel, an initramfs
and the bootloader configuration all changed within a few minutes of each
other, it says so and calls it a likely package update — clearly labelled as a
guess, so you can check it against your package manager's log.

Two honest limits:

* It compares **files**, not what actually ran. A firmware-level implant is
  invisible to it.
* ClamGuard does not run as root, so `/boot/initramfs-*.img` (mode 0600) cannot
  be hashed. Those are tracked by size, date and permissions instead, and the
  report says which ones only got the weaker check.

### Exporting

⋯ → **Export this report** gives you four choices:

| Format | For |
|---|---|
| Markdown | Pasting into a ticket or an email. |
| HTML | Keeping or printing. Self-contained, no network. |
| JSON | Feeding to another program. |
| Shell script | Every suggested command, **commented out**, with its reason and its risk above it. |

---

## 9. Hunt — querying your logs

Every application on this machine writes a log somewhere, and nobody reads
any of them. Hunt finds those files, converts them into one table, and lets
you ask questions of the lot at once.

### What it looks for

Deliberately **not** journald or auditd — every other tool on a Linux machine
already reads those. Hunt looks where the rest of it is:

| Place | What is in it |
|---|---|
| `~/.config` | Where most desktop applications actually keep their logs |
| `~/.local/state` | Where the XDG specification says they should |
| `~/.local/share` | Steam, Akonadi, KDE services, anything installed per user |
| `~/.cache` | Short-lived logs and the crash traces that outlive them |
| `~/.var/app` | Each flatpak's private config, data and cache |
| `~/snap` | The same for snaps |
| `~/.npm/_logs` | npm's failure logs |
| `/var/log` | The readable half: pacman's transaction record, Xorg, and so on |

Two more are **off by default** and have to be turned on in Hunt settings:
`/tmp`, which is noisy, and your shell history, which is the most sensitive
file in your home directory and is not something to index because it
technically matches.

The **systemd journal** is read too, but only when you ask — see below.

**auditd is not read.** `/var/log/audit` is mode 0700 root-only, and ClamGuard
never runs as root and adds no privileged helper verb to get around that. The
Sources dialog lists the directory under Skipped with that reason rather than
pretending it is not there. A few audit records reach the journal on their own
and those are indexed like anything else.

### Starting

Open **Hunt** in the sidebar (Ctrl+7) and press **Search for logs**. It takes
a couple of seconds. You then get a dialog with three tabs:

- **Found** — everything it will index, with a tick box each.
- **Indexed** — what is already in, and how much of each file has been read.
- **Skipped** — everything that matched and was *not* indexed, **with the
  reason**. A missing log that is unexplained reads as a bug; one with
  "binary (contains null bytes)" next to it reads as a decision. Directories
  that could not be opened at all are listed here too — `/var/log/audit` and
  `/var/log/private` on a typical machine.
- **Journal** — the systemd journal, which is not a file and so is not in the
  crawl at all.

Press **Index selected**. On a well-used desktop that is usually one to two
hundred megabytes and about fifteen seconds.

**Indexing again is nearly free.** Each file remembers the byte offset it was
read up to, so a second index only reads what has appeared since — a tenth of
a second for the same two hundred megabytes. A file that was rotated or
truncated is noticed by a hash of its head and re-read from the start.

### What it understands

About twenty log formats, recognised by running every parser over a sample of
each file and keeping the one that understood the most:

JSON Lines · logfmt · syslog (RFC 3164 and 5424) · Chromium ·
Abseil (Discord) · electron-log · Python and log4j · Go's standard logger ·
pacman · Xorg · nginx · Apache/nginx access logs · npm · CSV · and a
timestamp-first fallback for anything else.

Whatever the format, every line ends up with the same three things —
`Timestamp`, `Level`, `Message` — plus an `Extra` bag holding whatever else
that format knew, such as `Extra.pid` or `Extra.thread`.

### Asking questions

The query language is **KQL** — the same one Azure Sentinel uses.

```kql
Logs
| where Level == "error"
| summarize Count = count() by App
| sort by Count desc
```

Press **Ctrl+Enter** to run. **Ctrl+Space** completes; the list knows where
the cursor is, so it offers operators after a `|`, columns inside a `where`
and aggregates inside a `summarize`. A mistake is underlined as you type, with
the message on hover and a suggestion where there is an obvious one.

The **Queries** tab on the left has forty-five worked examples, grouped:
getting started, errors and failures, security, applications, volume and
timing, the index itself, and ClamAV. Double-click one to run it. The
**Tables** tab lists every column with what it holds, and every indexed file
grouped by application. **Functions** lists all hundred and thirty with their
signatures.

`docs/KQL.md` is the full reference.

### The systemd journal

Off until you ask for it. Open **Sources → Journal** and press **Read the
journal now**, or turn it on in Hunt settings.

It is read with `journalctl --output=json`, as you — no root, no helper, so it
sees exactly what you would see typing the same command. If you are in the
`systemd-journal` group (or `wheel` on many distributions) that is the whole
journal; if not, it is your own entries, and the Journal tab says which.

**Each systemd unit becomes its own source.** That is the point of indexing
it: `App` names `sshd.service`, `kernel`, `NetworkManager.service` rather than
saying "journal" a hundred thousand times, so

```kql
Logs
| where Location == "journal"
| summarize Entries = count(), Errors = countif(Level in ("error", "critical"))
         by App
| sort by Errors desc
```

tells you which part of the system is unhappy. Every journal field worth
having is in `Extra` — `Extra.pid`, `Extra.transport`, `Extra.code_file`.

**It resumes.** journald gives out a cursor, which is a position in the
journal, and Hunt stores it. The next read starts from there and costs only
what is new. If that cursor has expired — the journal was rotated or vacuumed
since — journalctl says so, and Hunt reads the configured window again and
tells you it did, rather than reporting "nothing new" forever.

**Mind the size.** The journal is usually far larger than every log file put
together. On the machine this was written for it holds 11.3 million entries,
7 million of them in the last week, against 1.1 million from 1,278 log files.
So the defaults are deliberately small:

| Setting | Default | Note |
|---|---|---|
| How far back | This boot | ~50,000 entries on a desktop. Also: Last 24 hours, 7 days, 30 days, Everything. |
| Keep | Everything | Or notice / warnings / errors and worse. |
| Most per pass | 250,000 | A pass that hits this is **not** a loss — the rest is read next time, from where it stopped. |

**Forget the journal** on the same tab removes every journal entry and the
saved position, and leaves your log files alone.

### The thing that surprises everybody

**About two thirds of the events have no timestamp**, because half the log
formats on a Linux desktop do not write one — Unity's `Player.log` does not,
Steam's console logs do not, and Xorg writes seconds since the server started
rather than a wall-clock time.

Those lines are indexed and searchable, but the time-range picker cannot see
them. The toolbar has a chip saying how many there are, and if a query comes
back empty the page says so directly. Switch the range to **All time** to
include them.

### Charts

Add `| render` and the Chart tab fills in:

```kql
Logs
| where isnotnull(Timestamp)
| summarize Events = count() by App, bin(Timestamp, 1h)
| sort by Timestamp asc
| render timechart
```

`timechart`, `linechart`, `areachart`, `columnchart`, `barchart`, `piechart`,
`scatterchart` and `card`.

### Insights — the rules

The **Insights** tab runs a set of analytics rules over the index and reports
what fired. Sixteen ship with the application:

| | |
|---|---|
| Downloads piped into a shell | Encoded or obfuscated commands |
| Repeated crashes | Repeated authentication failures |
| Error storms | Out of memory or disk |
| New log files this week | Gaps where a log stopped |
| Certificate and TLS failures | Public addresses in the logs |
| Privilege escalation tools | Mentions of autostart and cron |
| Activity in the middle of the night | ClamAV detections |
| Bursts of file errors | Files taking over the index |

Every finding shows **the query that produced it** and offers to open it in
the editor. That is the point: a tool that says "suspicious activity detected"
and will not say how is asking to be believed, and this one would rather be
checked. Rules that matched nothing are listed too, so a clean result is
visible rather than merely implied.

You can write your own. A rule is a JSON file in
`~/.config/clamguard/hunt-rules.d/` holding a query, a threshold and an
explanation — *Where rules live…* in the `⋯` menu opens the directory with a
worked example already in it. A rule cannot run a command, write a file or
reach the network, because the engine it runs on cannot.

### Saving, exporting, and getting it fast

**Save** keeps a query in the left rail along with the time range it was saved
with. A rolling range is saved as rolling, so "Last 24 hours" still means the
last 24 hours next year.

**Export** writes the current result as CSV, TSV, JSON or Markdown. The CSV
export prefixes any cell starting with `=`, `+`, `-` or `@` with a tab, so a
log line cannot be executed as a formula by whoever opens it.

The status strip says how many rows came back, how long it took, and **how
many rows were read out of the store**. The gap between the last two is the
whole performance story, and **Query details** in the `⋯` menu shows the SQL
the planner produced and which parts of your query it managed to answer from
an index. Filtering on `Timestamp`, `Level`, `App` or `Source` first — or just
narrowing the time range — is what makes a slow query fast.

### What Hunt will not do

- **It never writes to a log file.** Discovery reads, and nothing else.
- **It runs exactly one command, ever.** Reading the journal means running
  `journalctl`, and that is confined to a single module which may run that one
  program, resolved through `PATH`, with every argument checked against an
  allow-list before the process starts and no shell involved. Nothing else in
  Hunt can run anything at all. The flags that would let journalctl rotate,
  vacuum or erase the journal are not expressible.
- **A query cannot change anything.** Queries run on a database connection
  opened read-only at the operating-system level, not merely on a promise that
  the compiler is careful. `evaluate`, `externaldata` and `invoke` — the KQL
  operators that load a plugin, fetch a URL or call a server — are refused by
  name, with the reason.
- **Nothing leaves the machine.** The index is at
  `~/.local/share/clamguard/hunt.db`, mode 0600, and the only way anything
  gets out is a file dialog you opened.
- **It needs no administrator rights** and adds nothing to the privileged
  helper.

### Keeping it bounded

The index holds up to 5,000,000 events, 120 days and 2 GB by default —
whichever runs out first. All three can be changed or switched off in **Hunt
settings**. Retention removes the events that were *indexed* longest ago
rather than the oldest by timestamp, because two thirds of them have no
timestamp and guessing one in order to delete on the guess would be worse than
keeping them.

**Forget everything indexed** in the `⋯` menu empties the database. Your log
files are not touched.

---

## 10. Services — what is running, and why

Every systemd unit on this machine, and for each one everything ClamGuard could
find out about what it is for.

`systemctl status` already tells you whether something is running. It does not
tell you that nothing on the machine requires it, that it cost twenty-four
seconds of your last boot, which package installed it, or that your
distribution ships it switched off. Those facts exist and are a second away;
this page is where they meet.

### The list

Four columns — the unit, its state, whether it starts on its own, and one line
of what it is. Click any row and the panel on the right fills in.

The **search box** matches the unit's name, its description *and* its package,
so typing `cups` finds everything the printing stack installed rather than only
the unit called `cups`.

### The filters are the point

"Show me what is failing" is easy anywhere. These are the questions that
actually find something:

| Filter | What it answers |
|---|---|
| **Changed from the distribution default** | What did somebody switch on or off here? |
| **No package owns it** | Which unit files were added by hand? |
| **Locally overridden** | Which packaged units have a local `override.conf`? |
| **Slow at boot** | What is actually costing you start-up time? |
| **Masked** | What has been forcibly disabled? |
| **Worth a look** | Anything with a flag on it |

### The detail panel

Top to bottom, in the order you usually want it:

**Worth knowing** — only things you might act on. A failed unit, a local
override, a unit nothing owns, one that deviates from the distribution default,
one that ate your boot. A healthy packaged service shows this card not at all.

**What it is** — every source, labelled separately rather than blended, because
they genuinely say different things. The unit file names *this unit* ("ClamAV
On-Access Scanner"); the man page describes *the program* ("an anti-virus
on-access scanning daemon and clamd client"); the package describes *the
project* ("Anti-virus toolkit for Unix"). Underneath, structural notes: that
this is a template instance, that it is socket-activated and does not run
continuously, that a one-shot being inactive is success.

**Why it is here** — what pulled it in, what waits for it, and what would break
if it stopped. If nothing on the machine depends on it, the page says so.

**The details** — state, uptime, type, restart policy, user, memory, CPU,
tasks, boot time, sandboxing score, dependencies.

**What it runs**, **Files** (including which drop-ins are yours), **Read more**
(its man pages and homepage), and **Commands**.

### It cannot change anything

There is no Start button, and that is deliberate. ClamGuard's privileged helper
accepts a fixed list of ClamAV unit names and refuses every other one. Letting
a browser widen that would turn "this app can control ClamAV" into "this app
can control this machine" — for a page whose job is to explain.

So the Commands card gives you the exact `systemctl` line with a Copy button,
the same way the Boot Analyzer offers its remedies. You run it; ClamGuard does
not. Commands for your session's units use `systemctl --user` and never `sudo`
— they are yours, and several share a name with a system unit you would not
want to restart by accident. The copy button beside a unit's name gives you
the name exactly as systemd spells it.

### System units and session units

The picker at the top right switches between the machine's own units and the
ones your login session runs. On a desktop the second list is most of your
session — the Wayland compositor, the portals, the agents.

### What may be missing, and why

The page uses five optional helpers. If one is absent a row disappears and the
notice at the top says which and why:

- **`pacman` / `dpkg` / `rpm`** — without one, no unit can be traced to a
  package, and "no package owns it" stops meaning anything.
- **`whatis`** (from man-db) — man page one-liners.
- **`systemd-analyze`** — sandboxing scores and boot times.
- **`ss`** (from iproute2) — listening ports.

**Ports are the honest exception.** Run as you, `ss` lists every listening
socket but only names the process behind your *own*. Every system service runs
as somebody else, so unprivileged ClamGuard can see the sockets and attach none
of them. The page says that rather than showing an empty row, which would read
as "nothing is listening". `sudo ss -lntup` is what you want.

## 11. Scheduled scans

Set up under **Preferences → Scheduled scans**. Hourly, daily, weekly or
monthly, with a scope and a depth.

**Scheduled scans only run while ClamGuard is running.** This is deliberate —
ClamGuard does not install systemd timers behind your back — but it means:

- keep the tray icon on (**Preferences → Behaviour**), and
- turn on **Start ClamGuard when I log in** if you want them to happen reliably.

If a scheduled time passes while ClamGuard is closed, it runs once on the next
launch if **Run it late** is on. Only once, however long the app was closed.

---

## 12. History and logs

**History** records every scan in a local SQLite database: what was scanned,
how long it took, and every detection with what you did about it. Filter by
kind, period or text; export a single scan as a text report or a CSV of its
detections.

**Logs** shows what ClamAV itself is reporting. The default source is the
systemd journal, because the log files in `/var/log/clamav/` are owned by the
`clamav` user and a normal account cannot read them. Filter by text, show
problems only, or follow live. **Read as administrator** opens the real file
through the helper when you need it.

---

## 13. Editing ClamAV's configuration

Every option in `clamd.conf` and `freshclam.conf` — 182 of them — typed, grouped
and searchable. The help text under each one is ClamAV's own documentation,
read from the comments in the file, so it always matches your installed
version.

Options marked **Careful** can stop ClamAV from starting if they are wrong.
**Advanced** hides the ones most people never touch (an advanced option that is
actually set stays visible regardless).

### What happens when you save

1. **Preview changes** shows a unified diff. Nothing is written yet.
2. **Review and save** shows the same diff again in a confirmation, naming the
   file and the services that will restart.
3. You authenticate through polkit.
4. The helper validates the new file with `clamconf`. If ClamAV would reject
   it, nothing is written and you are told why.
5. The current file is copied to `clamd.conf.clamguard-YYYYMMDD-HHMMSS.bak`.
6. The new file replaces it atomically, keeping the original owner and mode.
7. The affected services are restarted one at a time, in order.

If you have not installed the helper, everything above still works up to step 2
— you can copy the diff and apply it by hand.

---

## 14. Administrator rights

ClamGuard never runs as root. When it needs to do something privileged it asks
`pkexec` to run one script:

```
/usr/local/lib/clamguard/clamguard-helper
```

That script is under 500 lines of code, has no dependencies beyond the Python
standard library, and imports nothing from ClamGuard. It accepts a closed list
of verbs and refuses everything else:

| Verb | What it does |
|---|---|
| `status` | Prints its version. |
| `read-file` | Prints one of a fixed list of ClamAV config files, or the last 4 MB of a ClamAV log. |
| `write-config` | Validates with `clamconf`, backs up, replaces one ClamAV config file. |
| `service` | `systemctl start/stop/restart/enable/disable`, ClamAV units only. |
| `update-db` | Runs `freshclam`. |
| `quarantine` | Moves a root-owned file into your vault — but only after ClamAV, run by the helper itself, confirms the file is infected. |
| `restore` | Restores a quarantined file into the folder it came from, per the helper's own root-owned record. |

Paths and unit names are checked inside the helper, not in the GUI. The two
verbs that touch files are deliberately narrow:

- **quarantine** will not move a file unless ClamAV flags it, verified by the
  helper rather than taken on trust: it scans the exact bytes it is about to
  move. It cannot be used to read or delete an arbitrary file as root.
- **restore** is given an entry id, never a path. Where the file goes, and what
  owner and permissions it gets, come from a record the helper keeps in
  `/var/lib/clamguard/records/` — root-owned and not editable by you. The
  metadata in your home directory is shown in the UI but never trusted.
  setuid and setgid bits are always stripped. And the file only goes back into
  the same real folder it came from: if a folder on the way has since been
  replaced by a link to somewhere else, the restore is refused. Use **Restore
  somewhere else** instead, or move it back by hand.

Restoring into `/usr`, `/bin`, `/etc/cron*`, `/etc/profile.d`, `/root` and
similar is refused outright. Every invocation is logged to
`/var/log/clamguard-helper.log`.

The polkit policy uses `auth_admin_keep`, which means a few minutes pass after
you authenticate before you are asked again. Change `allow_active` to
`auth_admin` in `/usr/share/polkit-1/actions/org.clamguard.helper.policy` if
you would rather be asked every single time.

To remove it:

```bash
sudo ./packaging/install-helper.sh --uninstall
```

---

## 15. Your data

```
~/.config/clamguard/
    settings.json            preferences
    schedules.json           scheduled scans
    boot-profile.json        Boot Analyzer preset, mutes and tuning
    boot-checks.d/           Boot Analyzer checks you wrote yourself
    hunt.json                Hunt: where to look, what to keep, limits
    hunt-queries.json        Hunt: queries you saved
    hunt-history.json        Hunt: the last hundred queries you ran
    hunt-rules.d/            Hunt: analytics rules you wrote yourself
~/.local/share/clamguard/
    history.db               scan history (SQLite)
    hunt.db                  the indexed events, log files and journal
                             alike (SQLite, mode 0600)
    quarantine/vault/        quarantined file payloads
    quarantine/meta/         where each came from
    boot-baseline.json       the recorded state of the boot chain
    logs/clamguard.log       what the app itself did
~/.cache/clamguard/
    generated/               rendered stylesheet glyphs
```

`hunt.db` is the big one — roughly twice the size of the logs it indexed, and
the only file here that can reach a gigabyte. It is mode 0600 because log
lines occasionally contain tokens. **Forget everything indexed** on the Hunt
page empties it; Hunt settings caps how large it is allowed to get.

Removing those three directories removes every trace of ClamGuard from your
account. Nothing else is written unless you explicitly run `install.sh` (which
adds a menu entry) or `install-helper.sh` (which adds the helper).

ClamGuard has no telemetry, no account, no crash reporting and no update check.
The only network traffic on this machine from any of this is ClamAV downloading
its own signature updates from `database.clamav.net`.

---

## 16. Troubleshooting

### ClamGuard says it needs PySide6

It prints the command for your distribution; see also the table in the
[README](../README.md#getting-it-running). If PySide6 is installed but ClamGuard
still says this, one of the three modules it needs is missing — on Debian and
Ubuntu they are separate packages, and `python3-pyside6.qtnetwork` is the one
people miss.

### "Could not load the Qt platform plugin xcb"

Qt 6.5 and later needs `libxcb-cursor0` for X11, and PySide6 from PyPI does not
bring it along. `sudo apt install libxcb-cursor0` (or your distribution's
equivalent) fixes it.

### "ClamAV is not installed"

Install it. Arch: `sudo pacman -S clamav`. Debian/Ubuntu:
`sudo apt install clamav clamav-daemon`. Fedora:
`sudo dnf install clamav clamd clamav-update`.

### Scans are very slow

Check the Scan page's engine notice. If the daemon is not responding, every
scan loads 3.6 million signatures from scratch — several seconds and several
hundred megabytes of RAM each time. Start the scanning daemon on the Protection
page and scans get several times faster.

### "The ClamAV daemon is not responding"

Look at the Protection page. Usually the service is stopped, or `clamd.conf`
has no `LocalSocket` line. The Logs page shows what `clamd` said when it tried
to start.

### Real-time protection will not start

Open the Protection page. The diagnosis is there, along with the fix. The most
common cause by far is missing exclusions — see [section 7](#7-real-time-protection).

### The window closed but ClamGuard is still running

That is **Preferences → Behaviour → Closing the window hides it instead of
quitting**, which is on by default so scheduled scans keep working. Use **Quit**
in the tray menu, or turn the setting off.

### A file I know is safe keeps being detected

Either exclude it (**Preferences → Never scan paths matching**, a regular
expression) or, if it is a whole category, turn off the setting that catches it
— `DetectPUA`, `AlertOLE2Macros` and `AlertEncrypted` are the usual ones, all on
the Configuration page under Detection.

### Something went wrong and I want the details

`~/.local/share/clamguard/logs/clamguard.log`, or run `./clamguard --verbose`
from a terminal.
