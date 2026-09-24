# ClamGuard

[![Tests](https://github.com/aleksapetakovic2/clamguard/actions/workflows/tests.yml/badge.svg)](https://github.com/aleksapetakovic2/clamguard/actions/workflows/tests.yml)

A modern desktop antivirus for Linux, built on ClamAV.

ClamAV is an excellent scanning engine with no front end worth using. ClamGuard
is the missing application around it: a dashboard that tells you whether you are
actually protected, scans that show you what they are doing, a real quarantine,
signature updates you can see, a configuration editor that shows you the diff
before it touches `/etc`, a Boot Analyzer that checks the part of the machine
a file scanner can never reach, and a log hunter that finds every log file on
the machine and lets you query the lot in KQL.

```
┌──────────────┬────────────────────────────────────────────┐
│  ClamGuard   │   Protected                                │
│              │   3,642,773 signatures, updated 19 hours   │
│  Dashboard   │   ago. Last scan: today, no threats.       │
│  Scan        │                                            │
│  Quarantine  │   [ Quick scan ]  [ Update now ]           │
│  Updates     │                                            │
│  Protection  │   Scanning daemon      ● Running           │
│  Services    │   Signature updates    ● Running           │
│  Boot        │   Real-time protection ● Failed  → Fix     │
│  Hunt        │                                            │
│  History     │                                            │
│  Logs        │                                            │
│  Settings    │                                            │
└──────────────┴────────────────────────────────────────────┘
```

## What it does

- **Dashboard** — one honest answer to "am I protected?", with the reasons.
- **Scanning** — quick, full, custom and removable-media scans; live progress
  with the current file, throughput and a real estimate; pause, resume, stop.
  Uses the ClamAV daemon when it is running, which is several times faster.
- **Quarantine** — detections are moved into a private vault, neutralised so
  they cannot be run or re-detected, with everything needed to put them back.
- **Updates** — signature versions, counts and age; update on demand and watch
  freshclam work.
- **Real-time protection** — start, stop and diagnose the on-access scanner,
  including the misconfigurations that stop it booting.
- **Boot Analyzer** — 44 checks over the firmware, the bootloader, the kernel
  and everything set to start automatically: Secure Boot, the TPM, kernel
  lockdown, module signing, CPU mitigations, `/boot` permissions, disk
  encryption, `ld.so.preload`, suspicious autostart entries and cron jobs,
  failed units, service sandboxing scores, and where your boot time went. It
  shows its evidence, shows its arithmetic, and changes nothing — every fix is
  a command you copy.
- **Hunt** — every log file on this machine that nobody reads: `~/.config`,
  `~/.local/share`, `~/.local/state`, `~/.cache`, flatpak's `~/.var/app`, and
  the readable half of `/var/log` — plus the systemd journal when you ask for
  it, with each unit becoming its own source so `App` names `sshd.service`
  rather than "journal". About twenty formats recognised and converted into
  one table, incrementally, then queried in **KQL** — the language Azure
  Sentinel uses — with a real editor, forty-five worked examples, charts, and
  a set of analytics rules that each show the query that produced them.
- **Services** — every systemd unit on the machine and what each one is *for*:
  the package that installed it, its man page summary, what pulled it in, what
  would break without it, its sandboxing score and what it cost at boot. Filter
  by the questions that actually find things — what deviates from the
  distribution's default, what no package owns, what carries a local override,
  what ate your boot time. It changes nothing; every action is a command you
  copy.
- **History** — every scan kept in a local database, searchable, exportable.
- **Logs** — live tail of ClamAV's journal and log files with filtering.
- **Configuration** — all 182 clamd and freshclam options, typed, grouped and
  searchable, with ClamAV's own documentation inline.

## What it will not do

It will not change a single system setting without showing you exactly what
will change and waiting for you to agree. It never runs as root — a small,
separately installed helper does the few privileged things, and you can read
all of it in one sitting: [`packaging/clamguard-helper`](packaging/clamguard-helper).

Hunt reads every log file it can find, and the systemd journal, which is a
great deal of text that something else wrote. None of it is ever interpreted — not as markup, not as a
command, not as a spreadsheet formula on the way out. Its query language runs
on a database connection the operating system opened read-only, so a query
cannot change the index even if the engine had a bug in it, and the KQL
operators that fetch a URL or load a plugin are refused by name with the
reason. Reading the journal means running `journalctl`, and that is the only
command anything in Hunt may run: one module, one program, every argument
checked against an allow-list, no shell.

The Boot Analyzer goes further and has no Apply button at all. It inspects
bootloaders, kernel command lines and ESP permissions — the settings where a
well-meant automatic fix becomes a machine that will not start — so it hands
you the command and a Copy button, and leaves the decision where it belongs.

It sends nothing anywhere. There is no telemetry, no account, and no network
traffic except the signature downloads ClamAV itself makes.

## Requirements

- Linux with ClamAV 1.0 or newer (`clamav` on most distributions)
- Python 3.11 or newer
- PySide6 6.8 or newer, with its QtWidgets, QtSvg and QtNetwork modules
- Optional: `polkit` for the privileged features, `systemd` for service control

## Getting it running

```bash
git clone https://github.com/aleksapetakovic2/clamguard.git
cd clamguard
./clamguard
```

There is no build step. The launcher finds a Python that has PySide6 and starts
the app; if there is none, it says what to install. On most distributions that
is one command:

| Distribution | Command |
|---|---|
| Arch, Manjaro | `sudo pacman -S pyside6` |
| Fedora | `sudo dnf install python3-pyside6` |
| Debian 13+, Ubuntu 25.10+ | `sudo apt install python3-pyside6.qtwidgets python3-pyside6.qtsvg python3-pyside6.qtnetwork` |

**Ubuntu 24.04 and 22.04 do not package PySide6 at all**, and neither do some
other distributions. Install it from PyPI into a `.venv` inside the checkout,
which the launcher (and the menu entry, and the test runner) find by
themselves:

```bash
sudo apt install python3-venv          # Debian and Ubuntu only
python3 -m venv .venv
.venv/bin/pip install PySide6-Essentials
```

If Qt then says it could not load the `xcb` platform plugin, install
`libxcb-cursor0`.

To add ClamGuard to your application menu (user-level, no root):

```bash
./install.sh
```

To enable the privileged features — editing `/etc/clamav`, controlling ClamAV's
services, running updates — install the helper yourself:

```bash
sudo ./packaging/install-helper.sh
```

Read that helper first. It is the only thing here that runs as root, and it is
under 500 lines of code with the reasoning for each check written next to it.

To update, `git pull`. If the helper changed, run the helper installer again.

## Where your data lives

```
~/.config/clamguard/     settings and schedules
~/.local/share/clamguard/  scan history, quarantine vault, app log
~/.cache/clamguard/      rendered icons
```

Deleting those three directories removes every trace of ClamGuard from your
account. Nothing is written outside them unless you explicitly install the
helper or the desktop entry.

## Documentation

| File | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the code is laid out |
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Using the app |
| [docs/KQL.md](docs/KQL.md) | The query language on the Hunt page |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | Working on the code |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability |

## Licence

ClamGuard is free software: you can redistribute it and/or modify it under the
terms of the [GNU General Public License, version 2](LICENSE), or (at your
option) any later version. It comes with no warranty; see the licence for
details. ClamAV itself is GPL v2; PySide6 is used under the LGPL v3.
