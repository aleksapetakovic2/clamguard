# Security policy

ClamGuard is a security tool, and one part of it runs as root, so security
reports are welcome and taken seriously.

## Reporting a vulnerability

Please report it privately, through this repository's **Security** tab →
**Report a vulnerability**. Do not open a public issue for anything that could
be exploited.

Say what you found, how to reproduce it, and what it lets an attacker do. The
fix is worked on privately and published together with the details; you are
credited, unless you would rather not be.

## What matters most

- **The privileged helper** — `packaging/clamguard-helper`, which runs as root
  through pkexec, together with `packaging/install-helper.sh` and the polkit
  policy. Anything that makes the helper act outside its allow-lists is the
  most serious kind of bug here: reading, writing, deleting or changing the
  owner of a file it should not; running a program it should not; controlling
  a unit that is not ClamAV's. [ARCHITECTURE.md → Privilege
  boundary](ARCHITECTURE.md#privilege-boundary) describes what the helper is,
  and is not, meant to stop.
- **Hostile input.** File names, log lines, unit descriptions and ClamAV's own
  output are written by someone else. None of it may ever be interpreted as
  markup, as a command, as SQL, or as a spreadsheet formula on export.
- **The quarantine** — a quarantined file becoming runnable or detectable
  again, or being restored somewhere, or with permissions, it did not have.
- **The single-instance socket** (`$XDG_RUNTIME_DIR/clamguard.sock`) accepting
  anything beyond the documented requests.

## Not in scope

- ClamAV itself. Report those to the ClamAV project:
  <https://github.com/Cisco-Talos/clamav/security>.
- Missed detections and false positives. Those are signature questions for
  ClamAV, not bugs in ClamGuard.
- Anything that needs the attacker to be root already, or to know the
  administrator's password. Such an attacker does not need the helper.
- The quarantine's XOR "neutralisation" using a key that is in the source. It
  is documented as neutralisation, not encryption: its job is to stop a
  quarantined file being run or re-detected by accident.

## Supported versions

Only the latest commit on `main`. Fixes are not backported.
