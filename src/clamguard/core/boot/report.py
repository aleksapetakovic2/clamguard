"""Turning a Report into something you can keep, send, or act on.

Four formats, each with a different reader in mind:

``markdown``
    For pasting into a ticket or an email. Plain text, readable unrendered.
``json``
    For another program. Stable keys; the same shape as ``Report.to_dict``.
``html``
    For keeping. Self-contained, no external assets, prints sensibly.
``script``
    Every suggested fix as a shell script, **commented out**, with the reason
    above each one. It is a worksheet, not an installer: the user uncomments
    what they agree with. ClamGuard will not run it.

That last one is the whole posture of this feature in one file. The Boot
Analyzer knows how to change your bootloader, your sysctls and your kernel
command line, and it deliberately does none of it.
"""

from __future__ import annotations

import html
import json

from .model import CATEGORY_ORDER, Report, Severity, format_duration

#: What the exports are called by default. The caller adds a directory.
DEFAULT_STEM = "boot-analysis"


def filename(report: Report, extension: str) -> str:
    stamp = report.started_at.strftime("%Y%m%d-%H%M")
    host = (report.hostname or "machine").replace("/", "-")
    return f"{DEFAULT_STEM}-{host}-{stamp}.{extension}"


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def to_markdown(report: Report, *, include_passes: bool = False) -> str:
    """A report you can paste into a ticket."""
    out: list[str] = []
    add = out.append

    add(f"# Boot analysis — {report.hostname or 'this machine'}")
    add("")
    add(f"*{report.started_at:%Y-%m-%d %H:%M}* · "
        f"{report.distribution or 'unknown distribution'} · "
        f"kernel {report.kernel or 'unknown'} · "
        f"{report.preset} profile · analysed in {report.duration:.1f}s")
    add("")
    add(f"**Score {report.score}/100 — {report.grade}.** {report.headline()}")
    add("")

    if report.score_working():
        add(f"> {report.score_explanation()}")
        add("")

    if report.facts:
        add("| | |")
        add("|---|---|")
        for key, value in report.facts.items():
            add(f"| {key} | {value} |")
        add("")

    if report.timings and report.timings.measured:
        phases = " + ".join(f"{phase.text} ({phase.name})"
                            for phase in report.timings.phases)
        add(f"**Boot time** {report.timings.total_text} — {phases}")
        add("")

    for category in CATEGORY_ORDER:
        items = [item for item in report.by_category(category)
                 if include_passes or item.is_problem]
        if not items:
            continue
        add(f"## {category.title}")
        add("")
        for item in items:
            mark = "✔" if item.severity is Severity.PASS else "•"
            muted = " *(muted)*" if item.muted else ""
            add(f"### {mark} {item.title}{muted}")
            add("")
            add(f"**{item.severity.label}** · `{item.id}`"
                + (f" · observed: `{item.value}`" if item.value else "")
                + (f" · expected: `{item.expected}`" if item.expected else ""))
            add("")
            if item.summary:
                add(item.summary)
                add("")
            if item.impact:
                add(f"*Why it matters.* {item.impact}")
                add("")
            for fix in item.fixes:
                add(f"**Fix — {fix.title}**"
                    + ("  *(needs a reboot)*" if fix.reboot_required else ""))
                if fix.explanation:
                    add("")
                    add(fix.explanation)
                if fix.command:
                    add("")
                    add("```bash")
                    add(fix.command)
                    add("```")
                if fix.manual:
                    add("")
                    add(f"Manually: {fix.manual}")
                if fix.risk:
                    add("")
                    add(f"⚠ {fix.risk}")
                add("")
            for evidence in item.evidence:
                add(f"<details><summary>Evidence — {evidence.source}</summary>")
                add("")
                add("```")
                add(evidence.content.strip())
                add("```")
                add("")
                add("</details>")
                add("")
        add("")

    if report.skipped:
        add("## Checks that did not run")
        add("")
        for item in report.skipped:
            add(f"- **{item.title}** — {item.reason}")
        add("")

    add("---")
    add("")
    add("Produced by ClamGuard's Boot Analyzer. Every check is read-only; "
        "nothing on this machine was changed.")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def to_json(report: Report) -> str:
    """The whole report as JSON, for another program to read."""
    return json.dumps(report.to_dict(), indent=2, sort_keys=False) + "\n"


# ---------------------------------------------------------------------------
# The worksheet
# ---------------------------------------------------------------------------


def to_script(report: Report) -> str:
    """Every suggested command, commented out, with its reason above it.

    Deliberately not runnable as written. Someone who wants to apply these has
    to read each one and remove a ``#``, which is the smallest possible speed
    bump in front of a script that edits bootloaders and sysctls. Nothing in
    ClamGuard ever executes this file.
    """
    out: list[str] = []
    add = out.append

    add("#!/bin/bash")
    add("#")
    add(f"# Suggested changes from ClamGuard's Boot Analyzer, "
        f"{report.started_at:%Y-%m-%d %H:%M}")
    add(f"# Machine: {report.hostname}  ·  kernel {report.kernel}"
        f"  ·  profile: {report.preset}")
    add("#")
    add("# EVERY COMMAND BELOW IS COMMENTED OUT, ON PURPOSE.")
    add("#")
    add("# These change the bootloader, the kernel command line, sysctls and")
    add("# file permissions on system directories. Read each one, understand")
    add("# what it does and what it costs, then uncomment the ones you want.")
    add("# Several of them can stop the machine booting if they are wrong for")
    add("# your setup — the risk notes say which.")
    add("#")
    add("# ClamGuard did not run any of this and will not.")
    add("")
    add("set -euo pipefail")
    add("")

    written = 0
    for category in CATEGORY_ORDER:
        items = [item for item in report.by_category(category)
                 if item.is_problem and any(fix.has_command for fix in item.fixes)]
        if not items:
            continue
        add("")
        add("# " + "=" * 70)
        add(f"# {category.title}")
        add("# " + "=" * 70)
        for item in items:
            add("")
            add(f"# [{item.severity.label}] {item.title}")
            for line in _wrap(item.summary, 74):
                add(f"#   {line}")
            if item.expected:
                add(f"#   observed {item.value!r}, expected {item.expected!r}")
            for fix in item.fixes:
                if not fix.has_command:
                    if fix.manual:
                        add(f"#   Manual step: {fix.manual}")
                    continue
                add("#")
                add(f"#   Fix: {fix.title}"
                    + ("  (needs a reboot)" if fix.reboot_required else ""))
                for line in _wrap(fix.explanation, 72):
                    add(f"#     {line}")
                if fix.risk:
                    for line in _wrap("RISK: " + fix.risk, 72):
                        add(f"#     {line}")
                for line in fix.command.splitlines():
                    add(f"# {line}")
                    written += 1
        add("")

    if not written:
        add("# Nothing to suggest — no finding in this report has a command.")
    add("")
    add("echo 'Nothing happened: every command in this file is commented out.'")
    return "\n".join(out) + "\n"


def _wrap(text: str, width: int) -> list[str]:
    import textwrap

    if not text:
        return []
    return textwrap.wrap(text, width) or []


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_TONE_COLOURS = {
    "danger": "#dc2626",
    "warn": "#d97706",
    "info": "#2563eb",
    "ok": "#15a34a",
}

_STYLE = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
       margin: 0; padding: 2rem 1.25rem 4rem; line-height: 1.55;
       background: #f6f7f9; color: #111827; }
main { max-width: 56rem; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
h2 { font-size: 1.1rem; margin: 2.5rem 0 .75rem; padding-bottom: .4rem;
     border-bottom: 1px solid #d8dde5; }
.meta { color: #5a6579; font-size: .85rem; margin-bottom: 1.5rem; }
.score { display: flex; align-items: center; gap: 1.25rem;
         background: #fff; border: 1px solid #e2e6ee; border-radius: 14px;
         padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; }
.score .number { font-size: 2.8rem; font-weight: 700; line-height: 1; }
.score .grade { font-size: .8rem; text-transform: uppercase;
                letter-spacing: .08em; color: #5a6579; }
.working { font-family: ui-monospace, monospace; font-size: .8rem;
           color: #5a6579; margin-top: .4rem; }
.facts { display: flex; flex-wrap: wrap; gap: .5rem; margin-bottom: 1.5rem; }
.fact { background: #fff; border: 1px solid #e2e6ee; border-radius: 999px;
        padding: .3rem .8rem; font-size: .8rem; }
.fact b { font-weight: 600; }
.finding { background: #fff; border: 1px solid #e2e6ee; border-radius: 12px;
           padding: 1rem 1.15rem; margin-bottom: .75rem;
           border-left: 4px solid var(--tone); }
.finding h3 { margin: 0 0 .35rem; font-size: 1rem; }
.badge { display: inline-block; font-size: .7rem; font-weight: 700;
         text-transform: uppercase; letter-spacing: .05em;
         color: var(--tone); margin-right: .5rem; }
.id { font-family: ui-monospace, monospace; font-size: .72rem; color: #8a94a6; }
.impact { font-size: .9rem; color: #43506b; margin: .5rem 0 0;
          padding-left: .75rem; border-left: 2px solid #dde3ec; }
.fix { margin-top: .75rem; font-size: .9rem; }
.fix .title { font-weight: 600; }
.risk { color: #b45309; font-size: .85rem; }
pre { background: #0f1420; color: #e6ebf5; padding: .75rem .9rem;
      border-radius: 8px; overflow-x: auto; font-size: .8rem; margin: .4rem 0; }
details { margin-top: .6rem; font-size: .85rem; }
summary { cursor: pointer; color: #5a6579; }
.bar { display: flex; height: 26px; border-radius: 6px; overflow: hidden;
       margin: .5rem 0 .25rem; }
.bar span { display: block; }
.legend { font-size: .75rem; color: #5a6579; }
footer { margin-top: 3rem; font-size: .8rem; color: #8a94a6; }
@media (prefers-color-scheme: dark) {
  body { background: #10131a; color: #e8ecf4; }
  h2 { border-color: #272f3d; }
  .score, .fact, .finding { background: #171b24; border-color: #272f3d; }
  .impact { color: #97a1b2; border-color: #272f3d; }
}
@media print { body { background: #fff; } .finding { break-inside: avoid; } }
"""


def to_html(report: Report, *, include_passes: bool = False) -> str:
    """A self-contained page. No external assets, prints sensibly."""
    esc = html.escape
    out: list[str] = []
    add = out.append

    add("<!doctype html>")
    add('<html lang="en"><head><meta charset="utf-8">')
    add('<meta name="viewport" content="width=device-width, initial-scale=1">')
    add(f"<title>Boot analysis — {esc(report.hostname or 'this machine')}</title>")
    add(f"<style>{_STYLE}</style></head><body><main>")

    add(f"<h1>Boot analysis — {esc(report.hostname or 'this machine')}</h1>")
    add(f'<p class="meta">{report.started_at:%A %d %B %Y, %H:%M} · '
        f"{esc(report.distribution or 'unknown distribution')} · "
        f"kernel {esc(report.kernel)} · {esc(report.preset)} profile · "
        f"analysed in {report.duration:.1f}s</p>")

    tone = _TONE_COLOURS[report.grade_tone]
    working = report.score_explanation() if report.score_working() else ""
    add('<section class="score">')
    add(f'<div><div class="number" style="color:{tone}">{report.score}</div>'
        f'<div class="grade">{esc(report.grade)}</div></div>')
    add(f"<div><div>{esc(report.headline())}</div>"
        + (f'<div class="working">{esc(working)}</div>' if working else "")
        + "</div>")
    add("</section>")

    if report.facts:
        add('<div class="facts">')
        for key, value in report.facts.items():
            add(f'<span class="fact"><b>{esc(key)}</b> {esc(value)}</span>')
        add("</div>")

    if report.timings and report.timings.measured:
        add(_timing_bar(report))

    for category in CATEGORY_ORDER:
        items = [item for item in report.by_category(category)
                 if include_passes or item.is_problem]
        if not items:
            continue
        add(f"<h2>{esc(category.title)}</h2>")
        for item in items:
            add(_finding_html(item))

    if report.skipped:
        add("<h2>Checks that did not run</h2><ul>")
        for item in report.skipped:
            add(f"<li><b>{esc(item.title)}</b> — {esc(item.reason)}</li>")
        add("</ul>")

    add("<footer>Produced by ClamGuard's Boot Analyzer. Every check is "
        "read-only; nothing on this machine was changed, and no suggested "
        "command was run.</footer>")
    add("</main></body></html>")
    return "\n".join(out)


def _finding_html(item) -> str:
    esc = html.escape
    tone = _TONE_COLOURS[item.severity.tone]
    parts = [f'<article class="finding" style="--tone:{tone}">']
    muted = ' <span class="id">(muted)</span>' if item.muted else ""
    parts.append(f'<h3><span class="badge">{esc(item.severity.label)}</span>'
                 f"{esc(item.title)}{muted}</h3>")
    detail = [f'<span class="id">{esc(item.id)}</span>']
    if item.value:
        detail.append(f"observed <code>{esc(item.value)}</code>")
    if item.expected:
        detail.append(f"expected <code>{esc(item.expected)}</code>")
    parts.append("<p>" + " · ".join(detail) + "</p>")
    if item.summary:
        parts.append(f"<p>{esc(item.summary)}</p>")
    if item.impact:
        parts.append(f'<p class="impact">{esc(item.impact)}</p>')

    for fix in item.fixes:
        parts.append('<div class="fix">')
        reboot = " (needs a reboot)" if fix.reboot_required else ""
        parts.append(f'<div class="title">{esc(fix.title)}{reboot}</div>')
        if fix.explanation:
            parts.append(f"<div>{esc(fix.explanation)}</div>")
        if fix.command:
            parts.append(f"<pre>{esc(fix.command)}</pre>")
        if fix.manual:
            parts.append(f"<div>Manually: {esc(fix.manual)}</div>")
        if fix.risk:
            parts.append(f'<div class="risk">⚠ {esc(fix.risk)}</div>')
        parts.append("</div>")

    for evidence in item.evidence:
        parts.append(f"<details><summary>Evidence — {esc(evidence.source)}"
                     f"</summary><pre>{esc(evidence.content.strip())}</pre></details>")
    parts.append("</article>")
    return "\n".join(parts)


#: Colours for the boot phase bar, in the order the phases happen.
_PHASE_COLOURS = {
    "firmware": "#8b5cf6",
    "loader": "#3b82f6",
    "kernel": "#14b8a6",
    "initrd": "#f59e0b",
    "userspace": "#22a55a",
}


def _timing_bar(report: Report) -> str:
    esc = html.escape
    timings = report.timings
    total = timings.total_seconds or 1.0
    segments, legend = [], []
    for phase in timings.phases:
        share = max(0.5, phase.seconds / total * 100)
        colour = _PHASE_COLOURS.get(phase.name, "#6b7688")
        segments.append(f'<span style="width:{share:.2f}%;background:{colour}" '
                        f'title="{esc(phase.name)} {esc(phase.text)}"></span>')
        legend.append(f'<span style="color:{colour}">■</span> '
                      f"{esc(phase.name)} {esc(phase.text)}")
    return (f"<h2>Boot time — {esc(format_duration(total))}</h2>"
            f'<div class="bar">{"".join(segments)}</div>'
            f'<div class="legend">{" · ".join(legend)}</div>')


# ---------------------------------------------------------------------------
# Writing one out
# ---------------------------------------------------------------------------

FORMATS = {
    "markdown": ("md", to_markdown),
    "json": ("json", to_json),
    "html": ("html", to_html),
    "script": ("sh", to_script),
}


def write(report: Report, directory, format_name: str = "markdown", **options):
    """Write `report` into `directory`; return the path written.

    Raises OSError if it cannot, which the caller shows to the user — a silent
    failed export is worse than none.
    """
    if format_name not in FORMATS:
        raise ValueError(f"unknown report format: {format_name!r}")
    extension, renderer = FORMATS[format_name]
    try:
        text = renderer(report, **options)
    except TypeError:
        text = renderer(report)     # to_json takes no options
    target = directory / filename(report, extension)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def describe_formats() -> list[tuple[str, str, str]]:
    """``(name, extension, one-line description)`` for the export menu."""
    return [
        ("markdown", "md", "Readable text, for a ticket or an email"),
        ("html", "html", "A self-contained page you can keep or print"),
        ("json", "json", "Structured data, for another program"),
        ("script", "sh", "Every suggested command, commented out, to review"),
    ]
