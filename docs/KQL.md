# KQL in ClamGuard

The Hunt page speaks Kusto Query Language — the same language Azure Data
Explorer and Microsoft Sentinel use. If you already know it, everything below
will be familiar and you can skip to [What is different](#what-is-different).
If you do not, the first two sections are all you need to start.

---

## The shape of a query

A query starts with a table and pushes rows through operators separated by
`|`. Each operator takes a table and produces a table.

```kql
Logs
| where Level == "error"
| summarize Count = count() by App
| sort by Count desc
| take 10
```

Read it top to bottom: *take every log line, keep the errors, count them per
application, put the busiest first, show ten.*

Two keyboard facts: **Ctrl+Enter** runs, **Ctrl+Space** completes.

---

## The tables

| Table | What is in it |
|---|---|
| `Logs` | Every line from every indexed log file, normalised |
| `Sources` | One row per indexed file — path, format, size, how much was read |
| `Scans` | ClamGuard's own scan history |
| `Detections` | Every threat ClamAV has found on this machine |

`Logs` is the one you will use. Its columns:

| Column | Type | Notes |
|---|---|---|
| `Timestamp` | datetime | **Null for about two thirds of events.** See below. |
| `Level` | string | `trace` `debug` `info` `notice` `warning` `error` `critical` `unknown` |
| `Message` | string | The line, with the format's prefix removed |
| `App` | string | Worked out from where the file sits — or, for a journal entry, the systemd unit that wrote it |
| `Source` | string | The full path of the file |
| `SourceName` | string | Just the file name |
| `Format` | string | `jsonl`, `chromium`, `abseil`, `syslog`, … |
| `Location` | string | `config`, `data`, `state`, `cache`, `flatpak`, `system`, `journal` |
| `LineNumber` | long | Where in the file it is |
| `Raw` | string | The original line, exactly |
| `Extra` | dynamic | Whatever else the format knew: `Extra.pid`, `Extra.thread` |

`Sources`, `Scans` and `Detections` are listed with their columns in the
Tables tab on the left of the page.

### Why so many timestamps are null

Half the log formats on a Linux desktop do not write a time. Unity's
`Player.log` does not. Steam's console logs do not. Xorg writes seconds since
the server started, which is not a wall-clock time and is kept in
`Extra.uptime` instead.

Those lines are indexed and searchable, but **the time-range picker cannot see
them**. If a query returns nothing, check the chip in the toolbar that says
how many events have no timestamp, and switch the range to *All time*.

### The systemd journal

When journal indexing is on, its entries are in `Logs` like everything else,
with `Location == "journal"` and `App` naming the unit:

```kql
Logs
| where Location == "journal" and App == "kernel"
| where Level in ("warning", "error", "critical")
| project Timestamp, Level, Message
| sort by Timestamp desc
```

journald's own fields are in `Extra`: `Extra.unit`, `Extra.identifier`,
`Extra.comm`, `Extra.pid`, `Extra.uid`, `Extra.transport`, `Extra.host`,
`Extra.boot`, and `Extra.code_file` / `Extra.code_line` / `Extra.code_func`
where the program recorded them.

Colour escapes are stripped from `Message` — plenty of services write ANSI
sequences into the journal — and the untouched text is in `Raw`.

---

## Operators

### Filtering

```kql
Logs | where Level == "error"
Logs | where Level in ("error", "critical")
Logs | where Message has "segfault"          // whole word — uses the text index
Logs | where Message contains "segf"         // substring — cannot use the index
Logs | where Message startswith "Failed"
Logs | where Message matches regex @"pid=\d+"
Logs | where Timestamp > ago(2h)
Logs | where Timestamp between (datetime(2026-09-01) .. datetime(2026-09-08))
Logs | where App !in ("discord", "Steam")
Logs | where Extra.pid == 1234
```

**`has` and `contains` are not the same thing and the difference matters.**
`has` matches whole terms and throws punctuation away, so `has "| sh"` is
really `has "sh"`, and `has ".desktop"` is really `has "desktop"`. When the
punctuation is the point, use `contains`. When it is not, prefer `has`: it is
answered by the full-text index and is many times faster.

Every string operator has a case-sensitive twin ending `_cs`, and a negated
form with a leading `!`: `!contains`, `!has`, `!startswith`, `!in`.

### Shaping

```kql
Logs | project Timestamp, App, Message          // choose columns
Logs | project When = Timestamp, Message        // choose and rename
Logs | project-away Raw, Extra                  // drop columns (wildcards allowed)
Logs | project-keep Timestamp, Message          // keep only these
Logs | extend Length = strlen(Message)          // add a computed column
Logs | distinct App
Logs | sort by Timestamp desc
Logs | top 20 by Timestamp desc
Logs | take 100
Logs | count
Logs | getschema                                // describe the columns
```

### Grouping

```kql
Logs | summarize count() by App
Logs | summarize Events = count(), Apps = dcount(App) by Level
Logs | summarize count() by bin(Timestamp, 1h)
Logs | summarize arg_max(Timestamp, *) by App   // the newest row per application
```

Arithmetic over aggregates works, which is how you get a rate:

```kql
Logs
| summarize Total = count(), Errors = countif(Level == "error") by App
| extend Percent = round(100.0 * Errors / Total, 1)
```

Aggregates: `count` `countif` `dcount` `dcountif` `sum` `sumif` `avg` `avgif`
`min` `max` `minif` `maxif` `any` `anyif` `make_list` `make_set` `make_bag`
`percentile` `percentiles` `stdev` `variance` `arg_max` `arg_min`.

### Joining and combining

```kql
Logs
| summarize Events = count() by Source
| join kind=inner (Sources | project Source = Path, Format) on Source

union withsource=Table Logs, Sources | count
```

Join kinds: `inner` `innerunique` (the default) `leftouter` `rightouter`
`fullouter` `leftanti` `rightanti` `leftsemi` `rightsemi`.

### Pulling fields out of a message

```kql
Logs
| where Format == "plain"
| parse Message with * "user=" User " action=" Action
| summarize count() by User, Action
```

```kql
Logs
| extend Address = extract(@"\b(\d{1,3}(?:\.\d{1,3}){3})\b", 1, Message)
| where isnotempty(Address)
```

### Drawing it

```kql
Logs
| where isnotnull(Timestamp)
| summarize Events = count() by App, bin(Timestamp, 1h)
| render timechart with (title="Events per hour")
```

Charts: `timechart` `linechart` `areachart` `stackedareachart` `columnchart`
`barchart` `piechart` `scatterchart` `card`.

The first column is the x axis, every numeric column is a series, and a second
non-numeric column names the series — which is what makes the query above draw
one line per application. A `datetime` column is used as the x axis whatever
order the columns came out in.

### Naming things

```kql
let recent = 2h;
let noisy = dynamic(["Steam", "discord"]);
let shorten = (text: string) { substring(text, 0, 60) };
Logs
| where Timestamp > ago(recent) and App !in (noisy)
| project Short = shorten(Message)
```

```kql
print Busiest = toscalar(Logs | summarize count() by App | top 1 by count_ | project App)
```

### Windows

After `serialize` (or any `sort by`), `row_number()`, `prev()`, `next()` and
`row_cumsum()` work:

```kql
Logs
| where isnotnull(Timestamp)
| sort by Timestamp asc
| serialize
| extend Gap = Timestamp - prev(Timestamp)
| where Gap > 1h
```

---

## Functions

Around a hundred and thirty of them, listed with their signatures in the
**Functions** tab on the left of the page. The categories:

| Category | Examples |
|---|---|
| string | `strcat` `substring` `split` `replace_regex` `extract` `extract_all` `trim` `base64_decode_tostring` `parse_url` `parse_path` |
| numeric | `abs` `round` `floor` `bin` `bin_at` `pow` `log` `max_of` `binary_and` `tohex` |
| datetime | `now` `ago` `datetime_add` `datetime_diff` `startofday` `endofmonth` `hourofday` `format_datetime` `unixtime_seconds_todatetime` |
| dynamic | `array_length` `array_slice` `array_sort_asc` `bag_keys` `set_union` `pack` `parse_json` |
| conditional | `iif` `case` `coalesce` `isnull` `isempty` |
| type | `tostring` `tolong` `todouble` `todatetime` `gettype` |
| hash | `hash_sha256` `hash_md5` `hash` |
| network | `ipv4_is_private` `ipv4_is_in_range` `ipv4_is_match` `parse_ipv4` |

### Three that are not Kusto

Clearly marked as ClamGuard extensions in the Functions tab, because hunting
through desktop logs needs them:

| Function | What it does |
|---|---|
| `basename(path)` | The last component of a path |
| `dirname(path)` | Everything before it |
| `entropy(text)` | Shannon entropy in bits per character. Ordinary prose sits near 4; a Base64 blob sits above 5. |

```kql
Logs
| where strlen(Message) > 120 and entropy(Message) > 5.0
| project Timestamp, App, Message
```

---

## What is different

This is an implementation of KQL, not a copy of one, and it runs against a
local SQLite database rather than a cluster. The differences, all of them
deliberate:

**Missing on purpose.** `evaluate` loads a plugin, `externaldata` fetches a
URL, `invoke` calls a stored function on a server. None of them exists here,
and each is refused *by name* with the reason rather than as a syntax error. A
query in Hunt is a pure function from the local store to a table: it cannot
run a command, write a file or make a network request.

**Missing because they have not been needed yet.** `make-series`,
`mv-apply`, `lookup`, `datatable`, `range`, `partition`, `fork`, `scan`,
geospatial functions, and HyperLogLog-based approximate aggregation — `dcount`
here is exact, which is better at this scale and simpler to explain.

**Deliberate divergences.**

* `"a" + "b"` concatenates. Kusto returns null. Everybody who types it means
  concatenation and null teaches them nothing.
* `serialize` is not required before a window function. Kusto insists because
  it distributes the work; there is nothing to distribute here, so the rows
  are materialised on demand. The order is whatever the previous operator
  produced, so sort first if the order matters.
* A naive timestamp in a log file is read as **local** time, because that is
  what the application that wrote it meant. Everything is stored and compared
  in UTC, and the results grid shows local time.

---

## Making it fast

The status strip under the results says three numbers: how many rows came
back, how long it took, and how many rows were read out of the store. **The
gap between the last two is the whole performance story.**

`Query details` in the `⋯` menu shows the SQL the planner produced and which
operators it managed to push into the index.

Things that are answered by an index:

* `where Timestamp …` — always. The time-range picker is applied before
  anything else for exactly this reason, so a narrow range is also the fastest
  one.
* `where Level == …`, `where App == …` — indexed.
* `where Message has "word"` and `search "word"` — the full-text index.
* `summarize … by` with `count`, `countif`, `sum`, `avg`, `min`, `max`,
  `dcount` — pushed into `GROUP BY`.
* `take`, `top`, `sort by`, `distinct`, `count`, `project` of plain columns.

Things that read every row in the range:

* `matches regex` — SQLite has no regular expressions.
* `contains` on a large range — prefer `has` when the punctuation does not
  matter.
* Anything computed: `where strlen(Message) > 100`.
* `percentile`, `stdev`, `make_list`, `arg_max` — no SQL equivalent.

None of those is wrong to use. They are just worth putting *after* a filter
that narrows the range first.

---

## Writing your own analytics rules

The Insights tab runs a set of rules over the index. A rule is a JSON file in
`~/.config/clamguard/hunt-rules.d/`:

```json
{
  "id": "my-rule",
  "title": "Something I care about",
  "question": "Did the thing I care about happen?",
  "risk": "medium",
  "category": "Yours",
  "query": "Logs\n| where Message has \"the thing\"\n| summarize Count = count() by App",
  "minimum_rows": 1,
  "count_column": "Count",
  "explanation": "What it means when this matches.",
  "advice": "What to do about it."
}
```

It fires when the query returns at least `minimum_rows` rows. A rule with the
same `id` as a built-in one replaces it.

A rule is a query and nothing else. There is no field that could name a
command, a script or a path to run, because the engine a rule runs on cannot
run anything. *Where rules live…* in the `⋯` menu opens the directory with a
worked example and a README already in it.
