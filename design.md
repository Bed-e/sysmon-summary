# Sysmon Triage Tool: design

Owner: Bed-e.

## 1. Purpose

A SOC analyst uploads a Sysmon `.evtx` dump. The tool finds the **attack chains** in it (the process trees where something suspicious happened) and shows them, the most suspicious first, each titled by what made it suspicious. Enriching the IOCs inside a chain with the three local portals is **optional** and only happens when the analyst asks.

It is a triage helper. Its verdicts are always "likely" ("Likely safe", "Suspicious", "Likely compromised"), and every verdict and score is shown with its reason. It never says "clean" or "safe" on its own.

*Previously* the tool was built around an API queue: rank IOCs, then enrich the top N, then build storylines. Chains are now the main output, and the APIs only add to what is already there.

**Out of scope:** live log collection, a database or accounts, uploading files anywhere (only IOC values go out, and only to the three local portals), IPv6 enrichment, enriching other IOC types (URLs, registry keys).

## 2. Ground rules for the code

1. Plain functions, dicts, lists, sets and strings. No classes unless the standard library forces one.
2. No library unless it is needed. Allowed: the standard library, `requests`, `python-dotenv`, `python-evtx`, and NiceGUI (with its FastAPI and uvicorn). Anything else needs Bed-e's approval.
3. Ask Bed-e before using anything above beginner-intermediate level (classes, `async`, new threads, decorators, complex generators or regex, metaprogramming).
4. If a function is hard to explain in a sentence or two, split or simplify it.
5. Data passed between steps is a plain dict or a list of dicts.
6. The design comes from the Sysmon schema, the portal contracts and triage practice, never from a particular sample dump. Missing fields are "unknown", never an error and never evidence.

## 3. Pipeline

Each step has one output, and the next step reads it. Data flows one way.

```
.evtx file
  1 parse        parse.read_events      -> events: list of event dicts (IDs 1, 3, 11, 12, 13, 14, 22; others counted and dropped)
  2 collect      iocs.collect_iocs      -> iocs: {ip, dns, hash} -> {value: record}  (facts only, no scores)
  3 findings     scoring                -> findings: list of {guid, points, reason, kind, subject}
  4 processes    scoring                -> process_scores: {guid: {image, score, findings}}  (worked out once)
  5 chains       storylines             -> {table, chains, other}
  6 IOC ranking  scoring + filters      -> ranked IOC rows, each with an enrichability tag
  7 enrich       enrich + web queue     -> results: {(type, value): common-shape answer}   (optional)
  8 show         web/                   -> tabs: Overview, Chains, IOCs, Timeline, Stats
```

`ProcessGuid` ties a process's creation (1), connections (3), DNS queries (22), files (11) and registry writes (12–14) together. Every step from 3 onward depends on it.

Steps 1–6 run when the dump is uploaded and call no API. Step 7 runs only when the analyst presses a Look up or Enrich button, and it never changes steps 3–6.

## 4. Findings (steps 3 and 4)

A **finding** is one local clue about one process:

```
{"guid": "{...}", "points": 25, "reason": "document app started a program (...)",
 "kind": "process" | "subject", "subject": ("ip", "1.2.3.4") or None}
```

- **Process findings** are about the process itself: user-writable path (`Temp`, `Downloads`, `Users`), double extension (`.pdf.exe`), odd parent pair (a document viewer starting a program, a script host from a user path), registry autorun write (`\CurrentVersion\Run`, Winlogon shell or userinit, an IFEO `Debugger`), a burst of failed DNS lookups, and the **enumeration burst**. There is no minus for running from a system folder: living-off-the-land binaries (`rundll32`, `powershell`) doing bad things must not be discounted.
- **Subject findings** are about one IOC the process touched, worked out per process:
  - IP: the connection comes from an unexpected process (not a browser or known updater), uses an unusual port (not 80, 443 or 53), or has regular timing (possible beaconing).
  - DNS: very long or high-entropy label, or a close lookalike of a well-known name.
  - Hash: an autorun registry value written by *another* process contains this file's full path (lowercased substring; a bare filename never matches).
- **Enumeration burst:** `ENUM_MIN_COUNT` or more discovery commands (`whoami`, `ipconfig`, `net`/`net1`, `systeminfo`, `nltest`, `tasklist`, `netstat`, `quser`, `arp`, `route`, `hostname`, ...) started by the **same parent** within `ENUM_WINDOW_SECONDS`. The points go to the parent (the shell doing the recon).
- **Process score** = the sum of its findings. It is worked out once, kept in the upload's state, and read by the chains, the IOC table and the timeline.

Weights, thresholds and word lists are named constants in `scoring/config.py`. Known limit: paths with environment variables, quotes or arguments can be missed. A miss means "nothing pointed at it", never "no persistence".

## 5. Chains (step 5)

- A **flagged** process has a score above 0. A **chain** is one process tree (a root and everything it started) with at least one flagged process. Trees with nothing flagged go in a collapsed **Other activity** list.
- **Title:** the strongest finding in the tree, its process and its subject, e.g. `invoice.pdf.exe → C2 to 1.2.3.4`. Not the root process. Other flagged branches are shown inside the same card.
- **Shape:** flagged processes show their findings and activity. Unflagged ancestors and descendants are shown as plain lines with no detail, so the whole flow is visible.
- **Rank:** the highest process score in the tree, then larger tree, then earliest start.
- **Dropped by:** if a process's image path matches a file another process created (event 11), the chain shows "file written by chrome.exe at 10:02". Trees are not merged.
- A root is a process whose parent is missing from the dump (it started before the capture). Its parent's image name is shown as a note.
- Portal answers **mark** a chain (a badge on the IOC and a "portal hit" count on the card). They never change its score or rank.

Output: `{"table": {guid: process entry}, "chains": [{root, score, title_finding, guids, flagged}], "other": [root guid, ...]}`.

## 6. IOCs and enrichability (step 6)

**IOC rank (split inheritance).** An IOC has no scoring code of its own. Its score is:
- the subject findings about this IOC, plus
- the *process* findings of the highest-scoring process that touched it.

So a lookalike domain ranks high, but chrome's other 300 domains do not inherit that finding. Ties: more sightings, then earliest first seen.

**Enrichability tag.** Every IOC stays visible. Each gets `enrichable: True`, or a reason it is not sent:

| Reason | IOC | When |
|---|---|---|
| nothing to gain | IP | private, loopback, link-local, multicast, broadcast, CGNAT, reserved (`ip_not_public`) |
| nothing to gain | IP | inside a CDN or cloud range in `data/shared_ranges.txt` (`ip_known_shared_range`) |
| must not send | DNS | `.local`, `.lan`, `.internal`, `.home`, `.arpa`, a single label, or in `data/ad_domains.txt` (`dns_internal`) |

"Must not send" is a privacy rule from the IP and DNS portals' own designs, and it is checked again right before any call. Hashes are always enrichable.

*Previously* these were "skip" rules that removed IOCs before ranking, and the skipped ones had their own tab.

## 7. Enrichment (step 7, optional)

**What the analyst can send:**
- **Look up / Retry** on an IOC row or an IOC inside a chain sends that one IOC.
- **Enrich this chain** sends the enrichable IOCs touched by that chain's flagged processes.

**Queue.** One FIFO queue per upload, drained by one background thread, one lookup at a time (no parallel calls). A press while the thread is running adds to the queue. Anything already queued or answered is ignored, except a Retry, which replaces the old answer. A progress bar shows done out of queued. The browser sends only an IOC's row number or a chain's number; the server looks up only IOCs it collected itself.

**VirusTotal protection (hash lookups only).** Hash lookups are spaced to the per-minute limit. A daily count is kept in `data/hash_usage.txt` (gitignored). Once the daily budget is used up, a hash is answered "not enriched: daily VirusTotal budget reached" without a call. Limits live in `data/api_limits.txt` (default 4 a minute, 500 a day).

**Common shape.** `enrich.py` is the only file that knows the portal contracts. It turns each answer into `{type, value, score_0_to_100, label, reasons, status}`, where status is `enriched`, `partial` (some sources failed) or `not_enriched` (call failed, timed out, `503`, every source failed, `not_graded`, or a `400`, logged as `portal_rejected_input`). A failure is never shown as a low score. Portal scores are never averaged across types or merged into local scores. The portal's label is shown beside its number.

### Portal contracts

Base URLs come from `.env`: `IP_PORTAL_URL`, `HASH_PORTAL_URL`, `DNS_PORTAL_URL`. No API keys are held here.

| | IP portal | Hash portal | DNS portal |
|---|---|---|---|
| Call | `GET /api/ip/<ip>` | `GET /api/v1/hash/{hash}` | `GET /api/v1/domain/{name}` |
| Input | IPv4 | md5 / sha1 / sha256, lowercase hex | a DNS name |
| Score | `verdict.score` | `verdict.score` | `assessment.average` (may be `null`) |
| Label | `verdict.level` | `verdict.label` | `assessment.verdict` |
| Reasons | `verdict.reasons` | `verdict.reasons` | each source's `score_reason`, plus `assessment.verdict_note` |
| `sources` | list of `{name, status}` | dict | dict |
| Partial | a source `status: error` | `verdict.failed_sources` not empty | `sources_used < sources_total` |
| Total failure | HTTP `503` | every source `error` | `verdict: not_graded` |
| Not judged | `level: not_applicable` | none | `not_graded` |
| Timeout used | 30 s | 15 s | 70 s (crt.sh can take a minute) |

## 8. Web app

NiceGUI. Uploading parses, finds and ranks locally; no portal is called. The state for each upload (events, iocs, process scores, chains, ranked IOCs, queue, results) lives in a module-level dict keyed by a random upload id. Only the background thread writes results. A NiceGUI timer updates the progress bar, badges and table while the queue is running.

Tabs, in order:

1. **Overview:** the soft verdict and its one-line reason, then the top chains. The verdict comes from the highest chain score only, using the badge bands: 0 = **Likely safe**, 1–39 = **Suspicious**, 40+ = **Likely compromised**. Portal hits are shown but do not move the verdict.
2. **Chains:** one card per chain (section 5) with its score badge, title, a one-line summary, the flagged processes and their findings, portal hits, the Enrich this chain button, and the process tree. Other activity is collapsed at the bottom. 10 at a time with Show more.
3. **IOCs:** every IOC in rank order (section 6) with its why (grouped by process, full text on hover), the processes that touched it, its portal answer, and Look up / Retry. If it is not enrichable, the reason replaces the button.
4. **Timeline:** one row per process in tree order, a bar from first to last event coloured by process score, dots per event type, and dashed parent-to-child links. A "Show" dropdown picks flagged processes and their parents (default), one chain, or all processes. A table of flagged processes sits under the chart.
5. **Stats:** counts kept out of the way: events kept and dropped by ID, parse errors, IOCs found by type, IOCs not enrichable by reason, lookups done or failed, and events with no ProcessGuid.

The theme (Light / Dark / System, cards, score badges grey 0 / orange 1–39 / red 40+) is in `web/theme.py`.

## 9. File layout

| File | Job |
|---|---|
| `parse.py` | read the `.evtx`, return event dicts |
| `iocs.py` | collect and de-duplicate IOCs |
| `scoring/` | findings, process scores, IOC rank (`config.py` holds every weight and list) |
| `filters.py` | enrichability tag |
| `storylines.py` | process table, tree, chains, dropped-by |
| `enrich.py` | portal calls and conversion to the common shape |
| `web/app.py`, `web/pages.py`, `web/upload.py` | entry point, pages, upload endpoint |
| `web/actions.py`, `web/enrich_jobs.py`, `web/limits.py`, `web/runtime.py` | button actions, the queue and its thread, hash limits, shared state |
| `web/tabs/` | one module per tab: overview, chains, iocs, timeline, stats |
| `web/reasons.py`, `web/rows.py`, `web/storyline_summary.py`, `web/timeline_data.py`, `web/timeline_chart.py` | text, rows and chart data for the tabs; no UI code |
| `web/config.py`, `web/theme.py` | constants, columns, colours; theme and header |
| `data/*.txt` | shared ranges, AD domains, well-known names, API limits |

*Previously* `main.py` (command line) and `report.py` (static HTML) existed. They are removed in R4; the web app is the only interface.

## 10. Decisions

1. **Chains first, enrichment optional.** An analyst reads a story ("this file was downloaded, ran, and talked to that address"), not a ranked list of lookups. The APIs only add reputation to what the local evidence already shows.
2. **Findings belong to processes.** One scoring pass, one score per process, and data that flows one way. Subject findings stop one bad IOC from dragging up everything else the same process touched.
3. **Chains are titled by the strongest finding.** What made a tree suspicious matters more than its root (often `explorer.exe` or a browser).
4. **Portal answers mark, never re-rank.** Local evidence decides the order. The ranking does not jump around while the analyst works.
5. **Verdicts are "likely" and always show why.** A short verdict helps the analyst; the reason keeps it honest.
6. **Nothing is hidden.** IOCs that are not enrichable stay in the chains and the table, with the reason.
7. **Private and internal values never leave the machine.**
8. **One background thread, one queue, one lookup at a time.** Easy to read, and it respects the portals' rate limits.
9. **Tests make no network calls.** They use the sample dumps and saved portal answers as fixtures. Timeouts and `503`s are simulated.

## 11. Open questions

- Are `ENUM_MIN_COUNT` = 3 and `ENUM_WINDOW_SECONDS` = 300 right? Neither sample dump has a burst.
- Are the verdict bands (0 / 1–39 / 40+) right once real dumps are scored with findings?
- Where do the CDN ranges and the well-known-names list come from, and how are they kept up to date?

## 12. Milestones

Each milestone is on its own branch. Bed-e opens the pull requests.

- **R0 Design.** This file.
- **R1 Findings.** `scoring/` produces findings with kind and subject, adds the enumeration burst and per-process network findings, and builds `process_scores` once. IOC rank by split inheritance is done here too (it had to change with the findings). Tests rewritten to findings.
- **R2 Chains and IOC rank.** `storylines.py` builds chains (flagged trees, title finding, dropped-by, other activity). IOC rank uses split inheritance. `filters.py` returns the enrichability tag.
- **R3 Web.** Queue and progress bar, Chains tab, IOCs reason column, Overview verdict, Stats tab. Remove Enrich next N, the warning dialog and the Skipped tab.
- **R4 Cleanup.** Delete `main.py`, `report.py` and their tests; final pass on this file.
