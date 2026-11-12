# Sysmon Triage Tool: design

Owner: Bed-e. This is the design before any code (milestone M0).

## 1. Purpose and scope

A SOC analyst gives the tool a Sysmon `.evtx` dump. The tool pulls out the IOCs (IP addresses, DNS names, file hashes), skips the ones that cannot be interesting, ranks the rest, asks three local enrichment APIs about the highest-ranked ones, and shows the analyst a ranked, explained view of what happened on the machine.

It is a **triage helper, not a verdict engine**. It never says "clean" or "safe". An IOC with a low score or one that was skipped means only "nothing here pointed at it". The score and the reasons are always shown together.

**Out of scope for v1**

- Live log collection (the input is a saved dump)
- A database, accounts or login
- Uploading any file to any service. Only IOC values (an IP, a DNS name, a hash) leave the tool, and only to the three local APIs.
- IPv6 (the IP API accepts IPv4 only)
- Other IOC types as enrichment targets (URLs, registry keys, mutexes). No portal can look them up. Registry writes are still read and used as a local ranking signal (section 5).
- Async code and parallel API calls (see sections 2 and 10). One background thread is allowed in M5 only, to keep the web page responsive during lookups (section 7).

## 2. Ground rules for the code

These rules apply to every file and every milestone.

1. **Function-based Python as much as possible.** Plain functions, dicts, lists, tuples, sets and strings. No classes unless the standard library forces one on us.
2. **No library that is not explicitly necessary for functionality.** Allowed: the standard library, `requests` (the three existing portals use it), `python-dotenv` (reads the portal URLs from a gitignored `.env`, approved by Bed-e) and `python-evtx` (a binary `.evtx` file cannot be read without it). NiceGUI (with the FastAPI and uvicorn it brings) is allowed from milestone M5 only, approved by Bed-e for the tabbed web page: it gives tabs, tables with Show more, dialogs, timers and upload from plain Python functions. Anything else needs Bed-e's approval first.
3. **Ask Bed-e before any decision that needs structures or patterns above beginner-intermediate level.** Examples: classes and dataclasses, `async`, threads and thread pools, decorators, generators beyond a simple loop, type-hint tricks, regex that is hard to read, and metaprogramming. Claude stops and asks. It does not decide on its own, even if the choice looks better.
4. If a function is hard to explain in a sentence or two, it is split or simplified.
5. Data passed between steps is a plain dict or a list of dicts, so it can be printed and read.


## 3. Design independence from sample data

The design comes from the Sysmon event schema, the three API contracts and general triage practice. **It must not be shaped by any particular dump.**

- The tool must work on dumps with any mix of event IDs. Fields that are missing (for example the signature fields that only some events carry) are treated as "unknown", never as an error and never as a reason to trust or distrust an IOC.
- Tests may assert what the tool does with a sample, but a rule is added to the design only because it is justified on its own, in this file.

## 4. Pipeline

Each step is one plain function or a small group of functions in one module. Each step takes the output of the previous one.

```
.evtx file
  1 parse        -> list of event dicts (Sysmon IDs 1, 3, 11, 12, 13, 14, 22; every other ID is counted and dropped)
  2 collect      -> unique IOCs, each with counts, first/last seen, hosts, ProcessGuids
  3 filter       -> split into "to rank" and "skipped (reason code)"
  4 score        -> a local risk number and reasons for each IOC that was not skipped
  5 enrich       -> ask the APIs, one IOC at a time, highest local score first, up to a cap
  6 storylines   -> group events by ProcessGuid / ParentProcessGuid into process chains
  7 report       -> one HTML file (M4), later a web page (M5)
```

`ProcessGuid` is the key that ties a process's creation (event 1), its connections (event 3), its DNS queries (event 22) and its files (event 11) together. The storylines step depends on it.

## 5. Local filter rules (steps 3 and 4)

**Two different things happen locally.** *Skipping* removes an IOC from the API queue because it cannot produce a useful answer. *Ranking* only decides the order in which the remaining IOCs are looked up.

### Skip rules (each skip keeps a reason code)

| IOC | Skipped when | Reason code |
|---|---|---|
| IP | private, loopback, link-local, multicast, broadcast, CGNAT, reserved | `ip_not_public` |
| IP | inside a published CDN or cloud range kept in a plain text list file | `ip_known_shared_range` |
| DNS | ends in `.local`, `.lan`, `.internal`, `.home`, `.arpa`, is a single label, or is on our own AD domain list | `dns_internal` |

`dns_internal` is a privacy rule, not only a speed rule. The DNS portal's design says names are sent to outside services and internal names must never be typed in. The IP portal likewise never sends private addresses out. This tool enforces both **before** any API call.

Hashes are never skipped. A trusted path (the Windows system directories and `Program Files`, kept in one configurable list) is weak evidence, because a path can be faked and a replaced system binary is a real attack. It is a small negative ranking signal instead (see below).

### Ranking signals (add points, each with a stated reason)

- File or process in a user-writable path (`Temp`, `Downloads`, `Users`)
- Double extension such as `.mp4.exe`
- Odd parent-to-child pair (a document viewer starting an `.exe`; `explorer.exe` starting something from `Temp`)
- Outbound connection from an unexpected process (not a browser or known updater), or an unusual port (anything other than 80, 443 or 53)
- DNS name with a very long or high-entropy label, a burst of failed lookups (`QueryStatus` not 0) from one process, or a close lookalike of a name on a small well-known list
- Regular timing between connections to the same destination (possible beaconing)
- **Persistence by registry write** (events 12, 13, 14): a process writes an autorun location such as a `\CurrentVersion\Run` key. Points are added to the writing process (matched by `ProcessGuid`).
- **Persistence reference to a file**: for each hash IOC, a registry write to an autorun location (the same test as the persistence-by-registry-write signal) whose `Details` or `TargetObject` contains the file's full path (lowercased, plain substring check). A path that appears in some other key, such as a Windows application inventory entry, does not count, and neither does a write made by the file's own process, which the process-level signal already covers. Points are added to that hash. This runs locally on every hash **before** any API call, so a new file with no reputation history still moves up the queue and the cap is more likely to reach it. After enrichment, the report shows the portal's verdict and the persistence hit together.
- **Trusted path (negative)**: every file path seen for a hash is inside a protected system location. A small number of points is taken off. It lowers the order only; it never removes the hash from the queue and cannot cancel a strong signal.

**Process-level signals** (odd parent pair, user-writable path, registry autorun write) are scored per `ProcessGuid`. Every IP, DNS name and hash that process touched inherits the full points, so a persistent or suspicious process pulls everything it did up the queue.

Known limits of the path check: values using environment variables (`%APPDATA%`), quotes or arguments can be missed. A bare filename is never matched on its own, because common names would give false hits. A miss is "nothing pointed at it", never "no persistence".

The weights are placeholders kept as named constants at the top of one file, so they can be tuned.

## 6. The three enrichment APIs

All three run locally and are read-only for us. The base URLs come from configuration (environment variables), never from code. The tool holds no API keys, because each portal holds its own.

| | IP portal | Hash portal | DNS portal |
|---|---|---|---|
| Call | `GET /api/ip/<ip>` | `GET /api/v1/hash/{hash}` | `GET /api/v1/domain/{name}` |
| Input | IPv4 only | md5, sha1 or sha256 (32, 40 or 64 hex, lowercased) | a valid DNS name (not an IP or URL) |
| Score | `verdict.score` 0 to 100, higher = more likely malicious | `verdict.score` 0 = safe to 100 = malicious | `assessment.average` 0 = definitely safe to 100 = definitely malware, plus a per-source `score` |
| Label | `verdict.level`: `malicious`, `suspicious`, `no_known_bad`, `not_applicable` | `verdict.label`: `safe`, `suspicious`, `malicious` | `assessment.verdict`: `definitely_safe` ... `definitely_malware`, `not_graded` |
| Reasons | `verdict.reasons` | `verdict.reasons` | each source's `score_reason`, and `assessment.verdict_note` |
| Failure | `503` when every source failed; a single source failing is inside a `200` | always `200`; failed sources in `verdict.failed_sources` | always `200` for a valid name; failed sources have `status: error` and `score: null` |
| Bad input | `400` | `400` | `400` |
| Speed | sources are asked in sequence, up to about 24 seconds worst case | parallel inside the portal | sequential inside the portal; crt.sh alone can take about a minute |
| Limits | AbuseIPDB free tier is 1,000 checks a day | VirusTotal free quota is small | RDAP about 10 requests per 10 seconds |

None of the APIs has a batch endpoint, so the tool makes one call per IOC. Each portal caches its own results.

### 6.1 Contract details

These were read from the code and test fixtures of the three portals (`enrichment-portal-simple`, `hash-enrich-2`, `ioc-simple-dns`). All three are read-only `GET` calls that return JSON. `enrich.py` is the only file that knows them.

| | IP portal | Hash portal | DNS portal |
|---|---|---|---|
| Project | `enrichment-portal-simple` (Flask) | `hash-enrich-2` (FastAPI) | `ioc-simple-dns` (Flask) |
| Default port | 5001 | 8000 | 8010 |
| Config variable (in the portal's own clients) | `BACKEND_URL` (frontend), `PORTAL_URL` (MCP server) | `PORTAL_URL` | `BACKEND_URL` (no default) |
| Health check | none | `GET /api/v1/health` | `GET /api/v1/health` |
| Input cleaning done by the portal | strips spaces; IPv4 only | lowercases the hash | trims, lowercases, drops one trailing dot, converts to punycode |
| Sources it asks | Shodan InternetDB, RDAP, AbuseIPDB | VirusTotal, MalwareBazaar, ThreatFox | Google DNS, RDAP, crt.sh |
| Response header extras | none found | none found | `X-Cache-Age-<source>: <seconds>` for each cached source |

The variable names above are what the portals' own clients read. Two portals use the same name, so this tool needs its own three settings, one per portal (proposed names: `IP_PORTAL_URL`, `HASH_PORTAL_URL`, `DNS_PORTAL_URL`).

#### IP portal: `GET /api/ip/<ip>`

Success `200`:

```json
{
  "ip": "8.8.8.8",
  "classification": {"category": "global", "explanation": null, "ip": "8.8.8.8"},
  "verdict": {"level": "no_known_bad", "score": 0, "reasons": [], "summary": "..."},
  "sources": [
    {"name": "internetdb", "display_name": "...", "status": "ok",
     "summary": {}, "raw": {}, "error": null}
  ]
}
```

- `verdict.level`: `malicious` (score 60 or more), `suspicious` (20 or more), `no_known_bad` (below 20), `not_applicable`. `score` is a whole number 0 to 100.
- `not_applicable` is returned for private or reserved addresses (`classification.category` is not `global`). Its `score` is `0` but means **not judged**, never safe. All three sources are `skipped`. Our `ip_not_public` skip rule means the tool should never see this, but the converter must still handle it.
- `sources` is a **list**. `name` is one of `internetdb`, `rdap`, `abuseipdb`. `status` is one of `ok`, `no_data`, `error`, `skipped`, `not_configured` (no AbuseIPDB key).
- A missing or empty source adds points to the score ("undocumented is suspicious"), so a low-information IP is not shown as clean.
- Errors, always `{"error": "<code>", "message": "<text>"}`:

| Status | `error` code | Meaning |
|---|---|---|
| `400` | `invalid_ip` | not an IP address (hostnames, CIDR, URLs, hashes) |
| `400` | `unsupported_ip_version` | IPv6 |
| `503` | `sources_unavailable` | every source that was tried failed |
| `500` | `internal_error` | a bug in the portal |

#### Hash portal: `GET /api/v1/hash/{hash}`

Success `200` (always, for a valid hash):

```json
{
  "hash": "add97f...",
  "hash_type": "sha256",
  "sources": {
    "virustotal":    {"status": "ok", "data": {}, "error": null},
    "malwarebazaar": {"status": "ok", "data": {}, "error": null},
    "threatfox":     {"status": "ok", "data": {}, "error": null}
  },
  "verdict": {"score": 90, "label": "malicious", "reasons": [], "failed_sources": []}
}
```

- `hash_type`: `md5`, `sha1` or `sha256`, decided by length (32, 40, 64). Characters must be hex.
- `sources` is a **dict keyed by source name**. `status` is one of `ok`, `not_found`, `error`. On `error`, `error` is a plain **string**; otherwise `null`.
- `verdict.label`: `malicious` (score 70 or more), `suspicious` (30 to 69), `safe` (below 30). `score` is the highest score among the sources that know the hash.
- A hash nobody knows scores `50` (`suspicious`) with a reason saying so. It is never `safe`.
- `safe` needs VirusTotal to report at least 30 engines with no detection. If any source failed, a score below 30 is raised to `50` and the label is not `safe`.
- `verdict.failed_sources` lists the sources that returned `error`.
- The portal waits at most 12 seconds for all sources together. A slower source is reported as `status: error`, `error: "Took longer than 12 seconds"`.
- Errors: `400` with `{"error": "Expected 32, 40 or 64 hex characters"}` (a single string, no code field). There is no `503`.

#### DNS portal: `GET /api/v1/domain/{name}`

Success `200` (always, for a valid name, even when every source failed):

```json
{
  "ioc": {"type": "domain", "input": "Example.com.", "value": "example.com"},
  "sources": {
    "dns":   {"status": "ok", "data": {}, "score": 10, "score_reason": "..."},
    "rdap":  {"status": "ok", "data": {}, "score": 10, "score_reason": "..."},
    "crtsh": {"status": "error", "data": null,
              "error": {"code": "timeout", "message": "..."}, "score": null, "score_reason": "..."}
  },
  "assessment": {
    "score_min": 0, "score_max": 100, "average": 10,
    "sources_used": 2, "sources_total": 3,
    "verdict": "definitely_safe", "verdict_label": "Definitely safe", "verdict_note": null
  }
}
```

- `ioc.value` is the cleaned name that was actually looked up. Use it, not `input`.
- `sources` is a **dict** with keys `dns`, `rdap`, `crtsh`. `status` is one of `ok`, `not_found`, `error`. On `error`, `error` is an **object** `{code, message}` (codes seen include `timeout` and `upstream_error`). `score` is `null` for an errored source, and that source is left out of the average.
- `assessment.average` is the rounded mean of the scores that exist, or `null` when no source answered.
- `assessment.verdict` bands by `average`: `definitely_safe` (0 to 30), `likely_safe` (31 to 45), `undetermined` (46 to 55), `likely_malware` (56 to 70), `definitely_malware` (71 to 100). `not_graded` when `average` is `null`.
- When fewer than all sources scored, a `definitely_*` verdict is lowered to the matching `likely_*`, and `verdict_note` says why. `verdict_note` is `null` otherwise.
- Errors, always `{"error": "<text>", "input": "<what was sent>"}`:

| Status | Meaning |
|---|---|
| `400` | `not a valid DNS name: ...` (an IP address, a URL, a port, spaces, a single label, bad characters, longer than 253 characters) |
| `404` | `not found` (wrong path) |
| `405` | `method not allowed` |
| `500` | `internal error` |

#### Differences the converter must absorb

| Point | IP | Hash | DNS |
|---|---|---|---|
| `sources` type | list of dicts with `name` | dict | dict |
| Source error shape | string | string | object `{code, message}` |
| Where the overall score lives | `verdict.score` | `verdict.score` | `assessment.average` (can be `null`) |
| Where the label lives | `verdict.level` | `verdict.label` | `assessment.verdict` |
| Reasons | `verdict.reasons` (list of text) | `verdict.reasons` (list of text) | each source's `score_reason`, plus `assessment.verdict_note` |
| "Total failure" signal | HTTP `503` | none: look for every source `error` | none: `not_graded` and `average: null` |
| Unknown IOC | `no_known_bad` or `suspicious` with points for missing data | `suspicious`, score 50 | per-source `not_found` |
| Failed-source list | in the `sources[].status` | `verdict.failed_sources` | `sources_used` below `sources_total` |
| "Not judged" signal | `level: not_applicable` | none | `verdict: not_graded` |

**Mapping to the common shape** (section 6, "Combining the answers"). This mapping and the timeouts below are proposals made while writing this section, not facts from the portals, and are for Bed-e to review. `status` is one of `enriched`, `partial`, `not_enriched`:

- `status: not_enriched` when the call failed (timeout, connection refused, `5xx`), when the IP portal returns `503`, when the hash portal reports every source as `error`, or when the DNS portal returns `not_graded`. `reasons` holds the cause. `score_0_to_100` is `null`.
- `status: partial` when a portal answered but some sources failed (`verdict.failed_sources` not empty, or `sources_used` below `sources_total`).
- `status: enriched` otherwise.
- `label` is copied as given: `verdict.level`, `verdict.label` or `assessment.verdict`.
- A `400` from any portal is a bug in our filters, not an IOC result. The tool logs it and marks the IOC `not_enriched` with reason `portal_rejected_input`.

**Timeouts the tool must use.** A request timeout per portal, set above the portal's own worst case: IP at least 30 seconds, hash at least 15 seconds, DNS at least 70 seconds (crt.sh alone can take about a minute). The values are named constants in `enrich.py`.

**Combining the answers**

- A function converts each portal's answer into a common shape: `{type, value, score_0_to_100, label, reasons, status}`. This is the only place that knows the three contracts.
- The scores are **policy numbers, not probabilities**, and the three portals score differently, so scores are never averaged across IOC types. The portal's own label is shown beside the number.
- A lookup that failed, timed out or got a `503` is shown as **not enriched** with the reason. It is never shown as a low score.
- The hash portal's `safe` needs VirusTotal to have checked the file. The tool shows the label as given.

## 7. Output

- **M4, static HTML file.** One self-contained `.html` file written with plain string building. It shows:
  - process storylines ranked by a combined score: lineage, command lines, and the IPs, DNS names and hashes each process touched, with scores and reasons
  - a table of skipped IOCs with reason codes, so the analyst can audit the filter
  - how many IOCs were found, skipped, looked up and left un-enriched because of the cap
  - a fixed note that the scores are not a verdict
- **M5, NiceGUI web app.** The analyst uploads a dump in a browser and sees the same data in four tabs: Overview (counts and the enrich controls), IOCs (the ranked table), Storylines (the M4 process chains) and Skipped (the filter audit). It reuses the same functions. The web part only handles the upload, the enrich button and showing the page. The IOC table, the storylines and the skipped table show 10 rows first and a Show more button adds 10 more.
  - **No API is called by default.** Uploading a dump parses, filters and ranks it locally and shows the ranked table on the IOCs tab. Every IOC shows "not requested" in the portal column.
  - **Enrich on demand.** A dropdown for N (5, 10, 25, 50, 100, all) and an "Enrich top N" button on the Overview tab. Pressing the button sends only the N highest-ranked IOCs to the portals. IOCs outside the top N are never sent.
  - **One background thread.** The button starts a single thread (approved by Bed-e, M5 only) that runs the same sequential `for` loop as M3, one lookup at a time, highest rank first. The thread exists only so the web request returns at once. Calls are still not parallel.
  - **The page fills in as answers arrive, with no page reload.** While the thread runs, a NiceGUI timer (every 2 seconds) updates the status line, the counts and the portal column in place. When the thread finishes the timer stops and the storylines are rebuilt once so the answers appear inside them.
  - **Shared state.** The ranked list, the results so far and the run state ("idle", "running", "done", "failed") live in a module-level dict keyed by an upload id. Only the thread writes results. The page only reads. The browser never sends IOC values back, so the server only ever looks up IOCs it ranked itself.
  - **Failures stay visible.** A lookup that fails is shown as "not enriched" with the reason, as in M3. If the thread itself crashes, the run state becomes "failed" with the error text, and the page stops reloading.
  - Only one enrich run per upload at a time. Pressing the button while one is running does nothing. The dropdown offers 5, 10, 25, 50, 100 and all; a value above the number of ranked IOCs is clamped. `--cap` and `DEFAULT_CAP` stay for the command line only.
  - **Rate-limit protection, server side.** Only hash lookups reach VirusTotal, so only they are counted. When the top N holds hash lookups that would exceed the limits (time needed at the per-minute rate, share of the daily budget), the server shows a dialog with Send anyway and Cancel before any lookup starts. The thread spaces hash lookups to stay under the per-minute limit. The server keeps a daily count of hash lookups in a small gitignored file (`data/hash_usage.txt`), so a restart does not reset it. Once the daily budget is used up, a hash lookup is answered "not enriched: daily VirusTotal budget reached" without calling the portal (a hard stop, even after Send anyway). Every hash call is counted, even if the portal answered from its own cache, because the tool cannot see that.
  - **Limits file.** The limits live in `data/api_limits.txt`, not in the code, so they can follow the analyst's real VirusTotal key. Defaults: 4 per minute and 500 per day (VirusTotal free public API; to be checked against the analyst's key, and a premium key has higher limits). The monthly limit is not tracked.

## 8. Architecture and file layout

Small flat modules, each with plain functions:

| File | Job |
|---|---|
| `parse.py` | read the `.evtx`, return event dicts |
| `iocs.py` | collect and de-duplicate IOCs |
| `filters.py` | skip rules |
| `scoring.py` | local ranking signals |
| `enrich.py` | call the three APIs, convert answers to the common shape |
| `storylines.py` | build process chains from `ProcessGuid` |
| `report.py` | write the HTML |
| `main.py` | command line: dump in, report out |
| `web/app.py` | the NiceGUI app (tabs), the upload endpoint, the enrich thread and its shared state (M5 only) |
| `data/api_limits.txt` | per-minute and per-day hash lookup limits for the web app (M5 only) |
| `data/hash_usage.txt` | today's hash lookup count, written by the web app, gitignored (M5 only) |

## 9. Decisions, each with its reason

1. **Function-based Python and few libraries.** The code must be fully explainable by its owner, and every dependency is something to learn and maintain.
2. **`python-evtx` is used.** `.evtx` is a binary format. The only library-free option is a PowerShell export step, which is Windows-only and needs a manual second step.
3. **Filter, then rank, instead of filter only.** Skipping removes only what cannot produce a useful answer. Ranking handles the rest, so a cap or a timeout still leaves the most suspicious IOCs checked first.
4. **Skipped items are always visible with a reason.** Attackers abuse trusted binaries and domains, and the analyst must be able to audit the filter.
5. **Local clues are part of the product.** The APIs score reputation only. They cannot see a double extension, a strange parent process or a lookalike domain.
6. **A plain `for` loop for API calls, with a cap per run.** It is the easiest code to read. In M5 the same loop runs inside one background thread so the page stays responsive. The filter makes the list short. Parallelism is added only if measured to be too slow, and only with Bed-e's approval.
7. **Process-centric output.** An analyst reads a story, "this process started that one and talked to that address", not a flat list of 5,000 rows.
8. **Private and internal values never leave the machine.** This follows the rules of the IP and DNS portals.
9. **Tests make no network calls, and samples are fixtures only.** They run against the sample dumps and saved API answers, to check the code works. The samples never decide the design (section 3). Failures that cannot be recorded (a timeout, a `503`) are simulated, and the test says so.

## 10. Open questions (ask Bed-e before deciding)

- Should the hash skip rule use signature data (Sysmon events 6 and 7) when a dump contains it? Dumps without it must still work, using path alone.
- Is a sequential loop fast enough on real dumps? If not, parallel calls need Bed-e's approval. (One background thread for the M5 page is already approved. It does not make calls in parallel.)
- Does the tool need a cache of its own, or are the portals' caches enough?
- What is the per-run API cap?
- How are the local score and the API scores combined into one ranking?
- Where do the CDN and cloud range lists and the well-known-names list come from, and how are they kept up to date?

## 11. Milestones

Each is done when its stated result works on the sample dumps used as test fixtures (section 3).

- **M0 Design.** This file is reviewed and agreed.
- **M1 Parse and collect.** The tool reads both `.evtx` files and prints counts of events (including registry events 12, 13, 14) and unique IPs, DNS names and hashes. Hashes come from event 1 only, one hash per file (sha256, then sha1, then md5). IPs come from event 3 only, not from DNS answers. Registry events are parsed and kept, not collected as IOCs. No API calls.
- **M2 Filter and rank.** Each IOC has a skip reason or a local score with reasons, including the two persistence signals, with tests for every rule.
- **M3 Enrich.** The tool queries the three portals one IOC at a time, highest score first, up to the cap, and shows failures as not enriched.
- **M4 Storylines and static HTML.** One HTML report is written, with ranked process chains and the skipped-items table.
- **M5 NiceGUI web app.** A dump uploaded in the browser gives the same data in tabs (Overview, IOCs, Storylines, Skipped), with no API called until the analyst picks N and presses the button. The top N IOCs are then looked up one at a time by a background thread, and the page fills in as answers arrive. No API is called until the analyst presses the button and picks N. Results fill in row by row, with a warning before sending and a hard daily stop for VirusTotal-backed hash lookups, using the limits in `data/api_limits.txt`.
- **Later, only with approval.** Parallel calls, a cache of our own, other IOC types.
