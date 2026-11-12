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
- Threads, async code and parallel API calls (see sections 2 and 10)

## 2. Ground rules for the code

These rules apply to every file and every milestone.

1. **Function-based Python as much as possible.** Plain functions, dicts, lists, tuples, sets and strings. No classes unless the standard library forces one on us.
2. **No library that is not explicitly necessary for functionality.** Allowed: the standard library, `requests` (the three existing portals use it) and `python-evtx` (a binary `.evtx` file cannot be read without it). Flask is allowed from milestone M5 only. Anything else needs Bed-e's approval first.
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
- **M5, Flask web app.** The analyst uploads a dump in a browser and sees the same report. It reuses the same functions. The web part only handles the upload and shows the page.

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
| `web/app.py` | the Flask app (M5 only) |

## 9. Decisions, each with its reason

1. **Function-based Python and few libraries.** The code must be fully explainable by its owner, and every dependency is something to learn and maintain.
2. **`python-evtx` is used.** `.evtx` is a binary format. The only library-free option is a PowerShell export step, which is Windows-only and needs a manual second step.
3. **Filter, then rank, instead of filter only.** Skipping removes only what cannot produce a useful answer. Ranking handles the rest, so a cap or a timeout still leaves the most suspicious IOCs checked first.
4. **Skipped items are always visible with a reason.** Attackers abuse trusted binaries and domains, and the analyst must be able to audit the filter.
5. **Local clues are part of the product.** The APIs score reputation only. They cannot see a double extension, a strange parent process or a lookalike domain.
6. **A plain `for` loop for API calls, with a cap per run.** It is the easiest code to read. The filter makes the list short. Parallelism is added only if measured to be too slow, and only with Bed-e's approval.
7. **Process-centric output.** An analyst reads a story, "this process started that one and talked to that address", not a flat list of 5,000 rows.
8. **Private and internal values never leave the machine.** This follows the rules of the IP and DNS portals.
9. **Tests make no network calls, and samples are fixtures only.** They run against the sample dumps and saved API answers, to check the code works. The samples never decide the design (section 3). Failures that cannot be recorded (a timeout, a `503`) are simulated, and the test says so.

## 10. Open questions (ask Bed-e before deciding)

- Should the hash skip rule use signature data (Sysmon events 6 and 7) when a dump contains it? Dumps without it must still work, using path alone.
- Is a sequential loop fast enough on real dumps? If not, threads need Bed-e's approval.
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
- **M5 Flask web app.** A dump uploaded in the browser gives the same report.
- **Later, only with approval.** Parallel calls, a cache of our own, other IOC types.
