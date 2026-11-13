# Sysmon Summary

A local triage helper for SOC analysts. Upload a Sysmon `.evtx` dump and the app
finds the **attack chains** in it (process trees where something suspicious
happened), ranks them most suspicious first, and explains every score. Verdicts are
always "likely" (Likely safe / Suspicious / Likely compromised), never a final call.
The report has five tabs: Overview, Chains, IOCs, Timeline and Stats.

## Installation

Requires Python 3 (developed on 3.12).

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
```

## Enrichment APIs (optional)

All analysis runs locally; the app works without any API. If you want reputation
lookups for IPs, hashes and domains, run the portals it was built against and put
their base URLs in a `.env` file in the project folder:

```
IP_PORTAL_URL=http://127.0.0.1:...     # https://github.com/Bed-e/enrichment-portal-simple
HASH_PORTAL_URL=http://127.0.0.1:...   # https://github.com/gr-aleph/hash-enrich-2
DNS_PORTAL_URL=http://127.0.0.1:...    # https://github.com/NewCooDooer/ioc-simple-dns
```

A portal left unset shows its IOCs as "not enriched". Lookups only happen when you
press Look up or Enrich this chain, and private or internal values are never sent.
Hash lookup limits are set in `data/api_limits.txt`.

## Running

```bash
python -m web.app
```

Open http://127.0.0.1:5000 and upload a `.evtx` file. Set `PORT` to use another port.

## Tests

```bash
pytest
```

Tests make no network calls. Tests that use sample dumps (`my-training-example.evtx`,
`day-in-life-events.evtx` in the project folder) are skipped if those files are missing.
