# ThaiCERT MISP Customisations

This folder holds ThaiCERT's additions to MISP. The rest of this repository is upstream MISP (branch `2.5`), unchanged.

Maintenance scripts used by ThaiCERT (NCSA) to keep IOC quality high on its MISP instance, which reduces false positives in IDS/IPS, SIEM and firewall feeds.

| Script | Purpose |
|---|---|
| `misp_warninglist_check.py` | Scans `to_ids=True` attributes against enabled MISP warninglists (matched locally from `list.json`) and the local clean-file hash store, then sets `to_ids=False` on matches. Dry-run by default; `--commit` applies the changes. |
| `misp_wl_reenable.py` | Undoes earlier auto-flagging for attributes that the current matcher no longer considers a hit, such as user-content hosts (`*.netlify.app`) or URLs that matched on their path. |
| `misp_ioc_retirement.py` | Tiered IOC aging (IP 30d, domain/URL 90d, hash 180d). It re-validates stale IOCs against up to four configurable enrichment providers (A–D, set in `.env`), soft-disables the dead ones and republishes the affected events. |
| `clean_hash_feed.py` | Collects the vendor clean-file hash feed hourly into a local SQLite store (`data/clean_hash_feed.sqlite`). |

Data-source endpoints and credentials are not in the code: every provider URL and key comes from `.env` (see `.env.example`). A provider with no URL configured is skipped.

See `misp_ioc_retirement_workflow.md` for the retirement workflow and `docs/` for the clean-hash feed design and plan.

## Setup

```bash
cp .env.example .env                                         # fill in MISP_KEY and the enrichment API keys
cp misp_warninglist_check.ini.example misp_warninglist_check.ini   # set url + api_key
chmod 600 .env misp_warninglist_check.ini
```

The scripts expect the MISP virtualenv (`/var/www/MISP/venv/bin/python3`) and read the warninglists from `/var/www/MISP/app/files/warninglists/lists/`.

## Usage

```bash
./misp_warninglist_check.py            # dry-run, writes a CSV report
./misp_warninglist_check.py --commit   # apply
./misp_wl_reenable.py [--commit]
./misp_ioc_retirement.py               # honours DRY_RUN in .env
./clean_hash_feed.py [--stats]
```

## Tests

```bash
/var/www/MISP/venv/bin/python3 -m unittest discover -s tests -t .
```

## Security

Never commit `.env`, `*.ini`, logs, CSV reports or `data/`; `.gitignore` excludes them all. They contain API keys and IOC data.
