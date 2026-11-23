# ThaiCERT MISP Customisations

ThaiCERT's maintenance scripts for its MISP instance. They keep `to_ids` (the IDS export flag) accurate, so the IOCs that MISP feeds to IDS/IPS, SIEM and firewalls are current and free of known-benign values.

This folder is the only ThaiCERT addition to the repository. Everything outside `thaicert/` is upstream [MISP](https://github.com/MISP/MISP) branch `2.5`, unchanged.

## What each script does

| Script | Schedule | What it does |
|---|---|---|
| `misp_warninglist_check.py` | daily 19:00 | Finds `to_ids=True` attributes that match an enabled MISP warninglist or the local clean-hash store and sets `to_ids=False`, with an audit comment. |
| `misp_ioc_retirement.py` | Saturday 22:00 | Ages out stale IOCs. Candidates past their age threshold are re-checked against enrichment providers; dead ones get `to_ids=False` and their events are republished. |
| `clean_hash_feed.py` | hourly at :20 | Collects a vendor feed of known-clean file hashes into `data/clean_hash_feed.sqlite`, which the warninglist checker reads. |
| `misp_wl_reenable.py` | manual | Reverses past warninglist flags that the current matcher no longer considers a hit. |

### `misp_warninglist_check.py`

- Warninglists are read straight from `/var/www/MISP/app/files/warninglists/lists/*/list.json` and matched in Python, so the only MISP API calls are attribute fetches and updates.
- Only lists **enabled in MISP** are used. Lists whose name contains an exclude keyword are skipped (default: `VPN`, `Top 10K most-used sites`).
- **Subdomain rule:** a subdomain on a shared platform (free hosting, dynamic DNS, tunnels; see `USER_CONTENT_PARENTS` in the code) does **not** inherit the platform's listing. `evil-login.netlify.app` is not "popular" just because `netlify.app` is.
- **Clean hashes:** `sha256` and `filename|sha256` values are also looked up in the clean-hash store. A hit is recorded under the label `CLEAN_HASH_LIST_NAME`. If the store is missing or older than 24 hours, the script warns and carries on.
- Every run writes a CSV report, `misp_wl_report_<timestamp>.csv`.

### `misp_ioc_retirement.py`

- Covers only attributes owned by `OWNER_ORG_ID` that are still `to_ids=True`.
- Age thresholds come from `.env`: IP 30 days, domain/URL 90, hash 180, anything else 90.
- Each candidate is checked against the providers in order **A → B (URLs) / C (hashes) → D** and kept as soon as any provider says it is still active.
- **Safety-keep:** if every provider fails or times out, the IOC is kept, never retired.
- Values in `whitelist/*.txt` or `WHITELIST_IOCS` are always disabled, or deleted if `WHITELIST_ACTION=remove`.
- Affected events are republished with `alert=False`, so sync partners get the change without email alerts.
- The full flow, with a diagram, is in [`misp_ioc_retirement_workflow.md`](misp_ioc_retirement_workflow.md).

### `clean_hash_feed.py`

- The feed API serves only the last 30 days, one hour per call, so the script keeps its own SQLite store.
- The first run backfills about 720 hours. After that, each hourly run fetches the missing hours and re-fetches the newest 3.
- Exit codes: `0` ok, `1` some hours skipped (retried on the next run), `2` config or authentication error.
- Design notes: [`docs/superpowers/specs/`](docs/superpowers/specs/).

### `misp_wl_reenable.py`

- Reads the checker's own CSV reports (rows it applied), re-tests each value with the **current** matcher, and confirms the live state in MISP.
- It only acts on attributes that are still `to_ids=False` and still carry the checker's auto-comment.
- Each candidate is classified as `user_content`, `url_host` or `other`. By default `--commit` re-enables only `user_content` and `url_host`.

## Data sources

No provider name, endpoint or credential is in the code. Everything comes from `.env`, and a provider with no URL configured is skipped.

| Variables | Provider role | Used for |
|---|---|---|
| `ENRICH_A_URL`, `ENRICH_A_TOKEN` | IOC API: IPv4, domain, URL, sha256 | retirement, step 1 |
| `ENRICH_B_URL`, `ENRICH_B_KEY` | URL status lookup | retirement, step 2 (URLs) |
| `ENRICH_C_URL`, `ENRICH_C_KEY` | malware hash lookup | retirement, step 3 (hashes) |
| `ENRICH_D_URL`, `ENRICH_D_KEY`, `ENRICH_D_KEY_HEADER` | indicator API (any type; key optional) | retirement, step 4 (fallback) |
| `CLEAN_HASH_URL`, `CLEAN_HASH_API_KEY` | vendor clean-file hash feed | `clean_hash_feed.py` |

The real values for ThaiCERT production are kept privately, not in this repository.

## Setup

Requirements: the MISP virtualenv (`/var/www/MISP/venv`, which has PyMISP and requests) and read access to the MISP warninglists directory.

```bash
cd /var/www/MISP/thaicert
cp .env.example .env                                              # MISP key, providers, thresholds
cp misp_warninglist_check.ini.example misp_warninglist_check.ini  # MISP url + API key for the checker
chmod 600 .env misp_warninglist_check.ini
./clean_hash_feed.py                                              # first run backfills ~30 days
```

### Configuration (`.env`)

| Variable | Default | Notes |
|---|---|---|
| `MISP_URL`, `MISP_KEY`, `MISP_VERIFY_CERT` | | MISP connection (retirement) |
| `OWNER_ORG_ID` | `1` | Only this org's events are retired |
| `DRY_RUN` | `True` | `False` = actually disable and republish |
| `IP_/DOMAIN_/URL_/HASH_/DEFAULT_AGE_THRESHOLD` | 30/90/90/180/90 | Days |
| `API_DELAY_SECONDS` | `0.3` | Pause between candidates |
| `LOG_FILE` | `logs/misp_cleanup.log` | Retirement log |
| `WHITELIST_ACTION` | `disable` | `remove` **deletes** whitelisted attributes |
| `WHITELIST_IOCS` | | Comma-separated extra whitelist values |
| `CLEAN_HASH_LIST_NAME` | `Clean hash feed` | Label written into MISP comments. Changing it on a running system stops `misp_wl_reenable.py` recognising older comments. |
| `CLEAN_HASH_DELAY_SECONDS` | `0.5` | Pause between hourly feed calls |

`MAX_CHECKS_PER_RUN` appears in `.env.example` but the retirement script does not read it yet, so every candidate is checked.

## Usage

All scripts **dry-run by default** (retirement follows `DRY_RUN`).

```bash
./misp_warninglist_check.py                     # dry-run over all attributes, CSV report only
./misp_warninglist_check.py --days 1            # only attributes changed or published in the last day
./misp_warninglist_check.py --commit --days 1   # apply (what cron runs)
./misp_warninglist_check.py --no-clean-hash     # warninglists only

DRY_RUN=True ./misp_ioc_retirement.py           # test run; the variable overrides .env

./clean_hash_feed.py                            # collect
./clean_hash_feed.py --stats                    # store size, newest release, last fetch

./misp_wl_reenable.py                           # dry-run, writes misp_wl_reenable_dryrun_<ts>.csv
./misp_wl_reenable.py --commit --reasons user_content
```

## Production deployment

`/var/www/MISP` is a clone of this repository: `origin` is upstream MISP and `thaicert` is `ncsa-thaicert/thaicert-misp`. The scripts run from `/var/www/MISP/thaicert` under the `piyawut` user's crontab:

```cron
0 19 * * *  cd /var/www/MISP/thaicert && flock -n /tmp/misp_wl.lock ./misp_warninglist_check.py --commit --days 1 >> /var/www/MISP/thaicert/logs/misp_warninglist_check.log 2>&1
0 22 * * 6  cd /var/www/MISP/thaicert && flock -n /tmp/misp_retire.lock ./misp_ioc_retirement.py >> /var/www/MISP/thaicert/logs/misp_cleanup.log 2>&1
20 * * * *  cd /var/www/MISP/thaicert && flock -n /tmp/clean_hash_feed.lock ./clean_hash_feed.py >/dev/null 2>> /var/www/MISP/thaicert/logs/clean_hash_feed.err
```

Runtime files sit next to the scripts and are git-ignored:

| Path | Content |
|---|---|
| `.env`, `misp_warninglist_check.ini` | secrets (mode 600) |
| `data/clean_hash_feed.sqlite` | clean-hash store (~5 GB) |
| `logs/`, `misp_warninglist_check.log*`, `misp_wl_reenable.log` | logs |
| `misp_wl_report_*.csv`, `misp_wl_reenable_*.csv` | run reports (`misp_wl_reenable.py` reads the `misp_wl_report_*` ones) |

### Making changes

```bash
cd /var/www/MISP
git pull thaicert 2.5                     # get the latest ThaiCERT changes
# edit thaicert/..., then run the tests
git add thaicert && git commit -m "thaicert: ..."
git push thaicert 2.5
```

Upgrading MISP itself: `git pull origin 2.5` (or the MISP web updater), then `git push thaicert 2.5` to keep the repository in step. Upstream never touches `thaicert/`, so the merge is clean.

`.git` is group-shared (`core.sharedRepository=group`), so both `www-data` and members of the `www-data` group can run git here.

## Tests

```bash
cd /var/www/MISP/thaicert
/var/www/MISP/venv/bin/python3 -m unittest discover -s tests -t .
```

The tests cover the clean-hash collector (parsing, planning, retries, store) and the matcher and re-enable logic. They make no network calls and need no MISP.

## Security

- Never commit `.env`, `*.ini`, `data/`, logs or CSV reports. `.gitignore` excludes them, and they contain API keys and IOC data.
- Keep provider names, endpoints and tenant hostnames out of code, comments and commit messages. Put them only in `.env`.
- The repository is private. Before making it public, review `docs/`, `whitelist/` and the git history.
