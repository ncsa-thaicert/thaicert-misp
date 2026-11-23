#!/var/www/MISP/venv/bin/python3
"""
MISP Warninglist Attribute Checker  v3
========================================
Scans all MISP events for attributes (to_ids=True) that match enabled
warninglists. If a match is found (excluding VPN-related warninglists),
the attribute's IDS flag is set to False to prevent false positives
when feeding indicators to security devices (IDS/IPS, SIEM, firewall).

clean-hash feed:
  sha256 / filename|sha256 values are also looked up in the local clean-file
  hash feed store (data/clean_hash_feed.sqlite, filled hourly by clean_hash_feed.py).
  A hit counts as a warninglist match named "clean-hash feed (file=..., ...)".

PERFORMANCE:
  Warninglist matching is done 100% locally in Python by reading
  /var/www/MISP/app/files/warninglists/lists/*/list.json directly.
  This eliminates all warninglist HTTP API calls — only attribute
  fetch + attribute update calls are made to MISP.

Usage:
    python3 misp_warninglist_check.py              # dry-run
    python3 misp_warninglist_check.py --commit     # apply changes
    python3 misp_warninglist_check.py --exclude-keywords VPN,Tor
    python3 misp_warninglist_check.py --config /path/to/config.ini
    python3 misp_warninglist_check.py --no-clean-hash    # skip clean-hash feed lookup

Author : Auto-generated
Date   : 2026-07-17
"""

import argparse
import configparser
import csv
import ipaddress
import json
import logging
import os
import re
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
import urllib3

import clean_hash_feed

clean_hash_feed.load_env(clean_hash_feed.SCRIPT_DIR / ".env")  # for CLEAN_HASH_LIST_NAME

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from pymisp import PyMISP
except ImportError:
    print(
        "[ERROR] PyMISP is not installed.\n"
        "        pip install pymisp",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCRIPT_DIR      = Path(__file__).resolve().parent
WL_DIR          = Path("/var/www/MISP/app/files/warninglists/lists")
DEFAULT_CONFIG  = SCRIPT_DIR / "misp_warninglist_check.ini"
AUDIT_TAG       = "warninglist:auto-flagged"

TARGET_ATTRIBUTE_TYPES = [
    "ip-src", "ip-dst",
    "domain", "hostname", "url",
    "md5", "sha1", "sha256",
    "filename|sha256",
]
# Top-10K popular-sites list: too coarse — lists abusable hosts (e.g. sslip.io) and cut real C2 URLs
DEFAULT_EXCLUDE_KEYWORDS = ["VPN", "Top 10K most-used sites"]
CLEAN_HASH_LIST_NAME     = os.environ.get("CLEAN_HASH_LIST_NAME", "Clean hash feed")
CLEAN_HASH_STALE_HOURS         = 24

# Shared platforms where anyone can create their own subdomain (free hosting,
# dynamic DNS, tunnels, third-party "registries" like uk.com / in.net).
# The platform itself is often in popular-site warninglists (Top 10K),
# but a subdomain under it — e.g. "evil-login.netlify.app" — was set up by
# whoever registered it, typically the attacker, so hostname-list entries for
# the platform (or anything above it) are NOT applied to such subdomains.
# The platform's own host and "www.<platform>" are still matched.
# Mostly Public Suffix List (private section) entries; deliberately excluded:
# suffixes whose subdomains are the provider's own services, e.g.
# googleapis.com (fonts.googleapis.com), squarespace.com (static1.*), weebly.com.
USER_CONTENT_PARENTS = frozenset("""
    in.net uk.com us.com eu.com ru.com de.com cn.com gr.com sa.com co.com it.com jp.net
    com.se us.org eu.org eu.cc
    duckdns.org ddns.net no-ip.org sytes.net dyndns.org dynamic-dns.net dpdns.org kozow.com
    localto.net nip.io ngrok.io ngrok-free.app ngrok.app trycloudflare.com loca.lt serveo.net
    pages.dev workers.dev r2.dev vercel.app netlify.app web.app firebaseapp.com appspot.com
    github.io gitlab.io bitbucket.io codeberg.page gitbook.io
    blogspot.com blogspot.co.uk blogspot.ca blogspot.de blogspot.com.es blogspot.fr
    webflow.io wixsite.com myshopify.com framer.app framer.website notion.site carrd.co
    square.site weeblysite.com mystrikingly.com 000webhostapp.com lovable.app
    azurewebsites.net blob.core.windows.net cloudfront.net digitaloceanspaces.com
    ondigitalocean.app herokuapp.com onrender.com fly.dev up.railway.app deno.dev
    glitch.me surge.sh repl.co replit.app pythonanywhere.com hf.space streamlit.app
    wpenginepowered.com
""".split())

_URL_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://")
_HOST_END   = re.compile(r"[/?#\\]")
_SHA256     = re.compile(r"^[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
LOG_FILE   = SCRIPT_DIR / "misp_warninglist_check.log"

logger = logging.getLogger("misp_wl_check")
logger.setLevel(logging.INFO)
logger.propagate = False

_fmt = logging.Formatter(LOG_FORMAT)

_ch = logging.StreamHandler()
_ch.setFormatter(_fmt)
logger.addHandler(_ch)

try:
    _fh = RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
    _fh.setFormatter(_fmt)
    logger.addHandler(_fh)
except Exception as _e:
    print(f"[WARNING] Could not open log file {LOG_FILE}: {_e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def load_config(config_path: str) -> dict:
    config = configparser.ConfigParser()
    if not Path(config_path).exists():
        logger.error(f"Config file not found: {config_path}")
        logger.info(
            "Create a config file:\n\n"
            "[misp]\n"
            "url        = https://your-misp-instance.local\n"
            "api_key    = YOUR_API_KEY\n"
            "verify_ssl = False\n\n"
            "[tuning]\n"
            "page_size      = 1000\n"
            "retry_attempts = 3\n"
            "retry_delay    = 2\n"
        )
        sys.exit(1)

    config.read(config_path)
    if "misp" not in config:
        logger.error("Config must have a [misp] section.")
        sys.exit(1)

    m = config["misp"]
    for k in ("url", "api_key"):
        if k not in m:
            logger.error(f"Missing misp.{k} in config.")
            sys.exit(1)

    t = config["tuning"] if "tuning" in config else {}
    return {
        "url":            m["url"].strip(),
        "api_key":        m["api_key"].strip(),
        "verify_ssl":     m.getboolean("verify_ssl", fallback=False),
        "page_size":      int(t.get("page_size",      1000)),
        "retry_attempts": int(t.get("retry_attempts", 3)),
        "retry_delay":    float(t.get("retry_delay",  2.0)),
    }


# ---------------------------------------------------------------------------
# Retry helper
# ---------------------------------------------------------------------------
def with_retry(fn, attempts: int, delay: float, label: str = ""):
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except Exception as exc:
            if attempt == attempts:
                raise
            wait = delay * (2 ** (attempt - 1))
            logger.warning(
                f"  [{label}] attempt {attempt}/{attempts} failed: {exc}. "
                f"Retrying in {wait:.1f}s ..."
            )
            time.sleep(wait)


# ---------------------------------------------------------------------------
# Local warninglist loader — reads JSON files directly from disk
# ---------------------------------------------------------------------------
class LocalWarninglistMatcher:
    """
    Loads warninglist JSON files from WL_DIR and exposes a fast
    in-memory match() method.  No MISP API calls for matching.

    Supported warninglist types:
      string    — exact case-insensitive match
      hostname  — domain suffix match  (e.g. ".google.com"), on the host
                  part only for URLs (same as MISP's __evalHostname);
                  not applied above a USER_CONTENT_PARENTS platform
      substring — value contains the entry (case-insensitive)
      cidr      — IP address inside a CIDR network
      regex     — Python regex match
    plus, when a CleanHashStore is given, sha256 lookup in the clean-hash feed store.
    For "filename|..." attribute types only the hash part is matched.

    hostname and cidr entries are indexed (dict lookups per domain label /
    per prefix length) rather than scanned linearly, so match() costs
    microseconds instead of tens of milliseconds per value.
    """

    def __init__(self, enabled_names: set[str], exclude_keywords: list[str], clean_hash=None):
        # Structures populated during load
        self._exact:     dict[str, list[str]] = {}   # value -> [wl_name, ...]
        self._suffix:    dict[str, list[str]] = {}   # hostname -> [wl_name, ...]
        self._substring: list[tuple[str, str]] = []  # (needle, wl_name)
        # ip version -> prefixlen -> int(network_address) -> [wl_name, ...]
        self._networks:  dict[int, dict[int, dict[int, list[str]]]] = {4: {}, 6: {}}
        self._regexes:   list[tuple[re.Pattern, str]] = []
        # platform -> number of subdomain values kept because of it
        self.user_content_skips: dict[str, int] = {}
        self._clean_hash     = clean_hash       # clean_hash_feed.CleanHashStore or None
        self.clean_hash_hits = 0

        self._load(enabled_names, exclude_keywords)

    # ------------------------------------------------------------------
    def _should_exclude(self, name: str, exclude_keywords: list[str]) -> bool:
        return any(kw.lower() in name.lower() for kw in exclude_keywords)

    @staticmethod
    def _index(table: dict, key, wl_name: str) -> None:
        names = table.setdefault(key, [])
        if wl_name not in names:
            names.append(wl_name)

    def _load(self, enabled_names: set[str], exclude_keywords: list[str]):
        list_files = sorted(WL_DIR.glob("*/list.json"))
        loaded = 0
        skipped_disabled = 0
        skipped_excluded = 0

        for list_file in list_files:
            try:
                with open(list_file, encoding="utf-8") as fh:
                    data = json.load(fh)
            except Exception as exc:
                logger.warning(f"  Could not read {list_file}: {exc}")
                continue

            wl_name = data.get("name", list_file.parent.name)
            wl_type = data.get("type", "string").lower()
            entries = data.get("list", [])

            # Skip if not in the enabled set from MISP API
            if enabled_names and wl_name not in enabled_names:
                skipped_disabled += 1
                continue

            # Skip excluded keywords (e.g. VPN)
            if self._should_exclude(wl_name, exclude_keywords):
                skipped_excluded += 1
                continue

            count = 0
            for entry in entries:
                entry = str(entry).strip()
                if not entry:
                    continue

                if wl_type == "cidr":
                    try:
                        net = ipaddress.ip_network(entry, strict=False)
                        self._index(
                            self._networks[net.version].setdefault(net.prefixlen, {}),
                            int(net.network_address), wl_name,
                        )
                        count += 1
                    except ValueError:
                        pass

                elif wl_type == "hostname":
                    # Normalise: match the domain or any subdomain
                    suffix = entry.lower().lstrip(".")
                    self._index(self._suffix, suffix, wl_name)
                    count += 1

                elif wl_type == "substring":
                    self._substring.append((entry.lower(), wl_name))
                    count += 1

                elif wl_type == "regex":
                    try:
                        self._regexes.append((re.compile(entry, re.IGNORECASE), wl_name))
                        count += 1
                    except re.error:
                        pass

                else:  # "string" and anything else → exact match
                    key = entry.lower()
                    self._exact.setdefault(key, [])
                    if wl_name not in self._exact[key]:
                        self._exact[key].append(wl_name)
                    count += 1

            if count:
                loaded += 1

        logger.info(
            f"Warninglists loaded from disk: {loaded} "
            f"(disabled={skipped_disabled}, excluded={skipped_excluded})"
        )
        logger.info(
            f"  Exact entries : {sum(len(v) for v in self._exact.values()):,} values"
        )
        n_networks = sum(
            len(names)
            for by_len in self._networks.values()
            for table in by_len.values()
            for names in table.values()
        )
        logger.info(f"  CIDR networks : {n_networks:,}")
        logger.info(f"  Hostname sfx  : {sum(len(v) for v in self._suffix.values()):,}")
        logger.info(f"  Substrings    : {len(self._substring):,}")
        logger.info(f"  Regexes       : {len(self._regexes):,}")

    # ------------------------------------------------------------------
    def match(self, value: str, attr_type: str = "") -> list[str]:
        """
        Return a list of warninglist names that match `value`.
        Returns [] if no match.
        """
        if attr_type.startswith("filename|"):
            value = value.rsplit("|", 1)[-1].strip()
        hits: list[str] = []
        val_lower = value.lower()

        # 1. Exact / string match (O(1) hash lookup)
        hits.extend(self._exact.get(val_lower, []))

        # 2. Hostname suffix match — look up the host and each parent domain.
        #    A URL is matched on its host, never on its path or query
        #    (e.g. "evil.com/pg_www.wellsfargo.com" must not hit wellsfargo.com).
        #    Unlike MISP's __evalHostname, "//" only counts as a scheme
        #    separator at the start, so "a.com/r?u=https://b.com" -> "a.com".
        if self._suffix:
            host = _URL_SCHEME.sub("", val_lower, count=1)
            host = _HOST_END.split(host, maxsplit=1)[0].rsplit("@", 1)[-1]
            if host.count(":") == 1:          # strip ":port" (not IPv6)
                host = host.split(":")[0]
            labels = host.rstrip(".").split(".")
            for i in range(len(labels)):
                suffix = ".".join(labels[i:])
                # Host created by a user under a shared platform
                # (e.g. "evil.netlify.app"): stop before the platform entry.
                if (i > 0 and suffix in USER_CONTENT_PARENTS
                        and not (i == 1 and labels[0] == "www")):
                    if any(".".join(labels[j:]) in self._suffix for j in range(i, len(labels))):
                        self.user_content_skips[suffix] = self.user_content_skips.get(suffix, 0) + 1
                    break
                for wl_name in self._suffix.get(suffix, ()):
                    if wl_name not in hits:
                        hits.append(wl_name)

        # 3. Substring match
        for needle, wl_name in self._substring:
            if needle in val_lower and wl_name not in hits:
                hits.append(wl_name)

        # 4. CIDR match (only attempt for values that look like IPs):
        #    mask the address once per prefix length present in the lists
        if self._looks_like_ip(value):
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                ip = None
            if ip is not None:
                ip_int = int(ip)
                bits   = ip.max_prefixlen
                for prefixlen, table in self._networks[ip.version].items():
                    shift = bits - prefixlen
                    for wl_name in table.get(ip_int >> shift << shift, ()):
                        if wl_name not in hits:
                            hits.append(wl_name)

        # 5. Regex match
        for pattern, wl_name in self._regexes:
            if pattern.search(value) and wl_name not in hits:
                hits.append(wl_name)

        # 6. clean-hash feed lookup (sha256 only, one primary-key read).
        #    A broken store must not abort the scan: drop clean-hash for the rest of the run.
        if self._clean_hash is not None and _SHA256.match(val_lower):
            try:
                row = self._clean_hash.lookup(val_lower)
            except sqlite3.Error as exc:
                logger.warning(f"clean-hash lookup failed ({exc}) — continuing without clean-hash")
                self._clean_hash = None
                row = None
            if row:
                hits.append(format_clean_hash_hit(row))
                self.clean_hash_hits += 1

        return hits

    @property
    def clean_hash_enabled(self) -> bool:
        return self._clean_hash is not None

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        # Quick pre-filter before creating ipaddress objects
        return bool(value and (value[0].isdigit() or ":" in value))


def format_clean_hash_hit(row: dict) -> str:
    """Hit name for a clean-hash row. No "|" allowed: misp_wl_reenable strips comments with [^|]*?"""
    filename = (row.get("filename") or "").replace("|", "/")[:80]
    released = (row.get("release_date") or "")[:10]
    return f"{CLEAN_HASH_LIST_NAME} (file={filename}, size={row.get('size')}, released={released})"


def open_clean_hash(path=clean_hash_feed.DEFAULT_DB):
    """Open the clean-hash store read-only; None (with a warning) if it does not exist."""
    try:
        store = clean_hash_feed.CleanHashStore(path)
    except FileNotFoundError:
        logger.warning(f"clean-hash store not found ({path}) — continuing without clean-hash")
        return None
    except (OSError, sqlite3.Error) as exc:
        logger.warning(f"clean-hash store unusable ({path}: {exc}) — continuing without clean-hash")
        return None
    try:
        st = store.stats()
    except sqlite3.Error as exc:
        store.close()
        logger.warning(f"clean-hash store unusable ({path}: {exc}) — continuing without clean-hash")
        return None
    logger.info(
        f"clean-hash store: {st['files']:,} hashes, newest release {st['newest_release']}, "
        f"last fetch {st['last_fetched_at']}"
    )
    last = st["last_fetched_at"]
    age_ok = False
    if last:
        fetched_at = datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        age_ok = datetime.now(timezone.utc) - fetched_at <= timedelta(hours=CLEAN_HASH_STALE_HOURS)
    if not age_ok:
        logger.warning(
            f"clean-hash store is stale (last fetch {last or 'never'}) — check clean_hash_feed.py cron"
        )
    return store


# ---------------------------------------------------------------------------
# MISP helpers
# ---------------------------------------------------------------------------
def connect_misp(cfg: dict) -> PyMISP:
    logger.info(f"Connecting to MISP at {cfg['url']} ...")
    try:
        misp = PyMISP(cfg["url"], cfg["api_key"], cfg["verify_ssl"])
        logger.info("Connected.")
        return misp
    except Exception as exc:
        logger.error(f"Failed to connect: {exc}")
        sys.exit(1)


def get_enabled_warninglist_names(misp: PyMISP) -> set[str]:
    """
    Returns the set of enabled warninglist *names* from MISP.
    Used to filter which local JSON files to load.
    """
    logger.info("Fetching enabled warninglist names from MISP API ...")
    try:
        response = misp.warninglists(pythonify=True)
    except Exception as exc:
        logger.warning(f"Could not fetch warninglists from API: {exc}. Loading ALL local files.")
        return set()  # empty = load all

    if isinstance(response, dict):
        raw = response.get("Warninglists") or response.get("response", [])
    elif isinstance(response, list):
        raw = response
    else:
        raw = []

    names: set[str] = set()
    for wl in raw:
        wl_data = wl.get("Warninglist", wl) if isinstance(wl, dict) else wl
        wl_on   = getattr(wl_data, "enabled", None)
        if wl_on is None:
            wl_on = wl_data.get("enabled", False) if isinstance(wl_data, dict) else False
        if wl_on and str(wl_on) != "0":
            name = getattr(wl_data, "name", None) or (wl_data.get("name") if isinstance(wl_data, dict) else None)
            if name:
                names.add(str(name))

    logger.info(f"Enabled warninglists in MISP: {len(names)}")
    return names


def fetch_target_attributes_pages(misp: PyMISP, cfg: dict, days: int = None):
    """
    Generator that yields pages of attributes.

    With --days, two passes are made and de-duplicated by attribute id:
      1. timestamp         — attribute itself modified in the last N days
      2. publish_timestamp — event published on THIS instance in the last N days

    Pass 2 is needed for events pulled via sync: synced attributes keep the
    REMOTE timestamp (can be weeks old), so pass 1 alone never sees them,
    while publish_timestamp is set locally when the pulled event is saved.
    """
    page_size       = cfg["page_size"]
    retry_attempts  = cfg["retry_attempts"]
    retry_delay     = cfg["retry_delay"]

    if days:
        passes = [("timestamp", f"{days}d"), ("publish_timestamp", f"{days}d")]
        logger.info(
            f"Fetching to_ids=True attributes modified or event-published in the last "
            f"{days} days (page_size={page_size}) ..."
        )
    else:
        passes = [(None, None)]
        logger.info(f"Fetching to_ids=True attributes (page_size={page_size}) ...")

    seen_ids: set[str] = set()

    for filter_name, filter_val in passes:
        if filter_name:
            logger.info(f"  Pass: {filter_name}={filter_val}")

        page = 1
        while True:
            def _search(p=page):
                kwargs = {filter_name: filter_val} if filter_name else {}
                return misp.search(
                    controller="attributes",
                    type_attribute=TARGET_ATTRIBUTE_TYPES,
                    to_ids=True,
                    page=p,
                    limit=page_size,
                    pythonify=False,
                    **kwargs,
                )

            result = with_retry(_search, retry_attempts, retry_delay, f"attr-page-{page}")

            if isinstance(result, dict):
                batch = result.get("Attribute") or result.get("response", [])
            elif isinstance(result, list):
                batch = result
            else:
                batch = []

            if not batch:
                break

            fetched = len(batch)
            batch = [a for a in batch if str(a.get("id")) not in seen_ids]
            seen_ids.update(str(a.get("id")) for a in batch)

            logger.info(f"  Page {page}: fetched {fetched} attributes ({len(batch)} new)")
            if batch:
                yield batch

            if fetched < page_size:
                break
            page += 1


# ---------------------------------------------------------------------------
# Core processing
# ---------------------------------------------------------------------------
def process_attributes(
    misp: PyMISP,
    cfg: dict,
    matcher: LocalWarninglistMatcher,
    commit: bool,
    days: int = None,
) -> list[dict]:
    """
    1. Fetch candidate attributes page-by-page
    2. Deduplicate values per page
    3. Match locally (no API calls — pure in-memory)
    4. Apply updates
    5. Publish modified events
    """
    retry_attempts = cfg["retry_attempts"]
    retry_delay    = cfg["retry_delay"]

    report_rows:       list[dict]  = []
    total_fetched                  = 0
    total_skipped_analysis         = 0
    total_matched                  = 0
    total_updated                  = 0
    modified_event_ids: set[str]   = set()
    pending_updates:   list[tuple[dict, dict]] = []

    # A failed page fetch (e.g. HTTP 500 deep into pagination) must not throw
    # away the matches already collected — apply those, then report the error.
    fetch_error: Exception | None = None
    try:
        for batch in fetch_target_attributes_pages(misp, cfg, days):
            total_fetched += len(batch)

            # Deduplicate: value → list of attr dicts in this batch
            value_to_attrs: dict[str, list[dict]] = {}
            for attr in batch:
                # Check event analysis: only process if analysis is Completed ('2')
                event = attr.get("Event", {}) if isinstance(attr, dict) else getattr(attr, "Event", {})
                analysis = event.get("analysis") if isinstance(event, dict) else getattr(event, "analysis", None)

                # MISP analysis levels: 0 = Initial, 1 = Ongoing, 2 = Completed
                if str(analysis) not in ("2", "Completed"):
                    total_skipped_analysis += 1
                    continue

                val = str(attr.get("value", "")).strip() if isinstance(attr, dict) \
                      else str(getattr(attr, "value", "")).strip()
                if val:
                    value_to_attrs.setdefault(val, []).append(attr)

            unique_values = list(value_to_attrs.keys())

            for value in unique_values:
                first     = value_to_attrs[value][0]
                attr_type = str(first.get("type", "") if isinstance(first, dict) else getattr(first, "type", ""))
                wl_names_list = matcher.match(value, attr_type)
                if not wl_names_list:
                    continue

                wl_names = ", ".join(wl_names_list)

                for attr in value_to_attrs.get(value, []):
                    attr_id    = str(attr.get("id",       "?") if isinstance(attr, dict) else getattr(attr, "id",       "?"))
                    attr_uuid  = str(attr.get("uuid",     "?") if isinstance(attr, dict) else getattr(attr, "uuid",     "?"))
                    attr_type  = str(attr.get("type",     "?") if isinstance(attr, dict) else getattr(attr, "type",     "?"))
                    event_id   = str(attr.get("event_id", "?") if isinstance(attr, dict) else getattr(attr, "event_id", "?"))
                    old_comment= str((attr.get("comment") or "") if isinstance(attr, dict) else (getattr(attr, "comment", "") or ""))

                    total_matched += 1
                    action = "WOULD SET to_ids=False" if not commit else "SET to_ids=False"

                    row = {
                        "event_id":             event_id,
                        "attribute_id":         attr_id,
                        "attribute_uuid":       attr_uuid,
                        "attribute_type":       attr_type,
                        "attribute_value":      value[:120],
                        "matched_warninglists": wl_names,
                        "action":               action,
                        "timestamp":            datetime.now().isoformat(),
                    }
                    report_rows.append(row)

                    if commit:
                        new_comment = (
                            f"[Auto] IDS disabled by warninglist checker. Matched: {wl_names}"
                        )
                        if old_comment:
                            new_comment = f"{old_comment} | {new_comment}"

                        # Single API call: update to_ids + comment together
                        payload = {
                            "id":      attr_id,
                            "uuid":    attr_uuid,
                            "to_ids":  False,
                            "comment": new_comment,
                        }
                        pending_updates.append((row, payload))
                    else:
                        logger.info(
                            f"  [DRY-RUN] Attr {attr_id} (event={event_id}, "
                            f"{attr_type}={value[:50]}) → would set to_ids=False"
                        )
    except Exception as exc:
        fetch_error = exc
        logger.error(
            f"Attribute fetch aborted after {total_fetched:,} attributes: {exc}. "
            f"Applying the {len(pending_updates):,} update(s) collected so far."
        )

    # ── Apply updates ────────────────────────────────────────────────────
    # Deferred until all pages are fetched: the search filters on to_ids=True,
    # so updating mid-pagination shrinks the result set and shifts the page
    # offsets, silently skipping attributes on later pages.
    for row, payload in pending_updates:
        attr_id   = payload["id"]
        attr_uuid = payload["uuid"]
        event_id  = row["event_id"]
        try:
            with_retry(
                lambda p=payload: misp.update_attribute(p),
                retry_attempts, retry_delay,
                label=f"update-{attr_id}",
            )
            # Best-effort audit tag
            try:
                misp.tag(attr_uuid, AUDIT_TAG, local=True)
            except Exception:
                pass

            total_updated += 1
            modified_event_ids.add(event_id)
            logger.info(
                f"  ✓ Attr {attr_id} (event={event_id}, "
                f"{row['attribute_type']}={row['attribute_value'][:50]}) → to_ids=False"
            )
        except Exception as exc:
            logger.error(f"  ✗ Failed to update attr {attr_id}: {exc}")
            row["action"] = f"FAILED: {exc}"

    # ── Publish modified events ──────────────────────────────────────────
    if commit and modified_event_ids:
        logger.info(f"Publishing {len(modified_event_ids)} modified event(s) ...")
        for eid in sorted(modified_event_ids):
            try:
                with_retry(
                    lambda e=eid: misp.publish(e),
                    retry_attempts, retry_delay,
                    label=f"publish-{eid}",
                )
                logger.info(f"  ✓ Event {eid} published.")
            except Exception as exc:
                logger.error(f"  ✗ Failed to publish event {eid}: {exc}")

    # ── Summary ──────────────────────────────────────────────────────────
    logger.info("=" * 70)
    logger.info("SUMMARY")
    logger.info("=" * 70)
    logger.info(f"  Attributes fetched     : {total_fetched:,}")
    logger.info(f"  Skipped (non-completed): {total_skipped_analysis:,}")
    logger.info(f"  Warninglist matches    : {total_matched:,}")
    if commit:
        logger.info(f"  Attributes updated     : {total_updated:,}")
        logger.info(f"  Events published       : {len(modified_event_ids):,}")
    else:
        logger.info(
            f"  Attributes to update   : {total_matched:,} "
            f"(dry-run — re-run with --commit to apply)"
        )
    if matcher.clean_hash_enabled or matcher.clean_hash_hits:
        logger.info(f"  clean-hash-matched values    : {matcher.clean_hash_hits:,}")
    if matcher.user_content_skips:
        top = sorted(matcher.user_content_skips.items(), key=lambda kv: -kv[1])[:5]
        logger.info(
            f"  Kept (user-created host on shared platform): "
            f"{sum(matcher.user_content_skips.values()):,} value(s) — "
            + ", ".join(f"{p}={n}" for p, n in top)
        )
    if fetch_error is not None:
        logger.error(f"  INCOMPLETE RUN — fetch aborted: {fetch_error}")
    logger.info("=" * 70)

    return report_rows, fetch_error


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_console_table(rows: list[dict]) -> None:
    if not rows:
        print("\n  No attributes matched any warninglist. Nothing to do.\n")
        return

    print("\n" + "=" * 130)
    print(
        f"{'Event ID':<10} {'Attr ID':<10} {'Type':<12} "
        f"{'Value':<40} {'Matched Warninglist(s)':<45} {'Action'}"
    )
    print("-" * 130)
    for row in rows:
        print(
            f"{row['event_id']:<10} {row['attribute_id']:<10} "
            f"{row['attribute_type']:<12} "
            f"{row['attribute_value'][:38]:<40} "
            f"{row['matched_warninglists'][:43]:<45} "
            f"{row['action']}"
        )
    print("=" * 130)
    print(f"  Total: {len(rows):,} attribute(s)\n")


def write_csv_report(rows: list[dict], output_path: str) -> None:
    if not rows:
        return
    fieldnames = [
        "event_id", "attribute_id", "attribute_uuid",
        "attribute_type", "attribute_value",
        "matched_warninglists", "action", "timestamp",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    logger.info(f"CSV report: {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="MISP Warninglist Attribute Checker v3 — local fast matching",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 misp_warninglist_check.py               # dry-run\n"
            "  python3 misp_warninglist_check.py --commit      # apply changes\n"
            "  python3 misp_warninglist_check.py --exclude-keywords VPN,Tor\n"
        ),
    )
    p.add_argument("--config",           default=str(DEFAULT_CONFIG),
                   help=f"Config file (default: {DEFAULT_CONFIG})")
    p.add_argument("--commit",           action="store_true", default=False,
                   help="Apply changes. Without this flag runs in dry-run mode.")
    p.add_argument("--exclude-keywords", default=",".join(DEFAULT_EXCLUDE_KEYWORDS),
                   help=f"Comma-separated keywords to exclude warninglists (default: {','.join(DEFAULT_EXCLUDE_KEYWORDS)})")
    p.add_argument("--output",           default=None,
                   help="CSV report output path (default: auto-timestamped next to this script)")
    p.add_argument("--days",             type=int, default=None,
                   help="Only check attributes modified, or whose event was published/synced, in the last N days (default: check all attributes)")
    p.add_argument("--clean-hash-db",          default=str(clean_hash_feed.DEFAULT_DB),
                   help=f"clean-hash feed store (default: {clean_hash_feed.DEFAULT_DB})")
    p.add_argument("--no-clean-hash",          action="store_true", default=False,
                   help="Do not look up hashes in the clean-hash feed store.")
    p.add_argument("--verbose", "-v",    action="store_true", default=False,
                   help="Debug logging.")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    args = parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║    MISP Warninglist Attribute Checker  v3  (local match)    ║")
    print("║    Prevent false positives on security devices              ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

    mode = "COMMIT (changes WILL be applied)" if args.commit else "DRY-RUN (no changes)"
    logger.info(f"Mode  : {mode}")
    logger.info(f"Log   : {LOG_FILE}")

    cfg  = load_config(args.config)
    misp = connect_misp(cfg)

    exclude_keywords = [kw.strip() for kw in args.exclude_keywords.split(",") if kw.strip()]
    logger.info(f"Excluding warninglists containing: {exclude_keywords}")

    # Get enabled warninglist names from MISP (one API call)
    enabled_names = get_enabled_warninglist_names(misp)

    # Load and index warninglists from local disk (zero future API calls)
    logger.info(f"Loading warninglists from {WL_DIR} ...")
    clean_hash    = None if args.no_clean_hash else open_clean_hash(args.clean_hash_db)
    matcher = LocalWarninglistMatcher(enabled_names, exclude_keywords, clean_hash=clean_hash)

    # Fetch, match, update
    report_rows, fetch_error = process_attributes(
        misp, cfg, matcher, commit=args.commit, days=args.days
    )

    print_console_table(report_rows)

    if report_rows:
        ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = args.output or str(SCRIPT_DIR / f"misp_wl_report_{ts}.csv")
        write_csv_report(report_rows, output_path)

    if not args.commit and report_rows:
        print(
            "  ⚠  DRY-RUN — no changes were made.\n"
            "     Re-run with --commit to apply.\n"
        )

    if fetch_error is not None:
        sys.exit(1)


if __name__ == "__main__":
    main()
