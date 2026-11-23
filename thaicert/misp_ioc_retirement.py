#!/var/www/MISP/venv/bin/python3
"""
MISP IOC Retirement Script (with Enrichment & Retry Logic)
Author: Antigravity
Description:
  1. Asks MISP (server-side filters, paginated) for to_ids=True attributes owned by
     OWNER_ORG_ID that are older than their category threshold:
     IP=30d, Domain/URL=90d, Hash=180d. Whitelisted values are fetched separately (any age).
  2. Takes at most MAX_CHECKS_PER_RUN candidates, round-robin across categories,
     skipping ones kept by a run less than RECHECK_DAYS ago (state file), so
     successive runs work through the whole backlog.
  3. Re-validates them against up to four configurable enrichment providers (A-D).
     Composite values (ip|port, domain|ip, filename|hash) are split first.
  4. Soft-disables (to_ids=False) confirmed stale IOCs.
  5. Republishes affected events so downstream sync partners pick up the changes.
"""

import ipaddress
import json
import os
import sys
import time
import logging
from logging.handlers import RotatingFileHandler
import requests
import urllib3
from pymisp import ExpandedPyMISP

# Suppress self-signed certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Process locking imports (Unix only)
try:
    import fcntl
except ImportError:
    fcntl = None


# ── Custom .env loader ────────────────────────────────────────────────────────
def load_env(path):
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip("'\""))


script_dir = os.path.dirname(os.path.abspath(__file__))
load_env(os.path.join(script_dir, ".env"))

# ── Config ────────────────────────────────────────────────────────────────────
MISP_URL         = os.environ.get("MISP_URL",         "https://localhost")
MISP_KEY         = os.environ.get("MISP_KEY",         "")
MISP_VERIFY_CERT = os.environ.get("MISP_VERIFY_CERT", "False").lower() in ("true", "1", "yes")
OWNER_ORG_ID     = os.environ.get("OWNER_ORG_ID",     "1")
DRY_RUN          = os.environ.get("DRY_RUN",          "True").lower() in ("true", "1", "yes")

# Enrichment providers — endpoints and credentials come only from .env.
# A provider without its URL (and, where required, its key) is skipped.
ENRICH_A_URL          = os.environ.get("ENRICH_A_URL",          "").rstrip("/")  # IOC API base (all types)
ENRICH_A_TOKEN        = os.environ.get("ENRICH_A_TOKEN",        "")
ENRICH_B_URL          = os.environ.get("ENRICH_B_URL",          "")              # URL lookup endpoint
ENRICH_B_KEY          = os.environ.get("ENRICH_B_KEY",          "")
ENRICH_C_URL          = os.environ.get("ENRICH_C_URL",          "")              # hash lookup endpoint
ENRICH_C_KEY          = os.environ.get("ENRICH_C_KEY",          "")
ENRICH_D_URL          = os.environ.get("ENRICH_D_URL",          "").rstrip("/")  # indicator API base (all types)
ENRICH_D_KEY          = os.environ.get("ENRICH_D_KEY",          "")              # optional
ENRICH_D_KEY_HEADER   = os.environ.get("ENRICH_D_KEY_HEADER",   "X-API-Key")

ENRICH_A_ON = bool(ENRICH_A_URL and ENRICH_A_TOKEN)
ENRICH_B_ON = bool(ENRICH_B_URL and ENRICH_B_KEY)
ENRICH_C_ON = bool(ENRICH_C_URL and ENRICH_C_KEY)
ENRICH_D_ON = bool(ENRICH_D_URL)

IP_AGE_THRESHOLD      = int(os.environ.get("IP_AGE_THRESHOLD",      "30"))
DOMAIN_AGE_THRESHOLD  = int(os.environ.get("DOMAIN_AGE_THRESHOLD",  "90"))
URL_AGE_THRESHOLD     = int(os.environ.get("URL_AGE_THRESHOLD",      "90"))
HASH_AGE_THRESHOLD    = int(os.environ.get("HASH_AGE_THRESHOLD",    "180"))
DEFAULT_AGE_THRESHOLD = int(os.environ.get("DEFAULT_AGE_THRESHOLD",  "90"))

MAX_CHECKS_PER_RUN = int(os.environ.get("MAX_CHECKS_PER_RUN", "200"))   # enrichment-checked candidates per run
RECHECK_DAYS       = int(os.environ.get("RECHECK_DAYS",       "30"))    # skip IOCs kept less than N days ago
PAGE_SIZE          = int(os.environ.get("PAGE_SIZE",          "1000"))  # MISP search page size
STATE_FILE         = os.environ.get("RETIREMENT_STATE_FILE",
                                    os.path.join(script_dir, "data", "retirement_state.json"))
API_DELAY          = float(os.environ.get("API_DELAY_SECONDS", "0.3"))
HTTP_TIMEOUT       = int(os.environ.get("HTTP_TIMEOUT", "12"))
MAX_HTTP_RETRIES   = 2

# Whitelist configuration
WHITELIST_DIR    = os.environ.get("WHITELIST_DIR", os.path.join(script_dir, "whitelist"))
WHITELIST_IOCS   = set()
WHITELIST_ACTION = os.environ.get("WHITELIST_ACTION", "disable").lower()  # "disable" or "remove"



LOG_FILE = os.environ.get("LOG_FILE", os.path.join(script_dir, "logs", "misp_cleanup.log"))

# ── Logging ───────────────────────────────────────────────────────────────────
# The script writes its own rotating log; cron should send stdout to /dev/null
# (otherwise every line lands in the log twice).
os.makedirs(os.path.dirname(os.path.abspath(LOG_FILE)), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("misp_cleanup")

# ── IOC Categories ────────────────────────────────────────────────────────────
IP_TYPES     = {"ip-src", "ip-dst", "ip-dst|port", "ip-src|port"}
DOMAIN_TYPES = {"domain", "hostname", "domain|ip"}
URL_TYPES    = {"url", "uri"}
HASH_TYPES   = {"md5", "sha1", "sha256", "sha512",
                 "filename|md5", "filename|sha1", "filename|sha256"}
CATEGORY_TYPES = {
    "IP":     sorted(IP_TYPES),
    "DOMAIN": sorted(DOMAIN_TYPES),
    "URL":    sorted(URL_TYPES),
    "HASH":   sorted(HASH_TYPES),
}

# OPT: pre-build threshold dict once at module level — avoids rebuilding on every call
_THRESHOLD_MAP = {
    "IP":     IP_AGE_THRESHOLD,
    "DOMAIN": DOMAIN_AGE_THRESHOLD,
    "URL":    URL_AGE_THRESHOLD,
    "HASH":   HASH_AGE_THRESHOLD,
}

def get_category(t):
    if t in IP_TYPES:     return "IP"
    if t in DOMAIN_TYPES: return "DOMAIN"
    if t in URL_TYPES:    return "URL"
    if t in HASH_TYPES:   return "HASH"
    return "OTHER"

def get_threshold(cat):
    return _THRESHOLD_MAP.get(cat, DEFAULT_AGE_THRESHOLD)


def lookup_value(attr_type, value):
    """
    The part of an attribute value that enrichment providers understand, or None
    if it cannot be checked. Composite types are split:
      ip-src|port / ip-dst|port -> IP,  domain|ip -> domain,  filename|<hash> -> hash.
    IP values must parse as an IP address.
    """
    value = (value or "").strip()
    if attr_type in ("ip-src|port", "ip-dst|port", "domain|ip"):
        value = value.split("|", 1)[0].strip()
    elif attr_type.startswith("filename|"):
        value = value.rsplit("|", 1)[-1].strip()
    if not value:
        return None
    if attr_type in IP_TYPES:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return None
    return value


# ── State: when each kept IOC was last checked ────────────────────────────────
def load_state(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return {str(k): int(v) for k, v in data.items()}
    except FileNotFoundError:
        return {}
    except Exception as e:
        log.warning(f"State file {path} unreadable ({e}) — starting with an empty state.")
        return {}


def save_state(path, state, now):
    """Write the state atomically, dropping entries older than RECHECK_DAYS."""
    keep_after = now - RECHECK_DAYS * 86400
    state = {k: v for k, v in state.items() if v > keep_after}
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


# ── Global HTTP Session with Pooling ──────────────────────────────────────────
session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=20)
session.mount("https://", adapter)
session.mount("http://",  adapter)


# ── Robust Request Helper with Retries ────────────────────────────────────────
def request_with_retry(method, url, max_retries=MAX_HTTP_RETRIES, **kwargs):
    """
    Sends an HTTP request with exponential-backoff retry on Timeout/ConnectionError.
    OPT: single session.request() dispatch instead of branching on method string.
    """
    kwargs.setdefault("timeout", HTTP_TIMEOUT)
    for attempt in range(max_retries + 1):
        try:
            return session.request(method.upper(), url, **kwargs)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
            if attempt < max_retries:
                sleep_time = 2 ** attempt   # 1 s, then 2 s
                log.warning(
                    f"Request timeout/connection error for {url} "
                    f"(attempt {attempt+1}/{max_retries+1}). "
                    f"Retrying in {sleep_time}s ... Error: {exc}"
                )
                time.sleep(sleep_time)
            else:
                log.error(f"Request failed after {max_retries+1} attempts for {url}. Error: {exc}")
                raise


# ── Whitelist Loader ──────────────────────────────────────────────────────────
def load_whitelist(whitelist_dir):
    """
    Scans whitelist directory for .txt files; returns a set of whitelisted IOC values.
    Lines starting with '#' and blank lines are ignored.
    """
    whitelist = set()
    if not os.path.exists(whitelist_dir):
        log.warning(f"Whitelist directory '{whitelist_dir}' does not exist.")
        return whitelist

    log.info(f"Loading whitelists from directory: {whitelist_dir}")
    try:
        files = [f for f in os.listdir(whitelist_dir) if f.endswith(".txt")]
        if not files:
            log.warning(f"No .txt whitelist files found in {whitelist_dir}")
            return whitelist

        for filename in files:
            filepath = os.path.join(whitelist_dir, filename)
            try:
                count = 0
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        whitelist.add(line)
                        count += 1
                log.info(f"  Loaded {count} item(s) from {filename}")
            except Exception as e:
                log.error(f"  Error reading {filename}: {e}")
    except Exception as e:
        log.error(f"Error scanning whitelist directory {whitelist_dir}: {e}")

    log.info(f"Total whitelisted items loaded: {len(whitelist)}")
    return whitelist


# ── Enrichment Helpers ────────────────────────────────────────────────────────
# Return values:
#   True  → still active in feed  (KEEP)
#   False → not found / offline   (RETIRE)
#   None  → API error             (safety-fail → KEEP)

def check_provider_d(category, value):
    """Provider D: indicator API, any IOC category (pulse count > 0 = active)."""
    if not ENRICH_D_ON:
        return None
    type_map = {"IP": "IPv6" if ":" in value else "IPv4", "DOMAIN": "domain", "URL": "url", "HASH": "file"}
    ind_type = type_map.get(category)
    if not ind_type:
        return None
    url = (
        f"{ENRICH_D_URL}"
        f"/{ind_type}/{requests.utils.quote(value, safe='')}/general"
    )
    headers = {ENRICH_D_KEY_HEADER: ENRICH_D_KEY} if ENRICH_D_KEY else {}
    try:
        r = request_with_retry("GET", url, headers=headers)
        if r.status_code == 200:
            pulses = r.json().get("pulse_info", {}).get("count", 0)
            log.debug(f"Provider D {category} {value}: {pulses} pulses")
            return pulses > 0
        if r.status_code == 404:
            log.debug(f"Provider D {category} {value}: not found")
            return False
        log.warning(f"Provider D HTTP {r.status_code} for {value}")
        return None
    except Exception as e:
        log.error(f"Provider D error for {value}: {e}")
        return None


def check_provider_b(value):
    """Provider B: URL lookup (URL type only)."""
    if not ENRICH_B_ON:
        return None
    try:
        r = request_with_retry(
            "POST",
            ENRICH_B_URL,
            headers={"Auth-Key": ENRICH_B_KEY},
            data={"url": value},
        )
        if r.status_code == 200:
            res = r.json()
            qs  = res.get("query_status")
            if qs == "ok":
                status = res.get("url_status", "")
                log.debug(f"Provider B {value}: {status}")
                return status == "online"
            if qs == "no_results":
                log.debug(f"Provider B {value}: not found")
                return False
            log.warning(f"Provider B status '{qs}' for {value}")
            return None
        log.warning(f"Provider B HTTP {r.status_code} for {value}")
        return None
    except Exception as e:
        log.error(f"Provider B error for {value}: {e}")
        return None


def check_provider_c(value):
    """Provider C: hash lookup (hash types only)."""
    if not ENRICH_C_ON:
        return None
    try:
        r = request_with_retry(
            "POST",
            ENRICH_C_URL,
            headers={"Auth-Key": ENRICH_C_KEY},
            data={"query": "get_info", "hash": value},
        )
        if r.status_code == 200:
            qs = r.json().get("query_status")
            log.debug(f"Provider C {value}: {qs}")
            if qs == "ok":             return True
            if qs == "hash_not_found": return False
            log.warning(f"Provider C status '{qs}' for {value}")
            return None
        log.warning(f"Provider C HTTP {r.status_code} for {value}")
        return None
    except Exception as e:
        log.error(f"Provider C error for {value}: {e}")
        return None


def check_provider_a(category, value, attr_type):
    """Provider A: IOC API (IPv4, domain, URL, sha256)."""
    if not ENRICH_A_ON:
        return None

    if category == "IP":
        if ":" in value:    # skip IPv6
            return None
        endpoint = f"{ENRICH_A_URL}/ioc/api/v1/ipv4"
    elif category == "DOMAIN":
        endpoint = f"{ENRICH_A_URL}/ioc/api/v1/domain"
    elif category == "URL":
        endpoint = f"{ENRICH_A_URL}/ioc/api/v1/url"
    elif category == "HASH":
        if attr_type not in ("sha256", "filename|sha256") or len(value) != 64:
            return None
        endpoint = f"{ENRICH_A_URL}/ioc/api/v1/file/sha256"
    else:
        return None

    try:
        r = request_with_retry(
            "GET",
            endpoint,
            params={"value": value},
            cookies={"access_token": ENRICH_A_TOKEN},
            verify=False,
        )
        if r.status_code == 404:
            log.debug(f"Provider A {category} {value}: 404 not found (retire)")
            return False
        if r.status_code == 429:
            log.warning(f"Provider A rate limit hit for {value}. Skipping.")
            return None
        if r.status_code in (401, 403):
            log.error(f"Provider A auth error {r.status_code} — check ENRICH_A_TOKEN.")
            return None
        if r.status_code != 200:
            log.warning(f"Provider A HTTP {r.status_code} for {value}")
            return None

        body = r.json()
        data = body.get("data")
        if data is None:
            log.debug(f"Provider A {category} {value}: no data returned (retire)")
            return False
        if data.get("benign") is True:
            log.debug(f"Provider A {category} {value}: marked benign (retire)")
            return False

        risk = data.get("risk")
        if risk is None:
            log.debug(f"Provider A {category} {value}: risk=null, no threat found (retire)")
            return False

        score = risk.get("malicious_score", 0)
        log.debug(f"Provider A {category} {value}: malicious_score={score}")
        return score > 0

    except Exception as e:
        log.error(f"Provider A error for {value}: {e}")
        return None


def is_still_active(category, value, attr_type=""):
    """
    Aggregate check across enrichment providers A, B, C and D.
    Short-circuits as soon as any API confirms the IOC is still active.
    Order: A (fast) → B/C (type-specific) → D (fallback/slow).
    Returns True (keep), False (retire), or None (all APIs errored → safety-keep).
    `value` must already be the lookup value (see lookup_value()).
    """
    checked = 0

    # 1. Provider A — fast, covers almost all types
    if ENRICH_A_ON:
        res = check_provider_a(category, value, attr_type)
        if res is not None:
            checked += 1
            if res:
                return True

    # 2. Provider B — URLs only
    if category == "URL" and ENRICH_B_ON:
        time.sleep(0.1)
        res = check_provider_b(value)
        if res is not None:
            checked += 1
            if res:
                return True

    # 3. Provider C — hashes only
    if category == "HASH" and ENRICH_C_ON:
        time.sleep(0.1)
        res = check_provider_c(value)
        if res is not None:
            checked += 1
            if res:
                return True

    # 4. Provider D — universal fallback (prone to timeouts; queried last)
    res = check_provider_d(category, value)
    if res is not None:
        checked += 1
        if res:
            return True

    if checked == 0:
        log.warning(f"No enrichment result for {category} {value}. Safety-keeping.")
        return None

    return False


# ── Candidate collection (server-side filtered, paginated) ────────────────────
def search_attributes(misp, **filters):
    """Yield attributes matching `filters`, page by page (PAGE_SIZE), with retries."""
    page = 1
    while True:
        for attempt in range(1, 4):
            try:
                resp = misp.search(controller="attributes", pythonify=False,
                                   include_context=False, limit=PAGE_SIZE, page=page, **filters)
                break
            except Exception as e:
                if attempt == 3:
                    raise
                log.warning(f"MISP search page {page} failed ({e}); retry {attempt}/2 in {5 * attempt}s")
                time.sleep(5 * attempt)
        if isinstance(resp, dict) and resp.get("errors"):
            raise RuntimeError(f"MISP search error: {resp['errors']}")
        batch = resp.get("Attribute", []) if isinstance(resp, dict) else (resp or [])
        yield from batch
        if len(batch) < PAGE_SIZE:
            return
        page += 1


def make_candidate(attr, now, is_whitelisted):
    atype    = attr.get("type", "")
    category = get_category(atype)
    ts       = attr.get("timestamp")
    return {
        "id":             str(attr.get("id")),
        "uuid":           attr.get("uuid"),
        "type":           atype,
        "category":       category,
        "value":          attr.get("value", ""),
        "age_days":       int((now - int(ts)) / 86400) if ts else 9999,
        "threshold":      get_threshold(category),
        "event_id":       attr.get("event_id") or attr.get("Event", {}).get("id"),
        "is_whitelisted": is_whitelisted,
    }


def owned_and_active(attr):
    """Defensive re-check of the server-side filters."""
    org = attr.get("Event", {}).get("orgc_id")
    return (org is None or str(org) == str(OWNER_ORG_ID)) and attr.get("to_ids") in (True, 1, "1")


def collect_whitelisted(misp, now):
    """Active attributes whose value is whitelisted, regardless of age."""
    if not WHITELIST_IOCS:
        return []
    out = []
    for attr in search_attributes(misp, org=OWNER_ORG_ID, to_ids=True, value=sorted(WHITELIST_IOCS)):
        if owned_and_active(attr) and attr.get("value", "").strip() in WHITELIST_IOCS:
            out.append(make_candidate(attr, now, True))
    log.info(f"Whitelisted active attributes: {len(out)}")
    return out


def collect_stale(misp, now, recent, state, exclude_ids):
    """
    Up to MAX_CHECKS_PER_RUN stale candidates, taken round-robin across the
    IP/DOMAIN/URL/HASH categories. Each category is queried with
    timestamp <= now - threshold, so MISP returns only stale attributes.
    Attributes kept by a run after `recent` (per `state`) are skipped.
    Returns (candidates, attributes_fetched, skipped_recent).
    """
    per_cat, fetched, skipped = {}, 0, 0
    for cat, types in CATEGORY_TYPES.items():
        cutoff = now - get_threshold(cat) * 86400
        picked = []
        for attr in search_attributes(misp, org=OWNER_ORG_ID, to_ids=True,
                                      type_attribute=types, timestamp=[1, cutoff]):
            fetched += 1
            if not owned_and_active(attr) or str(attr.get("id")) in exclude_ids:
                continue
            if state.get(attr.get("uuid"), 0) > recent:
                skipped += 1
                continue
            picked.append(make_candidate(attr, now, False))
            if len(picked) >= MAX_CHECKS_PER_RUN:
                break
        per_cat[cat] = picked
        log.info(f"  {cat:6} stale (>{get_threshold(cat)}d): picked {len(picked)}")

    # Round-robin so one big category cannot starve the others
    out, i = [], 0
    while len(out) < MAX_CHECKS_PER_RUN and any(i < len(v) for v in per_cat.values()):
        for picked in per_cat.values():
            if i < len(picked) and len(out) < MAX_CHECKS_PER_RUN:
                out.append(picked[i])
        i += 1
    return out, fetched, skipped


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    # ── Process lock to prevent overlapping runs ──────────────────────────────
    lock_file = None
    if fcntl:
        lock_file_path = "/tmp/misp_ioc_retirement.lock"
        try:
            lock_file = open(lock_file_path, "w")
            fcntl.lockf(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            print("Another instance of the script is already running. Exiting.", file=sys.stderr)
            sys.exit(0)

    log.info("=" * 60)
    log.info(f"MISP IOC Retirement  |  DRY_RUN={DRY_RUN}")
    log.info(
        f"Enrichment  A={'YES' if ENRICH_A_ON else 'NO'}  "
        f"B={'YES' if ENRICH_B_ON else 'NO'}  "
        f"C={'YES' if ENRICH_C_ON else 'NO'}  "
        f"D={'YES' if ENRICH_D_ON else 'NO'}"
    )
    log.info(
        f"Thresholds  IP:{IP_AGE_THRESHOLD}d  Domain:{DOMAIN_AGE_THRESHOLD}d  "
        f"URL:{URL_AGE_THRESHOLD}d  Hash:{HASH_AGE_THRESHOLD}d"
    )
    log.info("=" * 60)

    # ── Load file-based whitelist ─────────────────────────────────────────────
    WHITELIST_IOCS.update(load_whitelist(WHITELIST_DIR))
    env_whitelist = os.environ.get("WHITELIST_IOCS", "")
    if env_whitelist:
        env_items = [x.strip() for x in env_whitelist.split(",") if x.strip()]
        WHITELIST_IOCS.update(env_items)
        log.info(f"  Loaded {len(env_items)} item(s) from .env WHITELIST_IOCS")



    log.info("-" * 60)

    if not MISP_KEY:
        log.critical("MISP_KEY is not set. Aborting.")
        if lock_file:
            lock_file.close()
        sys.exit(1)

    try:
        misp = ExpandedPyMISP(MISP_URL, MISP_KEY, ssl=MISP_VERIFY_CERT)
        log.info(f"Connected to MISP at {MISP_URL}")
    except Exception as e:
        log.critical(f"MISP connection failed: {e}")
        if lock_file:
            lock_file.close()
        sys.exit(1)

    now      = int(time.time())
    state    = load_state(STATE_FILE)
    recent   = now - RECHECK_DAYS * 86400
    log.info(
        f"Limits      MAX_CHECKS_PER_RUN={MAX_CHECKS_PER_RUN}  RECHECK_DAYS={RECHECK_DAYS}  "
        f"state entries={len(state):,}"
    )

    # ── Fetch candidates with server-side filters (paginated) ─────────────────
    try:
        whitelist_cands = collect_whitelisted(misp, now)
        stale_cands, fetched, skipped_recent = collect_stale(
            misp, now, recent, state, {c["id"] for c in whitelist_cands}
        )
    except Exception as e:
        log.critical(f"Failed to fetch attributes: {e}")
        if lock_file:
            lock_file.close()
        sys.exit(1)

    candidates       = whitelist_cands + stale_cands
    total_fetched    = fetched + len(whitelist_cands)
    total_candidates = len(candidates)
    log.info(
        f"Candidates this run: {total_candidates} "
        f"({len(whitelist_cands)} whitelisted, {len(stale_cands)} stale; "
        f"{skipped_recent:,} skipped as checked < {RECHECK_DAYS}d ago)"
    )
    if total_candidates == 0:
        log.info("Nothing to retire. Done.")
        if lock_file:
            lock_file.close()
        return

    # ── Re-validate and retire ────────────────────────────────────────────────
    retired           = 0
    kept_enrich       = 0
    kept_error        = 0
    error_update      = 0
    events_to_publish = set()

    for idx, item in enumerate(candidates, 1):
        cat            = item["category"]
        val            = item["value"]
        age            = item["age_days"]
        thr            = item["threshold"]
        aid            = item["id"]
        evid           = item["event_id"]
        is_whitelisted = item["is_whitelisted"]

        if is_whitelisted:
            log.info(
                f"[{idx}/{total_candidates}] {cat} ({item['type']})  "
                f"WHITELIST MATCH — automatically disabling | {val}"
            )
            active = False
        else:
            log.info(
                f"[{idx}/{total_candidates}] {cat} ({item['type']})  "
                f"Age:{age}d > {thr}d  |  {val}"
            )
            lv = lookup_value(item["type"], val)
            if lv is None:
                log.warning(f"  Value not checkable as {item['type']}: {val!r}")
                active = None
            else:
                active = is_still_active(cat, lv, item["type"])

        if active is True:
            log.info("  ==> KEEP  (still active in enrichment feeds)")
            kept_enrich += 1
            if not DRY_RUN and item["uuid"]:
                state[item["uuid"]] = now

        elif active is None:
            log.info("  ==> KEEP  (API error — safety-fail)")
            kept_error += 1
            if not DRY_RUN and item["uuid"]:
                state[item["uuid"]] = now

        else:  # active is False → retire
            if is_whitelisted and WHITELIST_ACTION == "remove":
                if DRY_RUN:
                    log.info("  ==> DRY-RUN: Would delete whitelisted attribute")
                    retired += 1
                else:
                    try:
                        misp.delete_attribute(aid)
                        log.info("  ==> DELETED  (whitelisted attribute removed from MISP)")
                        retired += 1
                        events_to_publish.add(evid)
                    except Exception as e:
                        log.error(f"  ==> ERROR deleting attr {aid}: {e}")
                        error_update += 1
            else:
                if DRY_RUN:
                    log.info("  ==> DRY-RUN: Would set to_ids=False")
                    retired += 1
                else:
                    try:
                        misp.update_attribute({"id": aid, "to_ids": False})
                        log.info("  ==> RETIRED  (to_ids=False written to MISP)")
                        retired += 1
                        events_to_publish.add(evid)
                    except Exception as e:
                        log.error(f"  ==> ERROR updating attr {aid}: {e}")
                        error_update += 1

        # Save progress now and then so a crash does not lose the whole run
        if not DRY_RUN and idx % 100 == 0:
            save_state(STATE_FILE, state, now)

        # Polite rate-limit delay between enrichment API calls
        if idx < total_candidates and not is_whitelisted:
            time.sleep(API_DELAY)

    if not DRY_RUN:
        try:
            save_state(STATE_FILE, state, now)
        except Exception as e:
            log.error(f"Could not save state file {STATE_FILE}: {e}")

    # ── Republish affected events ─────────────────────────────────────────────
    if not DRY_RUN and events_to_publish:
        log.info(f"Republishing {len(events_to_publish)} event(s) (alert=False) …")
        for evid in events_to_publish:
            try:
                misp.publish(evid, alert=False)
                log.info(f"  ==> Published event {evid}")
            except Exception as e:
                log.error(f"  ==> ERROR publishing event {evid}: {e}")

    # ── Summary ───────────────────────────────────────────────────────────────
    log.info("=" * 60)
    log.info("Summary")
    log.info("=" * 60)
    log.info(f"  Attributes Fetched          : {total_fetched}")
    log.info(f"  Skipped (checked recently)  : {skipped_recent}")
    log.info(f"  Candidates Checked          : {total_candidates}")
    log.info(f"  Retired  (to_ids=False)     : {retired}")
    log.info(f"  Kept     (still in feeds)   : {kept_enrich}")
    log.info(f"  Kept     (API error/safety) : {kept_error}")
    log.info(f"  Update errors               : {error_update}")
    if DRY_RUN:
        log.info("  [DRY-RUN] — no changes written to MISP")
    else:
        log.info(f"  Events republished          : {len(events_to_publish)}")
    log.info("=" * 60)
    log.info("Job complete.")

    if lock_file:
        lock_file.close()


if __name__ == "__main__":
    main()
