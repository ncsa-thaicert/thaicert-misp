#!/var/www/MISP/venv/bin/python3
"""
MISP IOC Retirement Script (with Enrichment & Retry Logic)
Author: Antigravity
Description:
  1. Fetches ALL attributes from MISP owned by OWNER_ORG_ID; skips already-disabled ones.
  2. Filters by tiered age thresholds: IP=30d, Domain/URL=90d, Hash=180d.
  3. Re-validates stale candidates against up to four configurable enrichment providers (A-D).
  4. Soft-disables (to_ids=False) confirmed stale IOCs.
  5. Republishes affected events so downstream sync partners pick up the changes.
Optimizations:
  - Pre-computed threshold dict (no rebuild per call).
  - Simplified HTTP retry using single session.request() call.
  - Counter-based enrichment aggregation (no temporary list).
  - owner_str cached outside the candidate loop.
"""

import os
import sys
import time
import logging
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

MAX_ATTRS_PER_RUN = int(os.environ.get("MAX_ATTRS_PER_RUN", "5000"))
API_DELAY         = float(os.environ.get("API_DELAY_SECONDS", "0.3"))
HTTP_TIMEOUT      = int(os.environ.get("HTTP_TIMEOUT", "12"))
MAX_HTTP_RETRIES  = 2

# Whitelist configuration
WHITELIST_DIR    = os.environ.get("WHITELIST_DIR", os.path.join(script_dir, "whitelist"))
WHITELIST_IOCS   = set()
WHITELIST_ACTION = os.environ.get("WHITELIST_ACTION", "disable").lower()  # "disable" or "remove"



LOG_FILE = os.environ.get("LOG_FILE", os.path.join(script_dir, "logs", "misp_cleanup.log"))

# ── Logging ───────────────────────────────────────────────────────────────────
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
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
    type_map = {"IP": "IPv4", "DOMAIN": "domain", "URL": "url", "HASH": "file"}
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
        if attr_type not in ("sha256", "filename|sha256") or len(value.split("|")[-1]) != 64:
            return None
        value    = value.split("|")[-1]
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

    OPT: uses an integer counter instead of a temporary list to detect all-error case.
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

    # ── Fetch ALL attributes; active-flag filtering done in Python ────────────
    log.info("Fetching all attributes (regardless of to_ids flag) …")
    try:
        resp = misp.search(controller="attributes",
                           limit=MAX_ATTRS_PER_RUN, pythonify=False)
        attributes = resp.get("Attribute", []) if isinstance(resp, dict) else resp
    except Exception as e:
        log.critical(f"Failed to fetch attributes: {e}")
        if lock_file:
            lock_file.close()
        sys.exit(1)

    total_fetched = len(attributes)
    log.info(f"Fetched {total_fetched} attribute(s).")

    # ── Filter: org ownership, active flag, whitelist/warninglist, age ─────────
    now       = time.time()
    owner_str = str(OWNER_ORG_ID)   # OPT: cast once outside loop
    candidates = []

    for attr in attributes:
        event   = attr.get("Event", {})

        # OPT: fastest exits first — skip foreign-org and disabled attrs before any other work
        if str(event.get("orgc_id", "")) != owner_str:
            continue
        if attr.get("to_ids") not in (True, 1, "1"):
            continue

        attr_value = attr.get("value", "")
        atype      = attr.get("type", "")
        ts         = attr.get("timestamp")

        # Whitelist: O(1) set membership
        is_whitelisted     = attr_value.strip() in WHITELIST_IOCS
        if not ts and not is_whitelisted:
            continue

        age_days  = int((now - int(ts)) / 86400) if ts else 9999
        category  = get_category(atype)
        threshold = get_threshold(category)

        if is_whitelisted or age_days > threshold:
            candidates.append({
                "id":                 attr.get("id"),
                "type":               atype,
                "category":           category,
                "value":              attr_value,
                "age_days":           age_days,
                "threshold":          threshold,
                "event_id":           event.get("id"),
                "event_info":         event.get("info", ""),
                "is_whitelisted":     is_whitelisted,
            })

    total_candidates = len(candidates)
    log.info(f"Found {total_candidates} stale candidate(s) exceeding their age threshold.")
    if total_candidates == 0:
        log.info("Nothing to retire. Done.")
        if lock_file:
            lock_file.close()
        return

    # Sort oldest-first for readable, stable log output
    candidates.sort(key=lambda x: x["age_days"], reverse=True)

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
            active = is_still_active(cat, val, item["type"])

        if active is True:
            log.info("  ==> KEEP  (still active in enrichment feeds)")
            kept_enrich += 1

        elif active is None:
            log.info("  ==> KEEP  (API error — safety-fail)")
            kept_error += 1

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

        # Polite rate-limit delay between enrichment API calls
        if idx < total_candidates:
            time.sleep(API_DELAY)

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
    log.info(f"  Stale Candidates            : {total_candidates}")
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
