#!/var/www/MISP/venv/bin/python3
"""
Clean-file hash feed Collector
=========================================
Pulls the vendor clean-hash feed (sha256 / size /
filename of known-clean vendor files) one hour per API call and keeps it in a
local SQLite store, because the API only serves the last 30 days.

Each run fetches every complete hour of the last 30 days that is not yet in
the store, plus the most recent REFETCH_RECENT_HOURS again (late data).
A first run therefore backfills ~720 hours; an hourly cron run makes ~4 calls.

The store is read by misp_warninglist_check.py / misp_wl_reenable.py through
CleanHashStore (read-only) to flag hashes of known-clean vendor files.

Usage:
    ./clean_hash_feed.py              # collect
    ./clean_hash_feed.py --stats      # show store stats
    ./clean_hash_feed.py --db PATH    # use another store

Config (.env): CLEAN_HASH_API_KEY (required), CLEAN_HASH_URL (required), CLEAN_HASH_DELAY_SECONDS
Spec: docs/superpowers/specs/2026-10-29-clean-hash-enrichment-design.md
"""

import argparse
import io
import logging
import os
import re
import sqlite3
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

import requests


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCRIPT_DIR           = Path(__file__).resolve().parent
DEFAULT_DB           = SCRIPT_DIR / "data" / "clean_hash_feed.sqlite"
LOG_FILE             = SCRIPT_DIR / "logs" / "clean_hash_feed.log"
RETENTION_DAYS       = 30
REFETCH_RECENT_HOURS = 3
HTTP_TIMEOUT         = (10, 120)      # (connect, read) seconds
RETRY_DELAYS         = (2, 4, 8)      # seconds; one retry per entry
MAX_RETRY_AFTER      = 60             # cap for a 429 Retry-After header

_SHA256 = re.compile(r"^[0-9a-f]{64}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    sha256       TEXT PRIMARY KEY,
    size         INTEGER,
    filename     TEXT,
    release_date TEXT,
    first_seen   TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS fetched_hours (
    start_time TEXT PRIMARY KEY,
    fetched_at TEXT NOT NULL,
    file_count INTEGER NOT NULL
);
"""

logger = logging.getLogger("clean_hash_feed")
logger.setLevel(logging.INFO)
logger.propagate = False


class AuthError(Exception):
    """API key rejected (401/403) — no point continuing the run."""


class FetchError(Exception):
    """One hour could not be fetched; it is retried on the next run."""


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------
def floor_hour(dt: datetime) -> datetime:
    return dt.replace(minute=0, second=0, microsecond=0)


def hour_key(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:00:00Z")


def start_time_param(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:00:00.000Z")


def plan_hours(now_utc: datetime, fetched: set[str]) -> list[datetime]:
    """Complete hours of the retention window still missing, plus the most recent ones again."""
    latest   = floor_hour(now_utc) - timedelta(hours=1)
    earliest = floor_hour(now_utc - timedelta(days=RETENTION_DAYS)) + timedelta(hours=1)
    recent   = {latest - timedelta(hours=i) for i in range(REFETCH_RECENT_HOURS)}
    hours, h = [], earliest
    while h <= latest:
        if h in recent or hour_key(h) not in fetched:
            hours.append(h)
        h += timedelta(hours=1)
    return hours


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------
def parse_feed_xml(data: bytes) -> tuple[list[dict], int]:
    """Return (records, invalid_sha256_count). Tags are matched by local name."""
    records, invalid = [], 0
    release_date = ""
    for _, elem in ET.iterparse(io.BytesIO(data), events=("end",)):
        tag = elem.tag.rsplit("}", 1)[-1]
        if tag == "releasedate":
            release_date = (elem.text or "").strip()
        elif tag == "file":
            fields = {c.tag.rsplit("}", 1)[-1]: (c.text or "").strip() for c in elem}
            sha256 = fields.get("sha256", "").lower()
            if not _SHA256.match(sha256):
                invalid += 1
            else:
                size = fields.get("size", "")
                records.append({
                    "sha256":       sha256,
                    "size":         int(size) if size.isdigit() else None,
                    "filename":     fields.get("filename", ""),
                    "release_date": release_date,
                })
            elem.clear()
    return records, invalid


# ---------------------------------------------------------------------------
# Store (writer side)
# ---------------------------------------------------------------------------
def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def init_db(path: Path) -> sqlite3.Connection:
    path = Path(path)
    if not path.parent.exists():
        path.parent.mkdir(parents=True)
        os.chmod(path.parent, 0o750)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    os.chmod(path, 0o640)
    return conn


def fetched_hour_keys(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT start_time FROM fetched_hours")}


def store_hour(conn: sqlite3.Connection, hour: datetime, records: list[dict]) -> tuple[int, int]:
    """Insert one hour's records and mark the hour fetched, atomically. Returns (new, duplicate)."""
    now = _utc_now_iso()
    new = 0
    with conn:
        for r in records:
            cur = conn.execute(
                "INSERT OR IGNORE INTO files (sha256, size, filename, release_date, first_seen) "
                "VALUES (?, ?, ?, ?, ?)",
                (r["sha256"], r["size"], r["filename"], r["release_date"], now),
            )
            new += cur.rowcount
        conn.execute(
            "INSERT OR REPLACE INTO fetched_hours (start_time, fetched_at, file_count) VALUES (?, ?, ?)",
            (hour_key(hour), now, len(records)),
        )
    return new, len(records) - new


# ---------------------------------------------------------------------------
# Store (reader side) — used by the warninglist checker
# ---------------------------------------------------------------------------
class CleanHashStore:
    """Read-only access to the clean-hash store."""

    def __init__(self, path):
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"clean-hash store not found: {path}")
        self.path  = path
        self._conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)

    def lookup(self, sha256: str) -> dict | None:
        row = self._conn.execute(
            "SELECT sha256, size, filename, release_date FROM files WHERE sha256 = ?", (sha256,)
        ).fetchone()
        if row is None:
            return None
        return dict(zip(("sha256", "size", "filename", "release_date"), row))

    def stats(self) -> dict:
        files, newest = self._conn.execute("SELECT COUNT(*), MAX(release_date) FROM files").fetchone()
        hours, last   = self._conn.execute("SELECT COUNT(*), MAX(fetched_at) FROM fetched_hours").fetchone()
        return {"files": files, "newest_release": newest, "last_fetched_at": last, "hours_fetched": hours}

    def close(self) -> None:
        self._conn.close()


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def fetch_hour(session, url: str, api_key: str, hour: datetime, sleep=time.sleep) -> bytes:
    """Body of one hour of clean-hash. Raises AuthError on 401/403, FetchError after retries."""
    label = start_time_param(hour)
    for attempt in range(len(RETRY_DELAYS) + 1):
        wait = RETRY_DELAYS[attempt] if attempt < len(RETRY_DELAYS) else None
        try:
            r = session.get(url, params={"startTime": label},
                            headers={"x-api-key": api_key}, timeout=HTTP_TIMEOUT)
        except requests.RequestException as exc:
            # str(exc) carries the URL but never the header, so the key is not logged
            problem = f"{type(exc).__name__}: {exc}"
        else:
            if r.status_code == 200:
                return r.content
            if r.status_code in (401, 403):
                raise AuthError(f"HTTP {r.status_code} — API key invalid or not authorised")
            if r.status_code != 429 and r.status_code < 500:
                raise FetchError(f"HTTP {r.status_code}")
            problem = f"HTTP {r.status_code}"
            retry_after = str(r.headers.get("Retry-After", ""))
            if r.status_code == 429 and retry_after.isdigit() and wait is not None:
                wait = min(int(retry_after), MAX_RETRY_AFTER)
        if wait is None:
            raise FetchError(f"{problem} (gave up after {len(RETRY_DELAYS)} retries)")
        logger.warning(f"  [{label}] {problem}; retrying in {wait}s ...")
        sleep(wait)


# ---------------------------------------------------------------------------
# Collect
# ---------------------------------------------------------------------------
def collect(conn, session, url: str, api_key: str, now_utc: datetime,
            delay: float = 0.5, sleep=time.sleep) -> int:
    """Fetch all planned hours into the store. Returns the process exit code (0/1/2)."""
    started = time.monotonic()
    hours   = plan_hours(now_utc, fetched_hour_keys(conn))
    logger.info(f"Hours to fetch: {len(hours)}"
                + (f" ({hour_key(hours[0])} .. {hour_key(hours[-1])})" if hours else ""))

    done = skipped = new_total = dup_total = invalid_total = 0
    for i, hour in enumerate(hours):
        if i and delay:
            sleep(delay)
        label = start_time_param(hour)
        try:
            body = fetch_hour(session, url, api_key, hour, sleep=sleep)
            records, invalid = parse_feed_xml(body)
        except AuthError as exc:
            logger.error(f"[{label}] {exc}. Stopping.")
            return 2
        except (FetchError, ET.ParseError) as exc:
            logger.error(f"[{label}] skipped: {exc}")
            skipped += 1
            continue
        new, dup = store_hour(conn, hour, records)
        done          += 1
        new_total     += new
        dup_total     += dup
        invalid_total += invalid
        logger.info(f"  [{label}] files={len(records):,} new={new:,} dup={dup:,}"
                    + (f" invalid_sha256={invalid}" if invalid else ""))

    logger.info("=" * 70)
    logger.info(f"  Hours fetched / skipped : {done:,} / {skipped:,}")
    logger.info(f"  Files new / duplicate   : {new_total:,} / {dup_total:,}")
    logger.info(f"  Invalid sha256 skipped  : {invalid_total:,}")
    logger.info(f"  Elapsed                 : {time.monotonic() - started:.1f}s")
    logger.info("=" * 70)
    return 1 if skipped else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
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


def _setup_logging() -> None:
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception as exc:
        print(f"[WARNING] Could not open log file {LOG_FILE}: {exc}", file=sys.stderr)


def main() -> int:
    p = argparse.ArgumentParser(description="Collect Clean-file hash feed into a local SQLite store")
    p.add_argument("--db", default=str(DEFAULT_DB), help=f"Store path (default: {DEFAULT_DB})")
    p.add_argument("--stats", action="store_true", help="Print store stats and exit")
    args = p.parse_args()

    _setup_logging()

    if args.stats:
        try:
            st = CleanHashStore(args.db).stats()
        except FileNotFoundError as exc:
            logger.error(str(exc))
            return 2
        for k, v in st.items():
            print(f"{k:<16}: {v:,}" if isinstance(v, int) else f"{k:<16}: {v}")
        return 0

    load_env(SCRIPT_DIR / ".env")
    api_key = os.environ.get("CLEAN_HASH_API_KEY", "").strip()
    if not api_key:
        logger.error(f"CLEAN_HASH_API_KEY is not set (add it to {SCRIPT_DIR / '.env'}).")
        return 2
    url   = os.environ.get("CLEAN_HASH_URL", "").strip()
    if not url:
        logger.error("CLEAN_HASH_URL is not set (add it to .env).")
        return 2
    delay = float(os.environ.get("CLEAN_HASH_DELAY_SECONDS", "0.5"))

    logger.info(f"clean-hash feed collect → {args.db}")
    conn = init_db(Path(args.db))
    try:
        with requests.Session() as session:
            return collect(conn, session, url, api_key, datetime.now(timezone.utc), delay=delay)
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
