# clean-hash feed Enrichment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** เก็บ clean-file hash feed ลง SQLite ทุกชั่วโมง แล้วให้ `misp_warninglist_check.py` / `misp_wl_reenable.py` ใช้ตัด false positive ของ `sha256` และ `filename|sha256`

**Architecture:** `clean_hash_feed.py` ไฟล์เดียวเป็นทั้ง collector (cron รายชั่วโมง) และ `CleanHashStore` (read-only lookup). `LocalWarninglistMatcher` รับ `clean_hash` เป็น optional และเพิ่มขั้นที่ 6 lookup sha256 ใน store

**Tech Stack:** Python 3.12 (`/var/www/MISP/venv/bin/python3`), `requests`, `sqlite3` (3.45), `xml.etree.ElementTree`, `unittest`

**Spec:** `docs/superpowers/specs/2026-10-29-clean-hash-enrichment-design.md`

## Global Constraints

- `/var/www/MISP/thaicert` ไม่ใช่ git repo — แทน commit ด้วย backup `<file>.bak_20261029` ก่อนแก้ไฟล์เดิม (ทำครั้งเดียวต่อไฟล์) และขั้น "Checkpoint" = รัน test ทั้งชุดผ่าน
- ห้ามติดตั้ง package เพิ่มใน MISP venv; test ใช้ `unittest` เท่านั้น
- รัน test ทุกครั้งจาก `/var/www/MISP/thaicert`: `/var/www/MISP/venv/bin/python3 -m unittest discover -s tests -t . -v`
- Test ต้องไม่เขียน production log: ใน `setUpModule` ให้ `misp_warninglist_check.logger.handlers.clear()` และ `clean_hash_feed` logger เช่นกัน
- ห้าม log API key ในทุกกรณี
- ค่าจาก spec: `DEFAULT_DB = /var/www/MISP/thaicert/data/clean_hash_feed.sqlite`, `RETENTION_DAYS = 30`, `REFETCH_RECENT_HOURS = 3`, `CLEAN_HASH_URL` (required, no default), `CLEAN_HASH_DELAY_SECONDS` default `0.5`, timeout `(10, 120)`, retry backoff `2/4/8` วินาที, stale threshold 24 ชม., `CLEAN_HASH_LIST_NAME` (from .env, default `"Clean hash feed"`), filename ตัดที่ 80 ตัวอักษร
- Exit code collector: `0` ครบ, `1` มีชั่วโมงถูกข้าม, `2` auth/config error
- Log format เดียวกับ checker: `"%(asctime)s [%(levelname)s] %(message)s"`

## Review Focus

1. DB มีอยู่แต่ว่าง (`last_fetched_at = None`) → checker ต้องเตือน stale และรันต่อ ไม่ crash — test ใน Task 4
2. hash ตัวใหญ่ / มี space ใน `filename|sha256` (`"a.dll| ABC…"`) → ต้อง match เหมือนตัวเล็ก — test ใน Task 4
3. `<file>` ที่ไม่มี `<size>` หรือ size ไม่ใช่ตัวเลข / ไม่มี `<filename>` → เก็บได้โดย `size=None`, `filename=""` ไม่ทิ้งทั้งชั่วโมง — test ใน Task 1
4. 429 พร้อม `Retry-After` ค่าใหญ่ (เช่น 3600) → รอไม่เกิน 60 วินาทีต่อครั้ง — test ใน Task 3
5. `CleanHashStore` อ่านขณะ collector ถือ write transaction ค้าง (WAL) → lookup ต้องได้ข้อมูลที่ commit แล้ว ไม่ error `database is locked` — test ใน Task 2

---

### Task 1: XML parser + hour planning (pure functions)

**Files:**
- Create: `clean_hash_feed.py`
- Create: `tests/__init__.py` (ว่าง), `tests/test_clean_hash_feed.py`

**Interfaces:**
- Produces:
  - `parse_feed_xml(data: bytes) -> tuple[list[dict], int]` — records `{"sha256", "size", "filename", "release_date"}` และจำนวน sha256 ที่ไม่ถูกต้อง; โยน `xml.etree.ElementTree.ParseError` ถ้า XML เสีย
  - `floor_hour(dt: datetime) -> datetime`
  - `hour_key(dt: datetime) -> str` → `"2026-10-29T09:00:00Z"` (ใช้เป็น key ใน `fetched_hours`)
  - `start_time_param(dt: datetime) -> str` → `"2026-10-29T09:00:00.000Z"`
  - `plan_hours(now_utc: datetime, fetched: set[str]) -> list[datetime]`
  - constants ตาม Global Constraints

- [ ] **Step 1: Write failing tests** ใน `tests/test_clean_hash_feed.py` class `ParseTests` / `PlanTests`

```python
SAMPLE = b"""<releaseMetaData xmlns="http://xml/metadataSharing.xsd"><company>Example Corp.</company><company>Example Corp.</company>
<releases><release><releasedate>2026-10-14T17:00:00</releasedate><objects>
<file><sha256>""" + b"A"*64 + b"""</sha256><size>1234</size><filename>a.dll</filename></file>
<file><sha256>nothex</sha256><size>1</size><filename>b.dll</filename></file></objects></release>
<release><releasedate>2026-10-14T18:00:00</releasedate><objects>
<file><sha256> """ + b"b"*64 + b""" </sha256><size>x</size></file></objects></release></releases></releaseMetaData>"""

def test_parse_sample(self):
    recs, bad = clean_hash_feed.parse_feed_xml(SAMPLE)
    self.assertEqual(bad, 1)
    self.assertEqual(recs[0], {"sha256": "a"*64, "size": 1234, "filename": "a.dll", "release_date": "2026-10-14T17:00:00"})
    self.assertEqual(recs[1], {"sha256": "b"*64, "size": None, "filename": "", "release_date": "2026-10-14T18:00:00"})

def test_parse_empty_releases(self):
    self.assertEqual(clean_hash_feed.parse_feed_xml(b'<releaseMetaData xmlns="http://xml/metadataSharing.xsd"><releases/></releaseMetaData>'), ([], 0))

def test_parse_broken_xml_raises(self):
    with self.assertRaises(ET.ParseError): clean_hash_feed.parse_feed_xml(b"<releaseMetaData><releases>")

def test_formats(self):
    t = datetime(2026, 10, 29, 9, 0, tzinfo=timezone.utc)
    self.assertEqual(clean_hash_feed.hour_key(t), "2026-10-29T09:00:00Z")
    self.assertEqual(clean_hash_feed.start_time_param(t), "2026-10-29T09:00:00.000Z")

def test_plan_first_run(self):
    now = datetime(2026, 10, 29, 10, 20, tzinfo=timezone.utc)
    hours = clean_hash_feed.plan_hours(now, set())
    self.assertEqual(hours[-1], datetime(2026, 10, 29, 9, tzinfo=timezone.utc))   # ไม่รวมชั่วโมง 10:00 ที่ยังไม่ครบ
    self.assertEqual(hours[0], datetime(2026, 9, 29, 11, tzinfo=timezone.utc))    # floor(now-30d)+1h
    self.assertEqual(len(hours), 719)
    self.assertEqual(hours, sorted(hours))

def test_plan_skips_fetched_but_refetches_last_3(self):
    now = datetime(2026, 10, 29, 10, 20, tzinfo=timezone.utc)
    fetched = {clean_hash_feed.hour_key(h) for h in clean_hash_feed.plan_hours(now, set())}
    self.assertEqual(clean_hash_feed.plan_hours(now, fetched),
                     [datetime(2026, 10, 29, h, tzinfo=timezone.utc) for h in (7, 8, 9)])
```

- [ ] **Step 2: Run** `... -m unittest tests.test_clean_hash_feed -v` → FAIL (`ModuleNotFoundError: clean_hash_feed`)

- [ ] **Step 3: Implement** ใน `clean_hash_feed.py` (shebang `#!/var/www/MISP/venv/bin/python3`, `chmod 755`). Parser ใช้ `ET.iterparse(io.BytesIO(data), events=("end",))`, local name = `tag.rsplit("}", 1)[-1]`, จำ `releasedate` ล่าสุด, เมื่อจบ `<file>` สร้าง record แล้ว `elem.clear()`. sha256 = `strip().lower()` ต้องตรง `^[0-9a-f]{64}$`. datetime ทั้งหมดเป็น UTC aware

- [ ] **Step 4: Run** → PASS

- [ ] **Step 5: Checkpoint** — test ทั้งชุดผ่าน

---

### Task 2: SQLite store + `CleanHashStore`

**Files:**
- Modify: `clean_hash_feed.py`
- Test: `tests/test_clean_hash_feed.py` (class `StoreTests`, ใช้ `tempfile.TemporaryDirectory`)

**Interfaces:**
- Consumes: `hour_key`, record dict จาก Task 1
- Produces:
  - `init_db(path: Path) -> sqlite3.Connection` — สร้าง parent dir (`750`), schema ตาม spec §4.1, `PRAGMA journal_mode=WAL`, chmod ไฟล์ `640`
  - `fetched_hour_keys(conn) -> set[str]`
  - `store_hour(conn, hour: datetime, records: list[dict]) -> tuple[int, int]` — `(new, duplicate)`; ทุกอย่างใน transaction เดียว (`with conn:`), upsert `fetched_hours(start_time, fetched_at, file_count=len(records))`
  - `class CleanHashStore: __init__(path) / lookup(sha256: str) -> dict | None / stats() -> dict / close()` — stats keys: `files`, `newest_release`, `last_fetched_at` (`None` ถ้าว่าง), `hours_fetched`

- [ ] **Step 1: Write failing tests**

```python
def test_store_dedup_keeps_first(self):
    n, d = clean_hash_feed.store_hour(conn, H, [rec("a"*64, "first.dll")])
    n2, d2 = clean_hash_feed.store_hour(conn, H2, [rec("a"*64, "second.dll")])
    self.assertEqual((n, d, n2, d2), (1, 0, 0, 1))
    self.assertEqual(clean_hash_feed.CleanHashStore(db).lookup("a"*64)["filename"], "first.dll")
    self.assertEqual(clean_hash_feed.fetched_hour_keys(conn), {clean_hash_feed.hour_key(H), clean_hash_feed.hour_key(H2)})

def test_store_hour_atomic(self):
    with self.assertRaises(Exception):
        clean_hash_feed.store_hour(conn, H, [rec("a"*64), {"sha256": None}])   # record เสียกลางทาง
    self.assertEqual(clean_hash_feed.fetched_hour_keys(conn), set())
    self.assertIsNone(clean_hash_feed.CleanHashStore(db).lookup("a"*64))

def test_empty_hour_recorded(self):
    clean_hash_feed.store_hour(conn, H, [])
    self.assertEqual(clean_hash_feed.CleanHashStore(db).stats()["hours_fetched"], 1)

def test_store_missing_file(self):
    with self.assertRaises(FileNotFoundError): clean_hash_feed.CleanHashStore(Path(tmp) / "nope.sqlite")

def test_store_is_readonly(self):
    s = clean_hash_feed.CleanHashStore(db)
    with self.assertRaises(sqlite3.OperationalError): s._conn.execute("DELETE FROM files")

def test_stats_empty_db(self):
    self.assertEqual(clean_hash_feed.CleanHashStore(db).stats()["last_fetched_at"], None)

def test_read_during_open_write_tx(self):          # Review Focus 5
    clean_hash_feed.store_hour(conn, H, [rec("a"*64)])
    conn.execute("BEGIN IMMEDIATE"); conn.execute("INSERT INTO files VALUES (?,?,?,?,?)", ("b"*64, 1, "x", "", "now"))
    s = clean_hash_feed.CleanHashStore(db)
    self.assertIsNotNone(s.lookup("a"*64)); self.assertIsNone(s.lookup("b"*64))
    conn.rollback()
```

- [ ] **Step 2: Run** → FAIL
- [ ] **Step 3: Implement** — `CleanHashStore` เปิด `sqlite3.connect(f"file:{path}?mode=ro", uri=True)` หลังเช็ค `Path(path).exists()` (ไม่งั้นโยน `FileNotFoundError`), เก็บ connection ใน `self._conn`
- [ ] **Step 4: Run** → PASS
- [ ] **Step 5: Checkpoint**

---

### Task 3: HTTP fetch + `collect()` + CLI

**Files:**
- Modify: `clean_hash_feed.py`
- Test: `tests/test_clean_hash_feed.py` (class `CollectTests`, fake session = object ที่มี `get(url, params, headers, timeout)` คืน response ปลอมที่มี `status_code`, `content`, `headers` จากคิวที่กำหนด; `sleep` เป็น list ที่บันทึกค่า)

**Interfaces:**
- Consumes: Task 1–2 ทั้งหมด
- Produces:
  - `class AuthError(Exception)`, `class FetchError(Exception)`
  - `fetch_hour(session, url: str, api_key: str, hour: datetime, sleep=time.sleep) -> bytes` — params `{"startTime": start_time_param(hour)}`, header `x-api-key`, timeout `(10, 120)`; 401/403 → `AuthError`; 429/5xx/`requests.RequestException` → retry 3 ครั้ง (รอ 2/4/8s; 429 ใช้ `Retry-After` ถ้าเป็นตัวเลข แต่ไม่เกิน 60) แล้ว `FetchError`; 4xx อื่น → `FetchError` ทันที
  - `collect(conn, session, url: str, api_key: str, now_utc: datetime, delay: float = 0.5, sleep=time.sleep) -> int` — คืน exit code; `AuthError` → log ERROR หยุดทันทีคืน `2`; `FetchError`/`ParseError` → log ERROR ข้ามชั่วโมงคืน `1` ตอนจบ; log สรุปท้ายรอบ (hours fetched/skipped, new, duplicate, invalid sha256, elapsed)
  - `load_env(path)` (copy จาก `misp_ioc_retirement.py`), `main() -> int`: `--stats` / `--db PATH`; ไม่มี `CLEAN_HASH_API_KEY` → ERROR คืน `2`; logger `"clean_hash_feed"` → `RotatingFileHandler(logs/clean_hash_feed.log, 10MB, 5)` + `StreamHandler(sys.stdout)`; `sys.exit(main())`

- [ ] **Step 1: Write failing tests**

```python
def test_auth_error_stops_run(self):
    s = FakeSession([resp(401)])
    self.assertEqual(clean_hash_feed.collect(conn, s, URL, "k", NOW, delay=0, sleep=self.sleeps.append), 2)
    self.assertEqual(len(s.calls), 1)

def test_5xx_retries_then_skips(self):
    s = FakeSession([resp(500)] * 4 + [resp(200, EMPTY_XML)] * 800)
    code = clean_hash_feed.collect(conn, s, URL, "k", NOW, delay=0, sleep=self.sleeps.append)
    self.assertEqual(code, 1)
    self.assertEqual(self.sleeps[:3], [2, 4, 8])
    self.assertNotIn(clean_hash_feed.hour_key(FIRST_HOUR), clean_hash_feed.fetched_hour_keys(conn))

def test_retry_after_capped(self):            # Review Focus 4
    s = FakeSession([resp(429, headers={"Retry-After": "3600"}), resp(200, EMPTY_XML)])
    clean_hash_feed.fetch_hour(s, URL, "k", FIRST_HOUR, sleep=self.sleeps.append)
    self.assertEqual(self.sleeps, [60])

def test_request_params_and_header(self):
    s = FakeSession([resp(200, EMPTY_XML)])
    clean_hash_feed.fetch_hour(s, URL, "secret", datetime(2026,10,29,9,tzinfo=timezone.utc), sleep=self.sleeps.append)
    self.assertEqual(s.calls[0]["params"], {"startTime": "2026-10-29T09:00:00.000Z"})
    self.assertEqual(s.calls[0]["headers"]["x-api-key"], "secret")

def test_bad_xml_skips_hour(self):
    s = FakeSession([resp(200, b"<broken")] + [resp(200, EMPTY_XML)] * 800)
    self.assertEqual(clean_hash_feed.collect(conn, s, URL, "k", NOW, delay=0, sleep=self.sleeps.append), 1)

def test_api_key_never_logged(self):
    with self.assertLogs("clean_hash_feed", "DEBUG") as cm:
        clean_hash_feed.collect(conn, FakeSession([resp(401)]), URL, "TOPSECRET", NOW, delay=0, sleep=self.sleeps.append)
    self.assertNotIn("TOPSECRET", "\n".join(cm.output))
```

- [ ] **Step 2: Run** → FAIL
- [ ] **Step 3: Implement** ตาม Interfaces; `collect` ใช้ `plan_hours(now_utc, fetched_hour_keys(conn))`; หน่วง `if delay: sleep(delay)` เฉพาะระหว่าง call (ไม่ก่อน call แรก) — test ข้างบนใช้ `delay=0` จึงเห็นเฉพาะ sleep ของ retry
- [ ] **Step 4: Run** → PASS
- [ ] **Step 5: Smoke** `./clean_hash_feed.py --db /tmp/x.sqlite` โดยไม่มี key ใน env → exit 2 + ข้อความ ERROR (ทำใน scratch dir ไม่ใช่ `.env` จริง: รันด้วย `env -u CLEAN_HASH_API_KEY` และ key ยังไม่ถูกใส่ใน `.env`); `./clean_hash_feed.py --db <db จาก test> --stats` พิมพ์ stats
- [ ] **Step 6: Checkpoint**

---

### Task 4: Checker integration

**Files:**
- Backup: `cp -p misp_warninglist_check.py misp_warninglist_check.py.bak_20261029`
- Modify: `misp_warninglist_check.py` (`TARGET_ATTRIBUTE_TYPES` บรรทัด 61-65, `LocalWarninglistMatcher` 185-384, `process_attributes` 558-561 + SUMMARY 660-684, `parse_args` 733-756, `main` 786-790)
- Test: `tests/test_matcher_clean_hash.py` — `setUp` สร้าง temp `WL_DIR/test-hashes/list.json` = `{"name": "test-hashes", "type": "string", "list": ["c"*64]}` แล้ว patch `wl.WL_DIR`; clean-hash DB ทดสอบสร้างด้วย `clean_hash_feed.init_db` + `store_hour`

**Interfaces:**
- Consumes: `clean_hash_feed.CleanHashStore`, `clean_hash_feed.DEFAULT_DB`, `stats()` keys
- Produces:
  - `CLEAN_HASH_LIST_NAME` (from .env, default `"Clean hash feed"`)
  - `format_clean_hash_hit(row: dict) -> str` → `"clean-hash feed (file=a.dll, size=1234, released=2026-10-14)"` (`|`→`/`, filename ≤ 80 ตัว, released = 10 ตัวแรกของ `release_date`)
  - `LocalWarninglistMatcher(enabled_names, exclude_keywords, clean_hash=None)`, attribute `clean_hash_hits: int`
  - `LocalWarninglistMatcher.match(value: str, attr_type: str = "") -> list[str]`
  - `open_clean_hash(path=clean_hash_feed.DEFAULT_DB) -> CleanHashStore | None`
  - CLI `--clean-hash-db`, `--no-clean-hash`

- [ ] **Step 1: Write failing tests**

```python
def test_clean_hash_hit_format(self):
    m = wl.LocalWarninglistMatcher(set(), [], clean_hash=self.store)       # store มี "a"*64, a.dll, 1234, 2026-10-14T17:00:00
    self.assertEqual(m.match("a"*64, "sha256"), ["clean-hash feed (file=a.dll, size=1234, released=2026-10-14)"])
    self.assertEqual(m.clean_hash_hits, 1)

def test_composite_matches_hash_part(self):                         # + Review Focus 2
    m = wl.LocalWarninglistMatcher(set(), [], clean_hash=self.store)
    self.assertEqual(m.match("evil.exe|" + "C"*64, "filename|sha256"), ["test-hashes"])
    self.assertTrue(m.match("x.dll| " + "A"*64, "filename|sha256")[0].startswith("clean-hash feed"))

def test_pipe_in_filename_sanitized_and_strippable(self):
    hit = wl.format_clean_hash_hit({"filename": "a|b.dll" + "x"*100, "size": 1, "release_date": "2026-10-14T00:00:00"})
    self.assertNotIn("|", hit)
    comment = f"orig | [Auto] IDS disabled by warninglist checker. Matched: test-hashes, {hit}"
    self.assertEqual(reenable._DISABLED_NOTE.sub("", comment).strip(), "orig")

def test_no_clean_hash_unchanged(self):
    m = wl.LocalWarninglistMatcher(set(), [])
    self.assertEqual(m.match("a"*64, "sha256"), [])
    self.assertEqual(m.match("c"*64, "sha256"), ["test-hashes"])

def test_target_types(self):
    self.assertIn("filename|sha256", wl.TARGET_ATTRIBUTE_TYPES)

def test_open_clean_hash_missing(self):
    with self.assertLogs("misp_wl_check", "WARNING"):
        self.assertIsNone(wl.open_clean_hash(Path(self.tmp) / "nope.sqlite"))

def test_open_clean_hash_empty_db_warns_stale(self):                      # Review Focus 1
    clean_hash_feed.init_db(self.empty_db).close()
    with self.assertLogs("misp_wl_check", "WARNING") as cm:
        self.assertIsNotNone(wl.open_clean_hash(self.empty_db))
    self.assertIn("stale", "\n".join(cm.output))
```

(`reenable` = `import misp_wl_reenable as reenable`; หลัง import ให้ clear handlers ของ logger อีกครั้ง เพราะ reenable ผูก FileHandler ใหม่)

- [ ] **Step 2: Run** `... -m unittest tests.test_matcher_clean_hash -v` → FAIL
- [ ] **Step 3: Implement**
  - `match()`: ขั้นแรกถ้า `attr_type.startswith("filename|")` → `value = value.rsplit("|", 1)[-1].strip()`; ขั้น 6 หลัง regex: `self._clean_hash and _SHA256.match(val_lower)` → lookup
  - `open_clean_hash()`: log `clean-hash store: {files:,} hashes, newest release …, last fetch …`; stale เมื่อ `last_fetched_at` เป็น `None` หรือเก่ากว่า 24 ชม.
  - `process_attributes`: `matcher.match(value, <type ของ attr แรกใน value_to_attrs[value]>)`; SUMMARY `clean-hash-matched values: N` เมื่อ `matcher._clean_hash` ไม่ใช่ `None`
  - `main`: `clean_hash = None if args.no_clean_hash else open_clean_hash(args.clean_hash_db)` แล้วส่งเข้า matcher
  - Docstring ต้นไฟล์: เพิ่มบรรทัดอธิบาย clean-hash และตัวอย่าง `--no-clean-hash`
- [ ] **Step 4: Run** → PASS
- [ ] **Step 5: Smoke** `./misp_warninglist_check.py --help` แสดง `--clean-hash-db`, `--no-clean-hash`
- [ ] **Step 6: Checkpoint**

---

### Task 5: Re-enable integration

**Files:**
- Backup: `cp -p misp_wl_reenable.py misp_wl_reenable.py.bak_20261029`
- Modify: `misp_wl_reenable.py` (`load_report_candidates` บรรทัด 75-76, `main` 113-116 และ 133)
- Test: `tests/test_matcher_clean_hash.py` (class `ReenableTests`)

**Interfaces:**
- Consumes: `wl.open_clean_hash()`, `match(value, attr_type)` จาก Task 4

- [ ] **Step 1: Write failing test** — เขียน CSV ชั่วคราวใน temp dir (patch `wl.SCRIPT_DIR`) ชื่อ `misp_wl_report_20261029_000000.csv` มี 3 แถว action `SET to_ids=False`: `uuid-a` type `sha256` = `"a"*64` (อยู่ใน clean-hash), `uuid-c` type `filename|sha256` = `"x.dll|" + "c"*64` (ตรง test-hashes), `uuid-d` type `sha256` = `"d"*64` (ไม่ตรงอะไร)

```python
def test_only_unmatched_rows_are_candidates(self):
    m = wl.LocalWarninglistMatcher(set(), [], clean_hash=self.store)
    self.assertEqual(set(reenable.load_report_candidates(m)), {"uuid-d"})
```

- [ ] **Step 2: Run** → FAIL (แถว composite กลายเป็น candidate)
- [ ] **Step 3: Implement** — ส่ง `r.get("attribute_type", "")` / `a.get("type", "")` เข้า `match()`; สร้าง matcher ด้วย `clean_hash=wl.open_clean_hash()`
- [ ] **Step 4: Run** test ทั้งชุด → PASS
- [ ] **Step 5: Checkpoint**

---

### Task 6: Rollout (ทำร่วมกับผู้ใช้ — ห้ามแตะ MISP ด้วย `--commit` ก่อนผู้ใช้อนุมัติ)

- [ ] **Step 1:** ผู้ใช้เพิ่ม `CLEAN_HASH_API_KEY=...` ใน `/var/www/MISP/thaicert/.env`
- [ ] **Step 2:** `./clean_hash_feed.py` (backfill) — รันในฐานะ `piyawut` เท่านั้น ห้าม sudo (ไม่งั้น `data/` เป็นของ root และ cron อ่านไม่ได้) → exit 0; จด per-hour file count, เวลาที่ใช้, มี 429 หรือไม่ จาก `logs/clean_hash_feed.log`
- [ ] **Step 3:** `./clean_hash_feed.py --stats` → `files > 0`, `hours_fetched ≈ 719`; สุ่ม 3 hash จาก DB ตรวจว่าเป็นไฟล์ vendor จริง
- [ ] **Step 4:** `./misp_warninglist_check.py` (dry-run, ไม่ใส่ `--days`) ช่วงโหลดน้อย → นับแถว CSV ที่มี `clean-hash feed` และแถว `filename|sha256`; ส่งสรุปให้ผู้ใช้ตัดสิน
- [ ] **Step 5 (หลังผู้ใช้อนุมัติ):** `./misp_warninglist_check.py --commit` หนึ่งครั้ง แล้วเพิ่ม cron:
  `20 * * * * cd /var/www/MISP/thaicert && flock -n /tmp/clean_hash_feed.lock ./clean_hash_feed.py >/dev/null 2>> /var/www/MISP/thaicert/logs/clean_hash_feed.err`
- [ ] **Step 6:** วันถัดไปตรวจ `logs/misp_warninglist_check.log` ว่ามีบรรทัด `clean-hash store:` และไม่มี stale warning
