# Clean-file hash feed Enrichment — Design Spec

- วันที่: 2026-10-29
- สถานะ: รอ review
- ขอบเขต: `misp_warninglist_check.py`, `misp_wl_reenable.py`, สคริปต์ใหม่ `clean_hash_feed.py`

---

## 1. เป้าหมาย

ใช้ feed **Clean File Metadata (clean-hash)** จาก a vendor ซึ่งให้ sha256 / size / filename ของไฟล์ vendor ที่ clean
เป็นแหล่งข้อมูลเพิ่มเติมให้ `misp_warninglist_check.py` ใช้ตัด false positive:
attribute ที่ hash ตรงกับ clean-hash จะถูกตั้ง `to_ids=False` เหมือนกรณีตรง warninglist โดย attribute ยังอยู่ใน event เป็น context
(เหมาะกับกรณี binary ของ vendor ที่ถูกใช้ใน DLL side-loading ซึ่งไม่ควร block ด้วย hash)

### เกณฑ์ความสำเร็จ

1. Collector เก็บ clean-hash สะสมลงเครื่องได้ต่อเนื่อง (ข้อมูลเกิน 30 วันไม่หาย) และเติมช่องว่างเองเมื่อหยุดไปไม่เกิน 30 วัน
2. Checker ตัด attribute `sha256` และ `filename|sha256` (`to_ids=True`) ที่ hash อยู่ใน clean-hash พร้อมระบุรายละเอียดไฟล์ใน comment
3. Re-enable script ไม่เปิด IDS คืนให้ attribute ที่ถูกตัดเพราะ clean-hash
4. Daily cron ของ checker ไม่ล้มเพราะ clean-hash (ไม่มี DB / DB เก่า → เตือนแล้วรันต่อ)
5. ไม่เพิ่มการใช้ RAM อย่างมีนัยสำคัญ (เครื่องเคย OOM เมื่อ 2026-10-09)

### นอกขอบเขต

- ทำ clean-hash เป็น warninglist ใน MISP UI
- `filename|md5`, `filename|sha1` (clean-hash มีแค่ sha256; ขยายภายหลังได้)
- Reverse lookup: เอา hash ใหม่จาก clean-hash ไปค้น attribute เก่าใน MISP
- แก้ permission ของ `misp_warninglist_check.ini` (แนะนำแยก: ตอนนี้ `644` และมี MISP API key แบบ plain text)

---

## 2. แหล่งข้อมูล: clean-hash feed API

- `GET ?startTime=YYYY-mm-ddThh:00:00.000Z`
- Header `x-api-key: <key>`
- 1 call = ข้อมูล 1 ชั่วโมงนับจาก `startTime` (UTC)
- เก็บย้อนหลังได้แค่ 30 วัน
- Response 200 = XML namespace `http://xml/metadataSharing.xsd`:
  `releaseMetaData/releases/release/{releasedate, objects/file/{sha256, size, filename}}`

**สมมติฐานที่ยังไม่ได้ยืนยัน** (ตรวจตอน backfill ครั้งแรก): ปริมาณไฟล์ต่อชั่วโมง, rate limit, และ vendor เติมข้อมูลย้อนหลังให้ชั่วโมงที่ผ่านไปแล้วหรือไม่

---

## 3. ภาพรวมสถาปัตยกรรม

```
cron :20 ทุกชั่วโมง                       cron 19:00 ทุกวัน (เดิม)
        │                                          │
  clean_hash_feed.py ──GET──▶ vendor API          misp_warninglist_check.py
        │                                          │  LocalWarninglistMatcher
        ▼ write (WAL)                              │   1-5 warninglists (เดิม)
  data/clean_hash_feed.sqlite ◀──read-only lookup────────┤   6   clean-hash lookup (ใหม่)
                         ◀──read-only lookup── misp_wl_reenable.py
```

---

## 4. Components

### 4.1 `clean_hash_feed.py` (ใหม่) — collector + `CleanHashStore`

ไฟล์เดียว รันเป็นสคริปต์ได้ (collector) และ import ได้ (`CleanHashStore`). Shebang `#!/var/www/MISP/venv/bin/python3`, ใช้แค่ `requests` + standard library

**Config** (อ่านจาก `/var/www/MISP/thaicert/.env` ด้วย `load_env` แบบเดียวกับ `misp_ioc_retirement.py`):

| ตัวแปร | Default | หมายเหตุ |
|---|---|---|
| `CLEAN_HASH_API_KEY` | — | จำเป็น; ไม่มี → ERROR, exit 2 |
| `CLEAN_HASH_URL` | (required) | |
| `CLEAN_HASH_DELAY_SECONDS` | `0.5` | หน่วงระหว่าง call (สำคัญตอน backfill) |

**ค่าคงที่**: `DEFAULT_DB = /var/www/MISP/thaicert/data/clean_hash_feed.sqlite`, `RETENTION_DAYS = 30`, `REFETCH_RECENT_HOURS = 3`

**Data model** (SQLite, `PRAGMA journal_mode=WAL`, โฟลเดอร์ `data/` = `750`, ไฟล์ DB = `640`):

```sql
CREATE TABLE IF NOT EXISTS files (
    sha256       TEXT PRIMARY KEY,   -- 64 hex ตัวเล็ก
    size         INTEGER,            -- NULL ถ้า parse ไม่ได้
    filename     TEXT,
    release_date TEXT,               -- ตามที่ vendor ให้ (YYYY-mm-ddThh:mm:ss)
    first_seen   TEXT NOT NULL       -- UTC ISO เวลาที่เก็บได้ครั้งแรก
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS fetched_hours (
    start_time TEXT PRIMARY KEY,     -- YYYY-mm-ddThh:00:00Z
    fetched_at TEXT NOT NULL,        -- UTC ISO
    file_count INTEGER NOT NULL
);
```

sha256 ซ้ำ → `INSERT OR IGNORE` (เก็บ record แรก). เก็บถาวร ไม่มี prune

**การเลือกชั่วโมงที่จะดึง** — `plan_hours(now_utc, fetched: set) -> list[datetime]`:

- `latest   = floor_hour(now_utc) - 1h` (ชั่วโมงล่าสุดที่ครบแล้ว)
- `earliest = floor_hour(now_utc - 30d) + 1h` (กันขอบ 30 วัน)
- ผลลัพธ์ = ทุกชั่วโมงใน `[earliest, latest]` ที่ไม่อยู่ใน `fetched` ∪ `{latest-2h, latest-1h, latest}` เรียงจากเก่าไปใหม่
- รันครั้งแรก ≈ 720 call; รันปกติ ≈ 4 call

**ต่อชั่วโมง**:

1. GET พร้อม header, timeout (connect 10s, read 120s)
2. Parse XML แบบ streaming (`xml.etree.ElementTree.iterparse`) เทียบ tag ด้วย local name (ตัด namespace) เพื่อทนกรณี namespace เปลี่ยน
3. sha256 → `strip().lower()` ต้องตรง `^[0-9a-f]{64}$` ไม่ตรง → ข้ามและนับใน log
4. Insert `files` + upsert `fetched_hours` ใน **transaction เดียว** — ถ้าล้มกลางทาง ชั่วโมงนั้นจะไม่ถูกบันทึกและถูกดึงใหม่รอบหน้า

**Error handling**:

| กรณี | การจัดการ |
|---|---|
| 401 / 403 | ERROR "API key invalid", หยุดทั้งรอบ, exit 2 |
| 429 / 5xx / timeout / connection error | retry 3 ครั้ง backoff 2s/4s/8s (429 ใช้ `Retry-After` ถ้ามี) แล้วข้ามชั่วโมงนั้น |
| 4xx อื่น | ERROR แล้วข้ามชั่วโมงนั้น |
| XML parse error | ERROR แล้วข้ามชั่วโมงนั้น |
| 200 ไม่มี `<file>` | บันทึกชั่วโมงนั้น `file_count = 0` |

Exit code: `0` ครบทุกชั่วโมง, `1` มีบางชั่วโมงถูกข้าม, `2` auth/config error

**CLI**: `./clean_hash_feed.py` (collect), `./clean_hash_feed.py --stats` (พิมพ์ stats แล้วจบ), `--db PATH`

**Logging**: ห้าม log API key (รวมถึงใน exception/header dump); format เดียวกับ checker, `RotatingFileHandler` ที่ `logs/clean_hash_feed.log` (10 MB × 5) + console ไป stdout. สรุปท้ายรอบ: จำนวนชั่วโมงที่ดึง/ข้าม, ไฟล์ใหม่, ไฟล์ซ้ำ, sha256 ไม่ถูกต้อง, เวลาที่ใช้

**`CleanHashStore`** (ใช้โดย checker และ re-enable):

- `CleanHashStore(path)` — เปิด `file:{path}?mode=ro` (uri) ถ้าไม่มีไฟล์ → `FileNotFoundError`
- `lookup(sha256: str) -> dict | None` — keys: `sha256, size, filename, release_date`
- `stats() -> dict` — `files`, `newest_release`, `last_fetched_at`, `hours_fetched`

### 4.2 `misp_warninglist_check.py` (แก้)

- `TARGET_ATTRIBUTE_TYPES` เพิ่ม `"filename|sha256"`
  - ผลข้างเคียงที่ยอมรับแล้ว: warninglist hash เดิม (`windows-binary-hashes`, `nioc-filehash`, `ti-falsepositives` ฯลฯ) จะครอบคลุม `filename|sha256` ด้วย
- ค่าคงที่ใหม่: `CLEAN_HASH_LIST_NAME = "clean-hash feed"`, `_SHA256 = re.compile(r"^[0-9a-f]{64}$")`
- `LocalWarninglistMatcher.__init__(enabled_names, exclude_keywords, clean_hash=None)` เก็บ `self._clean_hash`, เพิ่ม counter `self.clean_hash_hits = 0`
- `match(value, attr_type="")`:
  1. ถ้า `attr_type.startswith("filename|")` → `value = value.rsplit("|", 1)[-1].strip()` แล้วใช้ค่านี้กับทุกขั้น
  2. ขั้น 1-5 เดิมไม่เปลี่ยน
  3. ขั้น 6 (ใหม่): ถ้ามี `self._clean_hash` และ `val_lower` ตรง `_SHA256` → `lookup()` ถ้าเจอ append ชื่อ hit และ `clean_hash_hits += 1`
- รูปแบบชื่อ hit: `clean-hash feed (file=<filename>, size=<size>, released=<YYYY-mm-dd>)`
  - filename แทน `|` ด้วย `/` และตัดที่ 80 ตัวอักษร — ต้องไม่มี `|` เพราะ `_DISABLED_NOTE` ใน `misp_wl_reenable.py` ใช้ `[^|]*?` ตัด comment
  - ชื่อนี้ไหลเข้า `matched_warninglists` ใน CSV และ comment `[Auto] IDS disabled by warninglist checker. Matched: ...` ตามเดิม ไม่เปลี่ยน format
- ฟังก์ชันใหม่ `open_clean_hash(path=clean_hash_feed.DEFAULT_DB) -> CleanHashStore | None` (re-enable ใช้ร่วม):
  - ไม่มีไฟล์ → WARNING "clean-hash store not found — continuing without clean-hash" คืน `None`
  - มี → log stats; ถ้า `last_fetched_at` เป็น `None` (DB ว่าง) หรือเก่ากว่า 24 ชม. → WARNING "clean-hash store is stale — check clean_hash_feed.py cron" (ยังใช้ store ต่อ)
- `--exclude-keywords` ไม่มีผลกับ clean-hash; ปิด clean-hash ใช้ `--no-clean-hash`
- `process_attributes`: เรียก `matcher.match(value, attr_type)` โดย `attr_type` = type ของ attribute ตัวแรกใน `value_to_attrs[value]`
  (ค่า `sha256` กับ `filename|sha256` ไม่มีทางเป็น string เดียวกัน เพราะอย่างหลังมี `|`)
- SUMMARY เพิ่มบรรทัด `clean-hash-matched values: N` (ค่า `clean_hash_hits`) เมื่อเปิด clean-hash
- CLI ใหม่: `--clean-hash-db PATH` (default `clean_hash_feed.DEFAULT_DB`), `--no-clean-hash`

### 4.3 `misp_wl_reenable.py` (แก้)

- สร้าง matcher ด้วย `clean_hash=wl.open_clean_hash()` → hit จาก clean-hash นับเป็น "keep disabled: still matched"
- ส่ง type ให้ `match()` ทั้งสองจุด:
  - `load_report_candidates`: `matcher.match(value, r.get("attribute_type", ""))`
  - main loop: `matcher.match(value, a.get("type", ""))`

---

## 5. ผลต่อทรัพยากร

- RAM: ไม่โหลด hash เข้า memory; lookup เป็น primary-key read ทีละค่า (~สิบ µs) เฉพาะค่าที่เป็น sha256
- Disk: ประมาณ 150 bytes/row → 10 ล้าน row ≈ 1.5 GB (ว่าง 1.4 TB)
- MISP: ไม่เพิ่ม API call ฝั่ง MISP นอกจากการ update attribute ที่ match เพิ่ม

---

## 6. Testing

ใช้ `unittest` (MISP venv ไม่มี pytest และไม่ติดตั้งเพิ่มใน production venv)

```bash
cd /var/www/MISP/thaicert && /var/www/MISP/venv/bin/python3 -m unittest discover -s tests -t .
```

- Test ต้องปิด handler ของ logger `misp_wl_check` (กันเขียนลง production log) และชี้ `WL_DIR` ไป temp dir ที่มี `list.json` ตัวอย่าง
- `tests/test_clean_hash_feed.py`
  - Parse XML ตัวอย่างจากเอกสาร vendor (namespace, `<company>` ซ้ำ) ได้ record ถูกต้อง; sha256 ผิดรูปถูกข้าม; ตัวใหญ่ → ตัวเล็ก
  - `plan_hours`: ไม่รวมชั่วโมงปัจจุบัน, ไม่เกิน 30 วัน, ข้ามชั่วโมงที่ดึงแล้ว, มี 3 ชั่วโมงล่าสุดเสมอ, เรียงเก่า→ใหม่
  - Store: sha256 ซ้ำเก็บ record แรก; error กลาง transaction → ชั่วโมงนั้นไม่ถูกบันทึก
  - HTTP (fake session): 401 หยุดรอบ exit 2; 500 retry แล้วข้าม; 200 ว่างบันทึก 0
  - `CleanHashStore`: ไม่มีไฟล์ → `FileNotFoundError`; `lookup` เจอ/ไม่เจอ; เปิดแบบ read-only (เขียนไม่ได้)
- `tests/test_matcher_clean_hash.py`
  - sha256 ใน clean-hash → hit มีรายละเอียดตาม format
  - `filename|sha256` match hash ส่วนท้ายกับทั้ง warninglist ตัวอย่างและ clean-hash
  - filename ที่มี `|` ถูกแทนเป็น `/`; comment ที่สร้างผ่าน `_DISABLED_NOTE` ของ re-enable ตัดออกได้หมด
  - `clean_hash=None` → ผลเหมือนเดิมทุกกรณี
  - `open_clean_hash`: ไม่มีไฟล์ → `None`; ข้อมูลเก่ากว่า 24 ชม. → WARNING
- ทดสอบจริงหลังใส่ key: รัน collector, `--stats`, สุ่มตรวจ hash

---

## 7. Rollout

1. Backup `misp_warninglist_check.py`, `misp_wl_reenable.py` เป็น `.bak_20261029` (ตาม convention เดิม — ไม่มี git)
2. ผู้ใช้เพิ่ม `CLEAN_HASH_API_KEY=...` ใน `/var/www/MISP/thaicert/.env` (ไฟล์นี้ `600` อยู่แล้ว)
3. รัน `./clean_hash_feed.py` ด้วยมือ (backfill 30 วัน) แล้ว `./clean_hash_feed.py --stats` — ดูปริมาณต่อชั่วโมง/rate limit จาก log
4. วัดผลก่อนแตะ MISP: `./misp_warninglist_check.py` (dry-run, ไม่ใส่ `--days`) ช่วงเวลาที่โหลดน้อย → review CSV ร่วมกัน
5. ถ้าผลโอเค: `./misp_warninglist_check.py --commit` (full) หนึ่งครั้งเพื่อ catch-up แล้วเพิ่ม cron:

   ```
   # clean-hash feed collector - every hour at :20
   20 * * * * cd /var/www/MISP/thaicert && flock -n /tmp/clean_hash_feed.lock ./clean_hash_feed.py >/dev/null 2>> /var/www/MISP/thaicert/logs/clean_hash_feed.err
   ```

   Cron ของ checker รายวันไม่ต้องแก้ (ใช้ `--clean-hash-db` default)

---

## 8. ข้อจำกัดที่รู้แล้ว

- Attribute ที่เข้า MISP ก่อน vendor เผยแพร่ metadata จะไม่ถูกตรวจซ้ำโดย daily run (`--days 1`)
  - คาดว่าเกิดน้อย ถ้าเจอจริงเพิ่ม weekly `--days 7` ได้
- ไฟล์ vendor ที่ออกก่อนเริ่มเก็บเกิน 30 วันจะไม่มีใน clean-hash — ส่วนนี้พึ่ง `windows-binary-hashes` เดิม
- จาก CSV report ทั้งหมดตั้งแต่ ก.ค. 2026 มี hash ถูกตัดแค่ 8 แถว (SHA1 ของ empty file ทั้งหมด)
  - ประโยชน์จริงของ clean-hash ต้องดูจากขั้นที่ 4 ของ Rollout
