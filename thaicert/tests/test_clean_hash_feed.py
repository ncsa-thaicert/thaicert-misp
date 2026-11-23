import logging
import sqlite3
import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import clean_hash_feed


def setUpModule():
    lg = logging.getLogger("clean_hash_feed")
    lg.handlers.clear()
    lg.addHandler(logging.NullHandler())


SAMPLE = b"""<releaseMetaData xmlns="http://xml/metadataSharing.xsd"><company>Example Corp.</company><company>Example Corp.</company>
<releases><release><releasedate>2026-10-14T17:00:00</releasedate><objects>
<file><sha256>""" + b"A" * 64 + b"""</sha256><size>1234</size><filename>a.dll</filename></file>
<file><sha256>nothex</sha256><size>1</size><filename>b.dll</filename></file></objects></release>
<release><releasedate>2026-10-14T18:00:00</releasedate><objects>
<file><sha256> """ + b"b" * 64 + b""" </sha256><size>x</size></file></objects></release></releases></releaseMetaData>"""

EMPTY_XML = b'<releaseMetaData xmlns="http://xml/metadataSharing.xsd"><releases/></releaseMetaData>'
URL = "https://example.invalid/CleanHashFeed"
NOW = datetime(2026, 10, 29, 10, 20, tzinfo=timezone.utc)
FIRST_HOUR = datetime(2026, 9, 29, 11, tzinfo=timezone.utc)
H = datetime(2026, 10, 29, 8, tzinfo=timezone.utc)
H2 = datetime(2026, 10, 29, 9, tzinfo=timezone.utc)


def rec(sha256, filename="f.dll"):
    return {"sha256": sha256, "size": 1, "filename": filename, "release_date": "2026-10-14T17:00:00"}


class ParseTests(unittest.TestCase):
    def test_parse_sample(self):
        recs, bad = clean_hash_feed.parse_feed_xml(SAMPLE)
        self.assertEqual(bad, 1)
        self.assertEqual(recs[0], {"sha256": "a" * 64, "size": 1234, "filename": "a.dll",
                                   "release_date": "2026-10-14T17:00:00"})
        self.assertEqual(recs[1], {"sha256": "b" * 64, "size": None, "filename": "",
                                   "release_date": "2026-10-14T18:00:00"})

    def test_parse_empty_releases(self):
        self.assertEqual(clean_hash_feed.parse_feed_xml(EMPTY_XML), ([], 0))

    def test_parse_broken_xml_raises(self):
        with self.assertRaises(ET.ParseError):
            clean_hash_feed.parse_feed_xml(b"<releaseMetaData><releases>")


class PlanTests(unittest.TestCase):
    def test_formats(self):
        t = datetime(2026, 10, 29, 9, 0, tzinfo=timezone.utc)
        self.assertEqual(clean_hash_feed.hour_key(t), "2026-10-29T09:00:00Z")
        self.assertEqual(clean_hash_feed.start_time_param(t), "2026-10-29T09:00:00.000Z")

    def test_plan_first_run(self):
        hours = clean_hash_feed.plan_hours(NOW, set())
        self.assertEqual(hours[-1], datetime(2026, 10, 29, 9, tzinfo=timezone.utc))
        self.assertEqual(hours[0], FIRST_HOUR)
        self.assertEqual(len(hours), 719)
        self.assertEqual(hours, sorted(hours))

    def test_plan_skips_fetched_but_refetches_last_3(self):
        fetched = {clean_hash_feed.hour_key(h) for h in clean_hash_feed.plan_hours(NOW, set())}
        self.assertEqual(clean_hash_feed.plan_hours(NOW, fetched),
                         [datetime(2026, 10, 29, h, tzinfo=timezone.utc) for h in (7, 8, 9)])


class StoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.db = Path(self.tmp) / "data" / "clean_hash.sqlite"
        self.conn = clean_hash_feed.init_db(self.db)

    def tearDown(self):
        self.conn.close()
        self._tmp.cleanup()

    def test_store_dedup_keeps_first(self):
        n, d = clean_hash_feed.store_hour(self.conn, H, [rec("a" * 64, "first.dll")])
        n2, d2 = clean_hash_feed.store_hour(self.conn, H2, [rec("a" * 64, "second.dll")])
        self.assertEqual((n, d, n2, d2), (1, 0, 0, 1))
        self.assertEqual(clean_hash_feed.CleanHashStore(self.db).lookup("a" * 64)["filename"], "first.dll")
        self.assertEqual(clean_hash_feed.fetched_hour_keys(self.conn),
                         {clean_hash_feed.hour_key(H), clean_hash_feed.hour_key(H2)})

    def test_store_hour_atomic(self):
        with self.assertRaises(Exception):
            clean_hash_feed.store_hour(self.conn, H, [rec("a" * 64), {"sha256": None}])
        self.assertEqual(clean_hash_feed.fetched_hour_keys(self.conn), set())
        self.assertIsNone(clean_hash_feed.CleanHashStore(self.db).lookup("a" * 64))

    def test_empty_hour_recorded(self):
        clean_hash_feed.store_hour(self.conn, H, [])
        self.assertEqual(clean_hash_feed.CleanHashStore(self.db).stats()["hours_fetched"], 1)

    def test_store_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            clean_hash_feed.CleanHashStore(Path(self.tmp) / "nope.sqlite")

    def test_store_is_readonly(self):
        s = clean_hash_feed.CleanHashStore(self.db)
        with self.assertRaises(sqlite3.OperationalError):
            s._conn.execute("DELETE FROM files")

    def test_stats_empty_db(self):
        self.assertIsNone(clean_hash_feed.CleanHashStore(self.db).stats()["last_fetched_at"])

    def test_stats_values(self):
        clean_hash_feed.store_hour(self.conn, H, [rec("a" * 64)])
        st = clean_hash_feed.CleanHashStore(self.db).stats()
        self.assertEqual((st["files"], st["newest_release"], st["hours_fetched"]),
                         (1, "2026-10-14T17:00:00", 1))
        self.assertIsNotNone(st["last_fetched_at"])

    def test_read_during_open_write_tx(self):
        clean_hash_feed.store_hour(self.conn, H, [rec("a" * 64)])
        self.conn.execute("BEGIN IMMEDIATE")
        self.conn.execute("INSERT INTO files VALUES (?,?,?,?,?)", ("b" * 64, 1, "x", "", "now"))
        s = clean_hash_feed.CleanHashStore(self.db)
        self.assertIsNotNone(s.lookup("a" * 64))
        self.assertIsNone(s.lookup("b" * 64))
        self.conn.rollback()


class Resp:
    def __init__(self, status, content=b"", headers=None):
        self.status_code = status
        self.content = content
        self.headers = headers or {}


def resp(status, content=EMPTY_XML, headers=None):
    return Resp(status, content, headers)


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"url": url, "params": params, "headers": headers, "timeout": timeout})
        return self.responses.pop(0)


class CollectTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.conn = clean_hash_feed.init_db(Path(self._tmp.name) / "clean_hash.sqlite")
        self.sleeps = []

    def tearDown(self):
        self.conn.close()
        self._tmp.cleanup()

    def test_auth_error_stops_run(self):
        s = FakeSession([resp(401)])
        self.assertEqual(clean_hash_feed.collect(self.conn, s, URL, "k", NOW, delay=0, sleep=self.sleeps.append), 2)
        self.assertEqual(len(s.calls), 1)

    def test_5xx_retries_then_skips(self):
        s = FakeSession([resp(500)] * 4 + [resp(200)] * 800)
        code = clean_hash_feed.collect(self.conn, s, URL, "k", NOW, delay=0, sleep=self.sleeps.append)
        self.assertEqual(code, 1)
        self.assertEqual(self.sleeps[:3], [2, 4, 8])
        keys = clean_hash_feed.fetched_hour_keys(self.conn)
        self.assertNotIn(clean_hash_feed.hour_key(FIRST_HOUR), keys)
        self.assertEqual(len(keys), 718)

    def test_success_stores_and_returns_0(self):
        s = FakeSession([resp(200, SAMPLE)] + [resp(200)] * 800)
        self.assertEqual(clean_hash_feed.collect(self.conn, s, URL, "k", NOW, delay=0, sleep=self.sleeps.append), 0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM files").fetchone()[0], 2)

    def test_retry_after_capped(self):
        s = FakeSession([resp(429, headers={"Retry-After": "3600"}), resp(200)])
        clean_hash_feed.fetch_hour(s, URL, "k", FIRST_HOUR, sleep=self.sleeps.append)
        self.assertEqual(self.sleeps, [60])

    def test_request_params_and_header(self):
        s = FakeSession([resp(200)])
        clean_hash_feed.fetch_hour(s, URL, "secret", datetime(2026, 10, 29, 9, tzinfo=timezone.utc),
                             sleep=self.sleeps.append)
        self.assertEqual(s.calls[0]["params"], {"startTime": "2026-10-29T09:00:00.000Z"})
        self.assertEqual(s.calls[0]["headers"]["x-api-key"], "secret")
        self.assertEqual(s.calls[0]["timeout"], (10, 120))

    def test_other_4xx_no_retry(self):
        s = FakeSession([resp(404)])
        with self.assertRaises(clean_hash_feed.FetchError):
            clean_hash_feed.fetch_hour(s, URL, "k", FIRST_HOUR, sleep=self.sleeps.append)
        self.assertEqual((len(s.calls), self.sleeps), (1, []))

    def test_bad_xml_skips_hour(self):
        s = FakeSession([resp(200, b"<broken")] + [resp(200)] * 800)
        self.assertEqual(clean_hash_feed.collect(self.conn, s, URL, "k", NOW, delay=0, sleep=self.sleeps.append), 1)

    def test_api_key_never_logged(self):
        with self.assertLogs("clean_hash_feed", "DEBUG") as cm:
            clean_hash_feed.collect(self.conn, FakeSession([resp(401)]), URL, "TOPSECRET", NOW,
                              delay=0, sleep=self.sleeps.append)
        self.assertNotIn("TOPSECRET", "\n".join(cm.output))


if __name__ == "__main__":
    unittest.main()
