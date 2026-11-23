import csv
import json
import logging
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import misp_warninglist_check as wl
import misp_wl_reenable as reenable
import clean_hash_feed


def _quiet(name):
    lg = logging.getLogger(name)
    lg.handlers.clear()
    lg.addHandler(logging.NullHandler())


def setUpModule():
    # importing the scripts attaches production log files; never write to them from tests
    for name in ("misp_wl_check", "clean_hash_feed"):
        _quiet(name)


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        wl_dir = self.tmp / "lists" / "test-hashes"
        wl_dir.mkdir(parents=True)
        (wl_dir / "list.json").write_text(json.dumps(
            {"name": "test-hashes", "type": "string", "list": ["c" * 64]}))
        p = mock.patch.object(wl, "WL_DIR", self.tmp / "lists")
        p.start()
        self.addCleanup(p.stop)

        self.db = self.tmp / "clean_hash.sqlite"
        conn = clean_hash_feed.init_db(self.db)
        clean_hash_feed.store_hour(conn, datetime(2026, 10, 29, 8, tzinfo=timezone.utc), [
            {"sha256": "a" * 64, "size": 1234, "filename": "a.dll", "release_date": "2026-10-14T17:00:00"}])
        conn.close()
        self.store = clean_hash_feed.CleanHashStore(self.db)
        self.empty_db = self.tmp / "empty.sqlite"

    def tearDown(self):
        self.store.close()
        self._tmp.cleanup()


class MatcherTests(Base):
    def test_clean_hash_hit_format(self):
        m = wl.LocalWarninglistMatcher(set(), [], clean_hash=self.store)
        self.assertEqual(m.match("a" * 64, "sha256"),
                         [f"{wl.CLEAN_HASH_LIST_NAME} (file=a.dll, size=1234, released=2026-10-14)"])
        self.assertEqual(m.clean_hash_hits, 1)

    def test_composite_matches_hash_part(self):
        m = wl.LocalWarninglistMatcher(set(), [], clean_hash=self.store)
        self.assertEqual(m.match("evil.exe|" + "C" * 64, "filename|sha256"), ["test-hashes"])
        self.assertTrue(m.match("x.dll| " + "A" * 64, "filename|sha256")[0].startswith(wl.CLEAN_HASH_LIST_NAME))

    def test_uppercase_sha256_matches_clean_hash(self):
        m = wl.LocalWarninglistMatcher(set(), [], clean_hash=self.store)
        self.assertEqual(len(m.match("A" * 64, "sha256")), 1)

    def test_pipe_in_filename_sanitized_and_strippable(self):
        hit = wl.format_clean_hash_hit({"filename": "a|b.dll" + "x" * 100, "size": 1,
                                  "release_date": "2026-10-14T00:00:00"})
        self.assertNotIn("|", hit)
        self.assertIn("file=a/b.dll" + "x" * 73 + ",", hit)       # filename cut at 80 chars
        comment = f"orig | [Auto] IDS disabled by warninglist checker. Matched: test-hashes, {hit}"
        self.assertEqual(reenable._DISABLED_NOTE.sub("", comment).strip(), "orig")

    def test_no_clean_hash_unchanged(self):
        m = wl.LocalWarninglistMatcher(set(), [])
        self.assertEqual(m.match("a" * 64, "sha256"), [])
        self.assertEqual(m.match("c" * 64, "sha256"), ["test-hashes"])
        self.assertEqual(m.match("c" * 64), ["test-hashes"])

    def test_target_types(self):
        self.assertIn("filename|sha256", wl.TARGET_ATTRIBUTE_TYPES)

    def test_open_clean_hash_missing(self):
        with self.assertLogs("misp_wl_check", "WARNING"):
            self.assertIsNone(wl.open_clean_hash(self.tmp / "nope.sqlite"))

    def test_open_clean_hash_empty_db_warns_stale(self):
        clean_hash_feed.init_db(self.empty_db).close()
        with self.assertLogs("misp_wl_check", "WARNING") as cm:
            store = wl.open_clean_hash(self.empty_db)
        self.assertIsNotNone(store)
        store.close()
        self.assertIn("stale", "\n".join(cm.output))

    def test_open_clean_hash_corrupt_db_returns_none(self):
        for name, content in (("zero.sqlite", b""), ("garbage.sqlite", b"not a database" * 200)):
            path = self.tmp / name
            path.write_bytes(content)
            with self.assertLogs("misp_wl_check", "WARNING"):
                self.assertIsNone(wl.open_clean_hash(path), name)

    def test_lookup_error_disables_clean_hash_and_keeps_matching(self):
        class Broken:
            def lookup(self, sha256):
                raise sqlite3.DatabaseError("disk I/O error")
        m = wl.LocalWarninglistMatcher(set(), [], clean_hash=Broken())
        with self.assertLogs("misp_wl_check", "WARNING"):
            self.assertEqual(m.match("c" * 64, "sha256"), ["test-hashes"])
        self.assertFalse(m.clean_hash_enabled)
        self.assertEqual(m.match("a" * 64, "sha256"), [])

    def test_open_clean_hash_fresh_no_warning(self):
        with self.assertLogs("misp_wl_check", "INFO") as cm:
            store = wl.open_clean_hash(self.db)
        store.close()
        self.assertFalse([r for r in cm.records if r.levelno >= logging.WARNING])


class ReenableTests(Base):
    def setUp(self):
        super().setUp()
        rows = [
            ("uuid-a", "sha256", "a" * 64),
            ("uuid-c", "filename|sha256", "x.dll|" + "c" * 64),
            ("uuid-d", "sha256", "d" * 64),
        ]
        with open(self.tmp / "misp_wl_report_20261029_000000.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["attribute_uuid", "attribute_type", "attribute_value", "action"])
            w.writeheader()
            for uuid, t, v in rows:
                w.writerow({"attribute_uuid": uuid, "attribute_type": t,
                            "attribute_value": v, "action": "SET to_ids=False"})
        p = mock.patch.object(wl, "SCRIPT_DIR", self.tmp)
        p.start()
        self.addCleanup(p.stop)

    def test_only_unmatched_rows_are_candidates(self):
        m = wl.LocalWarninglistMatcher(set(), [], clean_hash=self.store)
        self.assertEqual(set(reenable.load_report_candidates(m)), {"uuid-d"})

    def test_restore_comment(self):
        note = "[Auto] IDS disabled by warninglist checker. Matched: Top 10K most-used sites"
        long_orig = "analyst: " + "x" * 400
        cases = {
            note: "",
            f"orig | {note}": "orig",
            f"{note} | later note": "later note",
            f"a | {note} | b": "a | b",
            f"{long_orig} | {note}": long_orig,
        }
        for comment, want in cases.items():
            self.assertEqual(reenable.restore_comment(comment), want, comment[:40])

    def test_clean_hash_cut_kept_when_store_unavailable(self):
        comment = f"x | [Auto] IDS disabled by warninglist checker. Matched: {wl.CLEAN_HASH_LIST_NAME} (file=a.dll, size=1, released=2026-10-14)"
        no_store = wl.LocalWarninglistMatcher(set(), [])
        self.assertTrue(reenable.clean_hash_cut_unverifiable(comment, no_store))
        self.assertFalse(reenable.clean_hash_cut_unverifiable("[Auto] IDS disabled by warninglist checker. Matched: google", no_store))
        with_store = wl.LocalWarninglistMatcher(set(), [], clean_hash=self.store)
        self.assertFalse(reenable.clean_hash_cut_unverifiable(comment, with_store))


if __name__ == "__main__":
    unittest.main()
