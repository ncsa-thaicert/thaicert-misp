import json
import os
import tempfile
import time
import unittest
from unittest import mock

# Keep the module's log file and .env-derived settings away from production
_TMP = tempfile.mkdtemp()
os.environ["LOG_FILE"] = os.path.join(_TMP, "retirement_test.log")
os.environ["RETIREMENT_STATE_FILE"] = os.path.join(_TMP, "state.json")

import misp_ioc_retirement as r  # noqa: E402


class LookupValueTests(unittest.TestCase):
    def test_composite_values_are_split(self):
        self.assertEqual(r.lookup_value("ip-dst|port", "8.219.85.91|8888"), "8.219.85.91")
        self.assertEqual(r.lookup_value("ip-src|port", "10.0.0.1|443"), "10.0.0.1")
        self.assertEqual(r.lookup_value("domain|ip", "evil.example|1.2.3.4"), "evil.example")
        self.assertEqual(r.lookup_value("filename|sha256", "a.exe|" + "a" * 64), "a" * 64)
        self.assertEqual(r.lookup_value("filename|md5", "x|y|" + "b" * 32), "b" * 32)

    def test_plain_values_unchanged(self):
        self.assertEqual(r.lookup_value("url", " http://x.example/a|b "), "http://x.example/a|b")
        self.assertEqual(r.lookup_value("sha256", "c" * 64), "c" * 64)
        self.assertEqual(r.lookup_value("ip-dst", "2001:db8::1"), "2001:db8::1")

    def test_unparseable_ip_is_not_checkable(self):
        self.assertIsNone(r.lookup_value("ip-dst", "not-an-ip"))
        self.assertIsNone(r.lookup_value("ip-dst|port", "|80"))
        self.assertIsNone(r.lookup_value("domain", "   "))


class ProviderDTypeTests(unittest.TestCase):
    def test_ipv6_uses_ipv6_endpoint(self):
        seen = []
        resp = mock.Mock(status_code=404)
        with mock.patch.object(r, "ENRICH_D_ON", True), \
             mock.patch.object(r, "ENRICH_D_URL", "https://d.example/api"), \
             mock.patch.object(r, "request_with_retry", side_effect=lambda m, u, **k: seen.append(u) or resp):
            r.check_provider_d("IP", "2001:db8::1")
            r.check_provider_d("IP", "1.2.3.4")
        self.assertIn("/IPv6/", seen[0])
        self.assertIn("/IPv4/", seen[1])


def _attr(i, typ, age_days, now, uuid=None):
    return {"id": str(i), "uuid": uuid or f"u{i}", "type": typ, "value": f"v{i}",
            "to_ids": True, "timestamp": str(now - age_days * 86400), "event_id": "7",
            "Event": {"orgc_id": str(r.OWNER_ORG_ID)}}


class CollectStaleTests(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        n = self.now
        self.data = {
            "IP":     [_attr(i, "ip-dst", 400, n) for i in range(1, 11)],
            "DOMAIN": [_attr(i, "domain", 400, n) for i in range(11, 13)],
            "URL":    [],
            "HASH":   [_attr(i, "sha256", 400, n) for i in range(21, 26)],
        }
        self.calls = []

    def _search(self, misp, **filters):
        self.calls.append(filters)
        types = filters["type_attribute"]
        cat = next(c for c, t in r.CATEGORY_TYPES.items() if t == types)
        yield from self.data[cat]

    def test_round_robin_cap_and_filters(self):
        with mock.patch.object(r, "MAX_CHECKS_PER_RUN", 6), \
             mock.patch.object(r, "search_attributes", side_effect=self._search):
            out, fetched, skipped = r.collect_stale(None, self.now, self.now - 30 * 86400, {}, set())
        self.assertEqual(len(out), 6)
        self.assertEqual([c["category"] for c in out], ["IP", "DOMAIN", "HASH", "IP", "DOMAIN", "HASH"])
        self.assertEqual(skipped, 0)
        for f in self.calls:
            self.assertEqual(f["org"], r.OWNER_ORG_ID)
            self.assertTrue(f["to_ids"])
            self.assertEqual(f["timestamp"][0], 1)
        ip_call = next(f for f in self.calls if "ip-dst" in f["type_attribute"])
        self.assertEqual(ip_call["timestamp"][1], self.now - r.IP_AGE_THRESHOLD * 86400)

    def test_recently_checked_are_skipped_and_excluded_ids_ignored(self):
        state = {"u1": self.now - 86400, "u2": self.now - 90 * 86400}
        with mock.patch.object(r, "MAX_CHECKS_PER_RUN", 100), \
             mock.patch.object(r, "search_attributes", side_effect=self._search):
            out, _, skipped = r.collect_stale(None, self.now, self.now - 30 * 86400, state, {"3"})
        ids = {c["id"] for c in out}
        self.assertNotIn("1", ids)   # kept yesterday
        self.assertIn("2", ids)      # kept 90 days ago: due again
        self.assertNotIn("3", ids)   # already a whitelist candidate
        self.assertEqual(skipped, 1)

    def test_foreign_org_and_disabled_are_dropped(self):
        self.data["IP"][0]["Event"]["orgc_id"] = "99"
        self.data["IP"][1]["to_ids"] = False
        with mock.patch.object(r, "MAX_CHECKS_PER_RUN", 100), \
             mock.patch.object(r, "search_attributes", side_effect=self._search):
            out, _, _ = r.collect_stale(None, self.now, self.now, {}, set())
        ids = {c["id"] for c in out}
        self.assertNotIn("1", ids)
        self.assertNotIn("2", ids)


class SearchPaginationTests(unittest.TestCase):
    def test_pages_until_short_page(self):
        misp = mock.Mock()
        misp.search.side_effect = [{"Attribute": [{"id": i} for i in range(3)]},
                                   {"Attribute": [{"id": 9}]}]
        with mock.patch.object(r, "PAGE_SIZE", 3):
            got = list(r.search_attributes(misp, to_ids=True))
        self.assertEqual(len(got), 4)
        self.assertEqual([c.kwargs["page"] for c in misp.search.call_args_list], [1, 2])

    def test_error_response_raises(self):
        misp = mock.Mock()
        misp.search.return_value = {"errors": ["bad filter"]}
        with self.assertRaises(RuntimeError):
            list(r.search_attributes(misp))


class StateTests(unittest.TestCase):
    def test_round_trip_and_pruning(self):
        path = os.path.join(_TMP, "s.json")
        now = int(time.time())
        r.save_state(path, {"fresh": now - 86400, "old": now - (r.RECHECK_DAYS + 1) * 86400}, now)
        self.assertEqual(r.load_state(path), {"fresh": now - 86400})
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o640")

    def test_missing_or_corrupt_state_is_empty(self):
        self.assertEqual(r.load_state(os.path.join(_TMP, "none.json")), {})
        bad = os.path.join(_TMP, "bad.json")
        with open(bad, "w") as f:
            f.write("{not json")
        self.assertEqual(r.load_state(bad), {})


if __name__ == "__main__":
    unittest.main()
