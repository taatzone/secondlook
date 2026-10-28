"""--online logic against canned answers: these tests never touch the real network."""
import io
import json
import unittest
import urllib.error
from datetime import datetime, timezone
from email.message import Message
from unittest import mock

from secondlook import online
from secondlook.check import analyze


def redirect(location, code=301):
    h = Message()
    h["Location"] = location
    return urllib.error.HTTPError("u", code, "moved", h, io.BytesIO())


def rdap(date):
    body = json.dumps({"events": [{"eventAction": "registration", "eventDate": date}]})
    return mock.MagicMock(__enter__=lambda s: io.BytesIO(body.encode()),
                          __exit__=lambda *a: None)


class Unshorten(unittest.TestCase):
    def test_follows_redirect_chain(self):
        hops = [redirect("https://tinyurl.com/b"), redirect("https://evil.top/pay")]
        with mock.patch.object(online._opener, "open", side_effect=hops) as o:
            self.assertEqual(online.unshorten("https://bit.ly/a"), "https://evil.top/pay")
        self.assertEqual(o.call_count, 2)
        self.assertEqual(o.call_args_list[0][0][0].get_method(), "HEAD")

    def test_non_shortener_is_not_contacted(self):
        with mock.patch.object(online._opener, "open") as o:
            self.assertEqual(online.unshorten("https://example.com"), "https://example.com")
        o.assert_not_called()


class DomainAge(unittest.TestCase):
    def test_age(self):
        with mock.patch("urllib.request.urlopen", return_value=rdap("2026-10-20T00:00:00Z")):
            days = online.domain_age_days("x.top", now=datetime(2026, 10, 28, tzinfo=timezone.utc))
        self.assertEqual(days, 8)

    def test_findings_by_age(self):
        for age, expect in ((5, "online.new-domain"), (90, "online.young-domain"), (900, None)):
            with mock.patch.object(online, "domain_age_days", return_value=age):
                f, _ = online.check_age("x.top")
            self.assertEqual(f.check if f else None, expect)

    def test_lookup_failure_is_a_note_not_a_crash(self):
        with mock.patch.object(online, "domain_age_days", side_effect=OSError("offline")):
            f, note = online.check_age("x.top")
        self.assertIsNone(f)
        self.assertIn("unavailable", note)


class AnalyzeOnline(unittest.TestCase):
    def test_short_link_destination_is_judged(self):
        with mock.patch.object(online, "unshorten",
                               side_effect=lambda u: "https://paypa1.com/x" if "bit.ly" in u else u), \
                mock.patch.object(online, "domain_age_days", return_value=3):
            r = analyze("Check this: https://bit.ly/abc", online=True)
        checks = {f["check"] for f in r["findings"]}
        self.assertIn("link.lookalike", checks)
        self.assertIn("online.new-domain", checks)
        self.assertEqual(r["verdict"], "likely-scam")

    def test_known_brands_are_not_looked_up(self):
        with mock.patch.object(online, "domain_age_days") as age:
            analyze("https://www.paypal.com/signin", online=True)
        age.assert_not_called()


if __name__ == "__main__":
    unittest.main()
