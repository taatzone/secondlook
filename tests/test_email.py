import unittest

from secondlook.email_check import looks_like_email, parse

HEAD = "From: {frm}\nTo: you@example.net\nSubject: Hi\n{extra}Content-Type: {ctype}\n\n{body}"


def mail(frm="Shop <news@shop.com>", extra="", ctype="text/plain", body="hello"):
    return HEAD.format(frm=frm, extra=extra, ctype=ctype, body=body)


def ids(raw):
    return {f.check for f in parse(raw)[0]}


class Email(unittest.TestCase):
    def test_detects_email(self):
        self.assertTrue(looks_like_email(mail()))
        self.assertFalse(looks_like_email("from the shop: your order is ready"))

    def test_clean_mail(self):
        self.assertEqual(ids(mail()), set())

    def test_fake_display_address(self):
        self.assertIn("email.fake-display-address",
                      ids(mail(frm='"support@paypal.com" <x@evil.top>')))

    def test_brand_display_name(self):
        self.assertIn("email.brand-name-wrong-sender", ids(mail(frm="PayPal Security <x@evil.top>")))
        self.assertEqual(ids(mail(frm="PayPal <service@paypal.com>")), set())

    def test_reply_to_elsewhere(self):
        self.assertIn("email.reply-elsewhere", ids(mail(extra="Reply-To: x@gmail.com\n")))
        self.assertEqual(ids(mail(extra="Reply-To: help@shop.com\n")), set())

    def test_auth_failed(self):
        r = ids(mail(extra="Authentication-Results: mx; spf=softfail; dkim=pass; dmarc=fail\n"))
        self.assertIn("email.auth-failed", r)
        self.assertEqual(ids(mail(extra="Authentication-Results: mx; spf=pass; dkim=pass\n")), set())

    def test_lying_link_and_html_text(self):
        body = ('<p>Hi</p><a href="https://evil.top/x">www.mybank.com</a>'
                '<a href="https://shop.com/a">shop.com/a</a><script>var x="secret";</script>')
        found, text, links = parse(mail(ctype="text/html", body=body))
        self.assertIn("email.link-mismatch", {f.check for f in found})
        self.assertEqual(len([f for f in found if f.check == "email.link-mismatch"]), 1)
        self.assertEqual(links, ["https://evil.top/x", "https://shop.com/a"])
        self.assertNotIn("secret", text)

    def test_hrefs_are_normalised_like_a_browser(self):
        body = ('<a href=" \x01https://evil.top/a ">www.mybank.com</a>'
                '<a href="java\tscript:alert(1)">Open</a><a href="data:text/html,x">x</a>')
        found, _, links = parse(mail(ctype="text/html", body=body))
        self.assertEqual(links, ["https://evil.top/a"])
        got = [f.check for f in found]
        self.assertIn("email.link-mismatch", got)
        self.assertEqual(got.count("email.code-link"), 2)

    def test_hostile_long_names_are_fast(self):
        import time
        long = "a" * 200000
        body = "<a href='https://x.com'>{}</a>".format(long + "." + long)
        t = time.perf_counter()
        parse(mail(frm='"{}" <x@shop.com>'.format(long + "@" + long), ctype="text/html", body=body))
        self.assertLess(time.perf_counter() - t, 2)


if __name__ == "__main__":
    unittest.main()
