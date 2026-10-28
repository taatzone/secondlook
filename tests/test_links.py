import unittest

from secondlook.links import check_url, find_urls, host_of, registrable, skeleton


def checks(url):
    return {f.check for f in check_url(url)}


class FindUrls(unittest.TestCase):
    def test_scheme_www_and_bare(self):
        text = "Go to https://a.example.com/x, or www.b.com. Or pay at dhl-fee.top/pay!"
        self.assertEqual(find_urls(text),
                         ["https://a.example.com/x", "www.b.com", "dhl-fee.top/pay"])

    def test_prose_is_not_a_link(self):
        self.assertEqual(find_urls("See file.txt, e.g. the notes. Mr.Smith said hi."), [])

    def test_email_address_is_not_a_link(self):
        self.assertEqual(find_urls("write to help@shop.com"), [])

    def test_no_duplicates(self):
        self.assertEqual(find_urls("bit.ly/x and again bit.ly/x"), ["bit.ly/x"])


class Parsing(unittest.TestCase):
    def test_registrable(self):
        self.assertEqual(registrable("login.paypal.com"), "paypal.com")
        self.assertEqual(registrable("www.amazon.co.uk"), "amazon.co.uk")
        self.assertEqual(registrable("evil.gov.ae"), "evil.gov.ae")
        self.assertEqual(registrable("paypal-login.web.app"), "paypal-login.web.app")

    def test_punycode_is_decoded(self):
        self.assertEqual(host_of("https://xn--pple-43d.com/"), "аpple.com")  # Cyrillic а

    def test_skeleton_folds_lookalikes(self):
        for fake in ("paypa1", "rnicrosoft", "аpple", "g00gle", "PAYPAL"):
            self.assertIn(skeleton(fake), {skeleton("paypal"), skeleton("microsoft"),
                                           skeleton("apple"), skeleton("google")})


class Verdicts(unittest.TestCase):
    def test_official_domains_are_clean(self):
        for url in ("https://www.paypal.com/signin", "https://myaccount.google.com/security",
                    "https://www.amazon.ae/gp/your-account", "https://emiratespost.ae/track",
                    "https://dubaipolice.gov.ae/fines"):
            self.assertEqual(checks(url), set(), url)

    def test_lookalikes(self):
        for url in ("https://paypa1.com/login", "rnicrosoft.com", "https://xn--pple-43d.com/",
                    "amazom.com"):
            self.assertIn("link.lookalike", checks(url), url)

    def test_brand_as_decoration(self):
        for url in ("https://dhl-redelivery.top/pay", "paypal.com.secure-check.xyz",
                    "http://paypa1.com.account-verify.xyz/login", "paypal-login.web.app"):
            self.assertIn("link.brand-decoy", checks(url), url)

    def test_brand_name_on_other_ending(self):
        self.assertIn("link.brand-wrong-domain", checks("https://paypal.help/"))

    def test_common_word_brand_not_decoy(self):
        self.assertNotIn("link.brand-decoy", checks("https://uae-visa-application.com/apply"))

    def test_userinfo_trick(self):
        self.assertIn("link.userinfo-trick", checks("https://paypal.com@evil.top/"))

    def test_ip_and_shortener_and_free_host(self):
        self.assertIn("link.ip-address", checks("http://203.0.113.9/login"))
        self.assertIn("link.shortener", checks("https://bit.ly/3abc"))
        self.assertIn("link.free-host", checks("https://my-portal.netlify.app"))

    def test_ordinary_site_is_clean(self):
        self.assertEqual(checks("https://www.bbc.co.uk/news"), set())
        self.assertEqual(checks("https://github.com/taatzone"), set())


if __name__ == "__main__":
    unittest.main()
