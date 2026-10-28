import unittest

from secondlook.language import check_text


def ids(text, has_link=False):
    return {f.check for f in check_text(text, has_link)}


class Rules(unittest.TestCase):
    def test_each_rule_has_a_trigger(self):
        cases = {
            "ask.code": "Please send me the code you just got",
            "pay.untraceable": "Buy three Google Play cards and send photos",
            "bait.delivery": "Your parcel is on hold, pay the customs fee",
            "bait.prize": "Congratulations, you have won an iPhone! Claim your prize",
            "impersonate.family": "Hi Mum, it's my new number",
            "impersonate.tech-support": "Your computer has been infected, call Microsoft support",
            "bait.investment": "Guaranteed returns of 20% weekly",
            "ask.credentials": "Please verify your card details",
            "pressure.secrecy": "Keep this between us",
            "pressure.fine": "You have an unpaid toll. Avoid a penalty",
            "pressure.account": "Your account has been suspended",
            "bait.job": "Part-time job, earn 500 AED per day",
            "pressure.urgency": "Final notice",
            "generic.greeting": "Dear customer,",
        }
        for rid, text in cases.items():
            self.assertIn(rid, ids(text), rid)

    def test_rule_fires_once(self):
        found = check_text("urgent urgent URGENT act now final notice")
        self.assertEqual([f.check for f in found], ["pressure.urgency"])

    def test_arabic(self):
        self.assertIn("pressure.account", ids("تم تعليق حسابك"))
        self.assertIn("pressure.urgency", ids("عاجل"))

    def test_combo_needs_a_link(self):
        self.assertNotIn("combo.pressure-plus-link", ids("Your account is locked"))
        self.assertIn("combo.pressure-plus-link", ids("Your account is locked", has_link=True))

    def test_everyday_messages_are_quiet(self):
        for text in ("See you at 8 for dinner, bring the kids!",
                     "Your code for the gym locker is on the fridge",
                     "I paid the electricity bill by bank transfer this morning",
                     "Your statement is ready in the app. We will never ask for your PIN."):
            self.assertEqual(ids(text), set(), text)


if __name__ == "__main__":
    unittest.main()
