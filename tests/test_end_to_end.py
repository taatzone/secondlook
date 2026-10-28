"""Every file in examples/ must get the verdict its name promises, offline."""
import io
import json
import socket
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from secondlook.check import analyze
from secondlook.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _no_network(*a, **k):
    raise AssertionError("offline mode tried to open a network connection")


class Examples(unittest.TestCase):
    def test_examples_exist(self):
        self.assertGreaterEqual(len(list(EXAMPLES.glob("scam-*"))), 5)
        self.assertGreaterEqual(len(list(EXAMPLES.glob("genuine-*"))), 3)

    @mock.patch.object(socket, "socket", _no_network)
    @mock.patch.object(socket, "create_connection", _no_network)
    @mock.patch.object(socket, "getaddrinfo", _no_network)
    def test_every_example_offline(self):
        for path in sorted(EXAMPLES.iterdir()):
            r = analyze(path.read_text(encoding="utf-8"))
            if path.name.startswith("scam-"):
                self.assertEqual(r["verdict"], "likely-scam", (path.name, r["findings"]))
            else:
                self.assertEqual(r["verdict"], "no-red-flags", (path.name, r["findings"]))


class TutorialPractice(unittest.TestCase):
    """docs/TUTORIAL.md publishes these answers; keep the tool honest to them."""

    def test_answers(self):
        cases = [
            ("Your Salik account has an unpaid toll balance of AED 50. Pay within 24 hours "
             "to avoid a penalty: salik-ae.cfd/pay", "likely-scam"),
            ("Hi, it's Sara from the dentist. Just confirming your appointment Monday at 10. "
             "Reply C to confirm.", "no-red-flags"),
            ("Apple: your iCloud storage is full. Upgrade at https://www.apple.com/icloud/",
             "no-red-flags"),
            ("Dad my phone fell in the water this is my new number, can you send 2000 to my "
             "friend's account, I'll pay back tomorrow. Don't tell mum", "likely-scam"),
            ("Your Netflix payment failed. Update your billing information: "
             "https://netflix.account-help.live", "likely-scam"),
        ]
        for text, expect in cases:
            self.assertEqual(analyze(text)["verdict"], expect, text)


class Cli(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(list(argv))
        return code, out.getvalue()

    def test_exit_codes(self):
        self.assertEqual(self.run_cli("see you at dinner")[0], 0)
        self.assertEqual(self.run_cli("Your account has been suspended")[0], 10)
        self.assertEqual(self.run_cli("-f", str(EXAMPLES / "scam-phishing.eml"))[0], 20)

    def test_json(self):
        code, out = self.run_cli("--json", "send me the code please, urgent")
        r = json.loads(out)
        self.assertEqual(r["verdict"], "likely-scam")
        self.assertEqual(code, 20)
        self.assertEqual(r["findings"][0]["check"], "ask.code")

    def test_human_output_never_says_safe(self):
        _, out = self.run_cli("--no-color", "see you at dinner")
        self.assertIn("NO RED FLAGS FOUND", out)
        self.assertIn("does NOT mean it is safe", out)

    def test_empty_input_is_usage_error(self):
        with self.assertRaises(SystemExit) as e, redirect_stdout(io.StringIO()), \
                mock.patch("sys.stderr", io.StringIO()):
            main(["   "])
        self.assertEqual(e.exception.code, 2)

    def test_missing_file_is_usage_error(self):
        with self.assertRaises(SystemExit) as e, mock.patch("sys.stderr", io.StringIO()):
            main(["-f", "/nonexistent/message.txt"])
        self.assertEqual(e.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
