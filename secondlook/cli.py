"""Command line: secondlook [MESSAGE] [-f FILE] [--online] [--json]."""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .check import analyze
from .findings import VERDICTS

EXIT = {"no-red-flags": 0, "suspicious": 10, "likely-scam": 20}
MAX_BYTES = 5_000_000  # a pasted message or a saved email; anything bigger is not one

ADVICE = {
    "likely-scam": [
        "Do not tap the links, reply, or call any number in the message.",
        "If it claims to be a company, open their app or type their website yourself.",
        "Already entered details? Change that password now and call your bank's number "
        "from the back of your card.",
        "Report it, then delete it. See docs/SCAM-FIELD-GUIDE.md for where to report.",
    ],
    "suspicious": [
        "Don't act on it yet. Check it through a channel you already trust: the official "
        "app, the number on your card, or a call to the person on their known number.",
        "Never share codes, passwords or card details because a message asked you to.",
    ],
    "no-red-flags": [
        "Nothing matched known scam patterns, but that does NOT mean it is safe.",
        "New scams appear daily. If it asks for money, codes or passwords, verify it "
        "another way first.",
    ],
}


def _color(enabled):
    def c(code, s):
        return "\033[{}m{}\033[0m".format(code, s) if enabled else s
    return c


def render(report, color=False):
    c = _color(color)
    tone = {"likely-scam": "1;31", "suspicious": "1;33", "no-red-flags": "1;32"}[report["verdict"]]
    lines = ["", c(tone, "  {}  ".format(VERDICTS[report["verdict"]])) +
             "  (score {}, {} checked)".format(report["score"], report["kind"]), ""]
    for f in report["findings"]:
        bar = "!!!" if f["points"] >= 40 else "!! " if f["points"] >= 20 else "!  "
        lines.append("  {} {}".format(c(tone, bar), c("1", f["title"])))
        lines.append("      " + f["why"])
        if f["evidence"]:
            lines.append("      " + c("2", "seen: " + f["evidence"]))
        lines.append("")
    for n in report["notes"]:
        lines.append("  " + c("2", "note: " + n))
    if report["notes"]:
        lines.append("")
    lines.append("  " + c("1", "What to do:"))
    lines += ["   - " + a for a in ADVICE[report["verdict"]]]
    if not report["online"] and report["links"]:
        lines.append("   - " + c("2", "Tip: --online also checks how old the websites are and "
                                     "unwraps short links."))
    lines.append("")
    return "\n".join(lines)


def _read_input(args):
    if args.file:
        with open(args.file, "rb") as fh:
            blob = fh.read(MAX_BYTES + 1)
    elif args.message:
        return " ".join(args.message)
    else:
        if sys.stdin.isatty():
            print("Paste the message, then press Ctrl-D (Ctrl-Z then Enter on Windows):",
                  file=sys.stderr)
        blob = sys.stdin.buffer.read(MAX_BYTES + 1)
    if len(blob) > MAX_BYTES:
        raise ValueError("input is larger than 5 MB; that is not a single message")
    return blob.decode("utf-8", errors="replace")


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="secondlook",
        description="Take a second look at a suspicious text, chat message or email before "
                    "you tap. Works offline; nothing is sent anywhere unless you add --online.",
        epilog="exit codes: 0 no red flags, 10 suspicious, 20 likely scam, 2 usage error")
    p.add_argument("message", nargs="*", help="the message text (or pipe it in, or use -f)")
    p.add_argument("-f", "--file", help="a text file or a saved email (.eml)")
    p.add_argument("--online", action="store_true",
                   help="also look up domain ages and unwrap short links (sends domain names only)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--no-color", action="store_true", help="plain output")
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    args = p.parse_args(argv)

    try:
        raw = _read_input(args)
    except (OSError, ValueError) as e:
        p.error(str(e))
    if not raw.strip():
        p.error("no message given")

    report = analyze(raw, online=args.online)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
        print(render(report, color=color))
    return EXIT[report["verdict"]]
