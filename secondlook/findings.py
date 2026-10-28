"""The one shape every check returns, and how findings add up to a verdict."""
from __future__ import annotations

from dataclasses import dataclass, asdict

# Score thresholds. A single strong signal (a lookalike domain, a request for a
# one-time code) is enough on its own; weak signals need company to matter.
LIKELY_SCAM = 60
SUSPICIOUS = 25

VERDICTS = {
    "likely-scam": "LIKELY SCAM",
    "suspicious": "SUSPICIOUS",
    "no-red-flags": "NO RED FLAGS FOUND",
}


@dataclass
class Finding:
    points: int        # how much this pushes towards "scam" (5 weak .. 60 decisive)
    check: str         # stable id, e.g. "link.lookalike"
    title: str         # one line a non-expert understands
    why: str           # why scammers do this, in plain words
    evidence: str = ""  # the exact text or link that triggered it

    def to_dict(self):
        return asdict(self)


def head_tail(s, cap):
    """Keep both ends of an oversized string, so padding at the front can't push the
    real content past the cut."""
    if len(s) <= cap:
        return s
    return s[:cap * 3 // 4] + "\n" + s[-(cap // 4):]


def score(findings):
    return sum(f.points for f in findings)


def verdict(findings):
    s = score(findings)
    if s >= LIKELY_SCAM:
        return "likely-scam"
    if s >= SUSPICIOUS:
        return "suspicious"
    return "no-red-flags"
