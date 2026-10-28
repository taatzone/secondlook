"""Glue: take a message, run every check, return one report."""
from __future__ import annotations

from . import email_check, language, links
from . import online as net
from .data import BRANDS, SHORTENERS
from .findings import score, verdict

_KNOWN = set().union(*BRANDS.values()) | SHORTENERS


def analyze(raw, online=False):
    """Analyse a text message or a raw email. Returns a plain dict (JSON-ready)."""
    findings, notes = [], []
    is_email = email_check.looks_like_email(raw)
    if is_email:
        found, text, urls = email_check.parse(raw)
        findings += found
        urls = list(dict.fromkeys(urls + links.find_urls(text)))
    else:
        text, urls = raw, links.find_urls(raw)

    if online:
        resolved = []
        for u in urls:
            try:
                final = net.unshorten(u)
            except OSError as e:
                notes.append("could not unwrap {}: {}".format(u, e))
                final = u
            if final != u:
                notes.append("{} really goes to {}".format(u, final))
                resolved.append(final)
        urls += resolved

    for u in urls:
        findings += links.check_url(u)
    findings += language.check_text(text, has_link=bool(urls))

    if online:
        for dom in dict.fromkeys(links.registrable(links.host_of(u)) for u in urls):
            if dom and dom not in _KNOWN:
                f, note = net.check_age(dom)
                if f:
                    findings.append(f)
                if note:
                    notes.append(note)

    # One finding per (check, evidence): a link repeated in text and HTML counts once.
    findings = list({(f.check, f.evidence): f for f in findings}.values())
    findings.sort(key=lambda f: -f.points)
    return {
        "verdict": verdict(findings),
        "score": score(findings),
        "kind": "email" if is_email else "text",
        "links": urls,
        "findings": [f.to_dict() for f in findings],
        "notes": notes,
        "online": online,
    }
