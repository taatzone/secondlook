"""Opt-in checks that need the internet (--online). Off by default.

What leaves your machine: only domain names (to rdap.org, for registration dates)
and shortened links (to the shortener itself, which answers with the destination).
The message text never leaves your machine, and no page is ever downloaded.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from . import data
from .findings import Finding
from .links import host_of, registrable

UA = "secondlook/0.1 (+https://github.com/taatzone/secondlook)"
TIMEOUT = 8


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # we want to read the Location header, not follow it


_opener = urllib.request.build_opener(_NoRedirect)


def unshorten(url, hops=5):
    """Follow a shortened link one hop at a time without loading any page."""
    if "://" not in url:
        url = "https://" + url
    for _ in range(hops):
        if registrable(host_of(url)) not in data.SHORTENERS:
            return url
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
        try:
            _opener.open(req, timeout=TIMEOUT)
            return url  # no redirect: this is the end of the chain
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location")
            if e.code not in (301, 302, 303, 307, 308) or not loc:
                return url
            url = urllib.parse.urljoin(url, loc)
    return url


def domain_age_days(domain, now=None):
    req = urllib.request.Request("https://rdap.org/domain/" + domain,
                                 headers={"User-Agent": UA, "Accept": "application/rdap+json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        doc = json.load(r)
    for ev in doc.get("events", []):
        if ev.get("eventAction") == "registration":
            born = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            return ((now or datetime.now(timezone.utc)) - born).days
    return None


def check_age(domain):
    try:
        days = domain_age_days(domain)
    except (OSError, ValueError, KeyError):
        return None, "registration date for {} unavailable".format(domain)
    if days is None:
        return None, "registration date for {} not published".format(domain)
    if days < 30:
        return Finding(40, "online.new-domain", "Website was created {} days ago".format(days),
                       "Scam sites are thrown away and replaced within weeks. A brand-new "
                       "domain asking for payment or logins is a strong warning.", domain), None
    if days < 180:
        return Finding(15, "online.young-domain", "Website is only {} days old".format(days),
                       "Young domains are not proof of a scam, but established companies "
                       "rarely send you to one.", domain), None
    return None, None
