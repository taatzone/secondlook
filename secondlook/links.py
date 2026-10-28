"""Find links in a message and judge each one by its address alone (no visiting)."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from . import data
from .findings import Finding

_SCHEME_URL = re.compile(r"\b(?:https?://|www\.)[^\s<>\"'`]+", re.I)
# A bare domain such as "dhl-redelivery.top/pay" - checked against BARE_TLDS after matching.
_BARE_URL = re.compile(r"(?<![@\w.-])((?:[\w-]+\.)+([a-z]{2,24}))(/[^\s<>\"'`]*)?", re.I)
_TRAILING = ".,;:!?)]}>'\""
_SUSPECT_WORDS = ("login", "log-in", "signin", "sign-in", "verify", "verification", "secure",
                  "account", "update", "confirm", "unlock", "wallet", "billing", "payment",
                  "refund", "redelivery", "reschedule", "suspend")


def find_urls(text):
    """Every link-looking thing in the text, in order, without duplicates."""
    found = []
    taken = []
    for m in _SCHEME_URL.finditer(text):
        found.append(m.group(0).rstrip(_TRAILING))
        taken.append(m.span())
    for m in _BARE_URL.finditer(text):
        if any(a <= m.start() < b for a, b in taken):
            continue
        if m.group(2).lower() not in data.BARE_TLDS:
            continue
        found.append(m.group(0).rstrip(_TRAILING))
    seen = set()
    return [u for u in found if not (u.lower() in seen or seen.add(u.lower()))]


def host_of(url):
    """Lower-case host name (punycode decoded to Unicode), or "" if unparseable."""
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "http://" + url
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    if "xn--" in host:
        try:
            host = host.encode("ascii").decode("idna")
        except UnicodeError:
            pass
    return host.lower().rstrip(".")


def registrable(host):
    """The part of a host name someone actually buys: login.paypal.com -> paypal.com.

    shortcut: approximates the Public Suffix List with SECOND_LEVEL labels,
    swap in the real list if hosts like "*.blogspot.co.uk" ever matter.
    """
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in data.SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    for fh in data.FREE_HOSTS:  # each site on a free host is its own owner
        if host.endswith("." + fh):
            return ".".join(labels[-(fh.count(".") + 2):])
    return ".".join(labels[-2:])


def skeleton(s):
    s = s.lower()
    for pair, rep in data.CONFUSABLE_PAIRS.items():
        s = s.replace(pair, rep)
    return "".join(data.CONFUSABLES.get(ch, ch) for ch in s).replace("-", "")


def _edit_distance(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _is_official(host):
    reg = registrable(host)
    return any(reg in domains or host in domains for domains in data.BRANDS.values())


def check_url(url):
    """Findings for one link, judged only by how its address is built."""
    out = []
    host = host_of(url)
    if not host:
        return out
    reg = registrable(host)
    name = reg.split(".")[0]
    official = _is_official(host)

    try:
        ipaddress.ip_address(host.strip("[]"))
        out.append(Finding(35, "link.ip-address", "Link goes to a bare number, not a name",
                           "Real companies use their own domain name. A link to a raw IP "
                           "address is usually a hastily set-up or hacked server.", url))
        return out
    except ValueError:
        pass

    if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
        out.append(Finding(50, "link.userinfo-trick", "Link hides its real address after an '@'",
                           "In a web address everything before '@' is ignored. "
                           "'https://paypal.com@evil.top' really opens evil.top.", url))

    if not official:
        out += _brand_checks(url, host, reg, name)

    if not host.isascii() and not any(f.check == "link.lookalike" for f in out):
        out.append(Finding(25, "link.foreign-letters", "Address uses non-Latin letters",
                           "Letters from other alphabets can look identical to ours, so an "
                           "address can look familiar and still lead somewhere else.", url))

    if reg in data.SHORTENERS or host in data.SHORTENERS:
        out.append(Finding(20, "link.shortener", "Shortened link hides where it goes",
                           "You cannot see the real destination until you tap. "
                           "Run with --online to unwrap it safely.", url))

    if any(host.endswith("." + fh) or host == fh for fh in data.FREE_HOSTS):
        out.append(Finding(15, "link.free-host", "Page lives on a free website builder",
                           "Fine for hobby sites, but banks and couriers do not host "
                           "their login pages on free builders. Fake ones often do.", url))

    tld = host.rsplit(".", 1)[-1]
    if tld in data.RISKY_TLDS and not official:
        out.append(Finding(10, "link.risky-ending", "Address ends in ." + tld,
                           "This ending is cheap and turns up often in scam reports. "
                           "Not proof by itself.", url))

    if not official and any(w in url.lower() for w in _SUSPECT_WORDS):
        out.append(Finding(10, "link.bait-words", "Address is dressed up with 'login/verify' words",
                           "Words like 'secure', 'verify' or 'account' in an unknown address "
                           "are there to make it feel official.", url))

    if host.count(".") >= 4 and not official:
        out.append(Finding(10, "link.deep-subdomains", "Address is unusually long and layered",
                           "Stacking names (paypal.com.account.verify.xyz) pushes the real "
                           "owner to the far right, where people stop reading.", url))
    return out


def _brand_checks(url, host, reg, name):
    tokens = set(skeleton(t) for t in re.split(r"[.\-_]", host))
    sk = skeleton(name)
    for brand, domains in data.BRANDS.items():
        if name == brand:
            return [Finding(30, "link.brand-wrong-domain",
                            "Uses the name '{}' on an unofficial ending".format(brand),
                            "{} uses {}. This is {}, which may be a regional site but is "
                            "often a copy.".format(brand, ", ".join(sorted(domains)[:3]), reg), url)]
        if sk == skeleton(brand) or (len(brand) >= 6 and _edit_distance(name, brand) == 1):
            return [Finding(60, "link.lookalike", "Address imitates '{}'".format(brand),
                            "'{}' is spelled to look like {} at a glance (swapped or "
                            "look-alike letters). It is not theirs.".format(reg, sorted(domains)[0]),
                            url)]
    for brand in data.BRANDS:
        if skeleton(brand) in tokens and brand not in data.COMMON_WORD_BRANDS:
            return [Finding(45, "link.brand-decoy", "Brand name '{}' used as decoration".format(brand),
                            "The address contains '{}' but is really owned by '{}'. The brand "
                            "name is there to borrow trust.".format(brand, reg), url)]
    return []
