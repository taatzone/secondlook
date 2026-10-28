"""Read a saved email (.eml): who really sent it, did it pass sender checks, do links lie."""
from __future__ import annotations

import email
import re
from email import policy
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser

from . import data
from .findings import Finding, head_tail
from .links import host_of, registrable, skeleton


_CODE_SCHEMES = {"javascript", "vbscript", "data", "file"}
_SCAN_CAP = 500  # link texts and sender names longer than this are not honest ones anyway


def looks_like_email(raw):
    head = raw.lstrip()[:2000]
    return bool(re.search(r"^(from|received|return-path|message-id|delivered-to):", head, re.I | re.M))


class _Html(HTMLParser):
    """Collects visible text and (href, link text) pairs from an HTML body."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.anchors, self._href, self._atext, self._skip = [], [], None, [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a":
            self._href, self._atext = dict(attrs).get("href"), []

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._atext).strip()))
            self._href = None
        if tag in ("p", "br", "div", "tr", "li"):
            self.text.append("\n")

    def handle_data(self, d):
        if self._skip:
            return
        self.text.append(d)
        if self._href is not None:
            self._atext.append(d)


def parse(raw):
    """Return (findings, body_text, link_urls) for a raw RFC 822 message."""
    msg = email.message_from_string(raw, policy=policy.default)
    findings, texts, links = [], [], []

    subject = str(msg.get("Subject", ""))
    if subject:
        texts.append(subject)

    for part in msg.walk():
        if part.is_multipart() or part.get_content_maintype() != "text":
            continue
        try:
            body = part.get_content()
        except (LookupError, ValueError):
            continue
        if part.get_content_subtype() == "html":
            p = _Html()
            p.feed(body)
            texts.append("".join(p.text))
            for href, label in p.anchors:
                # Browsers strip edge spaces/controls and drop tabs and newlines, so
                # " https://evil" and "java\tscript:" must be read the same way here.
                href = re.sub(r"^[\x00-\x20]+|[\x00-\x20]+$|[\t\n\r]", "", href or "")
                scheme = href.split(":", 1)[0].lower() if ":" in href else ""
                if scheme in ("http", "https"):
                    links.append(href)
                    f = _lying_link(href, label)
                    if f:
                        findings.append(f)
                elif scheme in _CODE_SCHEMES:
                    findings.append(Finding(
                        40, "email.code-link", "A link runs code instead of opening a website",
                        "This '{}:' link doesn't go to a website at all: it runs script or "
                        "opens content hidden inside the email. Normal emails never need "
                        "that.".format(scheme), href[:120]))
        else:
            texts.append(body)

    findings += _sender_checks(msg)
    return findings, "\n".join(texts), links


def _lying_link(href, label):
    """The text says one address, the link really goes to another."""
    shown = re.search(r"(?<![\w.-])(?:https?://)?((?:[\w-]+\.)+[a-z]{2,})",
                      head_tail(label, _SCAN_CAP), re.I)
    if not shown:
        return None
    a, b = registrable(host_of(shown.group(0))), registrable(host_of(href))
    if a and b and a != b:
        return Finding(45, "email.link-mismatch", "A link shows one address but opens another",
                       "The email displays '{}' but the link actually goes to '{}'. Honest "
                       "senders have no reason to disguise a link.".format(a, b),
                       "{} -> {}".format(label, href))
    return None


def _domain(addr):
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def _sender_checks(msg):
    out = []
    display, addr = parseaddr(str(msg.get("From", "")))
    from_dom = _domain(addr)

    # Display-name tricks: "PayPal Security <x@random.top>" or "service@paypal.com <x@random.top>"
    display = head_tail(display, _SCAN_CAP)
    inner = re.search(r"(?<![\w.+-])[\w.+-]+@([\w-]+\.[\w.-]+)", display)
    if inner and from_dom and registrable(inner.group(1).lower()) != registrable(from_dom):
        out.append(Finding(45, "email.fake-display-address",
                           "Sender name contains a different email address",
                           "The name shows '{}' but the real sender is '{}'. Most mail apps only "
                           "show the name, which is the point of the trick.".format(inner.group(0), addr),
                           str(msg.get("From"))))
    elif from_dom:
        words = set(skeleton(w) for w in re.findall(r"[^\W_]+", display.lower()))
        for brand, domains in data.BRANDS.items():
            if skeleton(brand) in words and registrable(from_dom) not in domains:
                out.append(Finding(40, "email.brand-name-wrong-sender",
                                   "Claims to be {} but sent from {}".format(brand, from_dom),
                                   "Anyone can type any name in the 'From' field. The address "
                                   "behind it is not one {} uses.".format(brand), str(msg.get("From"))))
                break

    reply = [a for _, a in getaddresses([str(v) for v in msg.get_all("Reply-To", [])])]
    for r in reply:
        if from_dom and _domain(r) and registrable(_domain(r)) != registrable(from_dom):
            out.append(Finding(25, "email.reply-elsewhere", "Replies go to a different address",
                               "Hitting 'Reply' would send your answer to '{}', not to the sender "
                               "shown. Scammers do this to receive replies safely.".format(r),
                               "Reply-To: " + r))
            break

    auth = " ".join(str(v) for v in msg.get_all("Authentication-Results", []))
    failed = sorted(set(m.group(1).upper() for m in
                        re.finditer(r"\b(spf|dkim|dmarc)\s*=\s*(?:fail|softfail|permerror)\b", auth, re.I)))
    if failed:
        out.append(Finding(40, "email.auth-failed", "Failed the sender checks: " + ", ".join(failed),
                           "Your mail provider checked whether this email really came from the "
                           "domain it claims, and it did not pass. That is how forged senders look.",
                           auth[:200]))
    return out
