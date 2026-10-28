"""Read the words of a message for the pressure tactics scams are built from.

Each rule is (points, id, title, why, patterns). A rule fires at most once,
however many of its patterns match. Patterns are case-insensitive regexes.
"""
from __future__ import annotations

import re

from .findings import Finding

RULES = [
    (50, "ask.code", "Asks you to share a one-time code",
     "This is the number one way accounts get stolen. The code was sent to YOU to prove it's "
     "you. No real company, friend or 'support agent' ever needs it read back.",
     [r"\b(send|tell|share|forward|give|read|text)\b.{0,25}\b(code|otp|pin|passcode)\b",
      r"\bcode\b.{0,20}\b(i|we)\b.{0,10}\b(just )?(sent|texted)\b",
      r"\b(sent|texted) (you )?a (6|six|4|four)[- ]digit code\b.{0,40}\b(by mistake|accident)"]),
    (40, "pay.untraceable", "Wants payment by gift card, crypto or money transfer",
     "Gift cards, crypto and wire transfers can't be reversed or traced. That is exactly why "
     "scammers ask for them and real businesses don't.",
     [r"\bgift ?cards?\b", r"\b(itunes|google play|steam|apple|amazon) (card|voucher)s?\b",
      r"\b(bitcoin|btc|usdt|tether|crypto(currency)?|ethereum)\b",
      r"\b(western union|moneygram|wire transfer)\b"]),
    (35, "bait.delivery", "Parcel problem that needs a small fee or your details",
     "Fake 'your parcel is on hold' texts are the most common scam SMS worldwide. The small "
     "fee is bait to capture your full card details.",
     [r"\b(delivery|shipping|redelivery|customs|handling|postage) (fee|charge|payment|cost)\b",
      r"\b(parcel|package|shipment)\b.{0,40}\b(on hold|held|could ?n[o']t be delivered|failed|"
      r"suspended|returned|pending)\b",
      r"\b(update|confirm)\b.{0,15}\b(delivery|shipping) (address|details|information)\b"]),
    (35, "bait.prize", "Says you won something you never entered",
     "You cannot win a lottery or giveaway you never entered. The 'prize' leads to a fee or a "
     "form that collects your details.",
     [r"\byou('ve| have)? (won|been selected)\b", r"\bclaim (your )?(prize|reward|gift|winnings)\b",
      r"\b(lottery|jackpot|lucky (draw|winner))\b"]),
    (35, "impersonate.family", "Someone claiming to be family on a new number",
     "'Hi Mum, this is my new number' is a well-known scam. Call your relative on the number "
     "you already have before doing anything.",
     [r"\bhi,? (mum|mom|mam|dad|mama|papa)\b", r"\b(this is|it'?s) my new (number|phone)\b",
      r"\b(lost|broke|dropped) my phone\b", r"\bnew number\b.{0,40}\b(save|delete the old)\b"]),
    (35, "impersonate.tech-support", "Says your device is infected and you must call",
     "Microsoft, Apple and your bank never contact you out of the blue about viruses. The "
     "'support' line is the scammer, and they will ask to control your computer.",
     [r"\byour (computer|device|pc|phone|mac|iphone) (is|has been|was) (infected|hacked|"
      r"compromised|locked)\b", r"\b(call|contact) (microsoft|apple|windows|norton|mcafee) "
      r"(support|helpdesk|technician)s?\b", r"\bvirus(es)? (detected|found)\b"]),
    (35, "bait.investment", "Promises guaranteed or doubled returns",
     "Real investments never guarantee profit. 'Guaranteed returns' and 'double your money' "
     "are the hook of investment and crypto scams.",
     [r"\bguaranteed (profit|returns?|income)\b", r"\bdouble your (money|investment|bitcoin)\b",
      r"\b(\d{2,3})% (profit|return)s? (daily|weekly|in \d+ days)\b"]),
    (30, "ask.credentials", "Asks you to confirm passwords, card or bank details",
     "Your bank already has your details. Requests to 'verify' or 'update' them through a "
     "message are how those details get stolen.",
     [r"\b(confirm|verify|update|validate|re-?enter)\b.{0,20}\b(password|card|bank|billing|"
      r"payment|account) ?(details|information|info|number)?\b",
      r"\b(cvv|card number|pin number|security code)\b"]),
    (30, "pressure.secrecy", "Asks you to keep it secret",
     "Scammers isolate people so nobody can warn them. A request to keep a payment from your "
     "family is a giant red flag.",
     [r"\b(don'?t|do not) tell (anyone|anybody|(your )?(family|bank|husband|wife|kids|children|"
      r"mum|mom|dad|parents|brother|sister))\b",
      r"\bkeep (this|it) (between us|confidential|secret|private)\b"]),
    (30, "pressure.fine", "Threatens an unpaid fine, toll or tax",
     "Fake toll, parking and tax messages push you to 'pay now to avoid a penalty'. Pay "
     "official fines only through the official app or website you type in yourself.",
     [r"\bunpaid (toll|fine|parking|traffic|tax|bill|invoice)\b", r"\b(salik|toll) (balance|fee|charge)\b",
      r"\b(avoid|face) (a )?(penalty|penalties|late fee|legal action|arrest)\b",
      r"\btax refund\b", r"\b(eligible|entitled) (for|to) a refund\b"]),
    (25, "pressure.account", "Says your account is suspended, locked or at risk",
     "'Your account will be closed' is designed to make you panic and tap before thinking.",
     [r"\baccount\b.{0,30}\b(suspended|locked|limited|blocked|closed|disabled|deactivated|"
      r"restricted|on hold)\b", r"\bunusual (sign-?in|login|activity)\b",
      r"\b(suspicious|unauthori[sz]ed) (activity|transaction|login|access)\b",
      r"تم (تعليق|إيقاف|ايقاف) حسابك"]),
    (25, "bait.job", "Easy money job offer",
     "Jobs that pay a lot for 'liking videos' or 'simple tasks' end with you paying a "
     "'deposit' to unlock earnings that never come.",
     [r"\b(part[- ]time|work from home|remote) (job|work|opportunity)\b.{0,80}\b(earn|salary|pay)\b",
      r"\bearn\b.{0,15}(\$|aed|£|€)?\s?\d+.{0,10}\b(per|a|each) (day|hour)\b",
      r"\b(like|rate) (videos|products|posts)\b.{0,40}\b(earn|paid|commission)\b"]),
    (15, "pressure.urgency", "Rushes you with a deadline",
     "A ticking clock stops you from checking. Real organisations give you time.",
     [r"\bwithin (\d+|twenty[- ]four|one|two) ?(hours?|hrs?|minutes?|mins?)\b", r"\burgent(ly)?\b",
      r"\b(final|last) (notice|warning|reminder|chance)\b", r"\bact (now|immediately|fast)\b",
      r"\b(expires?|expiring) (today|tonight|soon)\b", r"\bimmediately\b", r"عاجل"]),
    (5, "generic.greeting", "Greets you as 'dear customer' instead of by name",
     "Mass scams don't know your name. Weak on its own, since some real notices do this too.",
     [r"\bdear (customer|user|client|member|sir|madam|account ?holder|valued)\b"]),
]

_COMPILED = [(p, i, t, w, [re.compile(x, re.I | re.S) for x in pats])
             for p, i, t, w, pats in RULES]

# A link plus one of these is the textbook phishing shape: scare you, then hand you the exit.
_PHISH_TRIGGERS = {"bait.delivery", "pressure.account", "ask.credentials", "pressure.fine",
                   "bait.prize"}


def check_text(text, has_link=False):
    out = []
    for points, rid, title, why, pats in _COMPILED:
        for pat in pats:
            m = pat.search(text)
            if m:
                out.append(Finding(points, rid, title, why, _snippet(text, m)))
                break
    if has_link and any(f.check in _PHISH_TRIGGERS for f in out):
        out.append(Finding(15, "combo.pressure-plus-link", "Pressure plus a link to tap",
                           "Scare first, then offer a link as the way out: that is the shape of "
                           "almost every phishing message.", ""))
    return out


def _snippet(text, m, pad=25):
    a, b = max(0, m.start() - pad), min(len(text), m.end() + pad)
    s = " ".join(text[a:b].split())
    return ("…" if a else "") + s + ("…" if b < len(text) else "")
