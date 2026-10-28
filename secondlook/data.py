"""Reference data: brands scammers imitate, link shorteners, free hosts, risky endings.

Everything here is plain data so anyone can extend it without touching the logic.
See docs/EXTENDING.md.
"""

# Brand label -> the domains that really belong to it. A link that *looks* like
# one of these labels but is not on this list is what the lookalike check hunts for.
BRANDS = {
    # global
    "paypal": {"paypal.com", "paypal.me"},
    "apple": {"apple.com", "icloud.com", "apple.news"},
    "icloud": {"icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.ae", "amazon.de", "amazon.fr",
               "amazon.in", "amazon.sa", "amazon.ca", "amazon.com.au", "amzn.to"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "outlook": {"outlook.com", "live.com", "office.com"},
    "office365": {"office.com", "microsoft.com"},
    "google": {"google.com", "google.ae", "google.co.uk", "goo.gl", "forms.gle"},
    "gmail": {"gmail.com", "google.com"},
    "facebook": {"facebook.com", "fb.com", "fb.me"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "netflix": {"netflix.com"},
    "spotify": {"spotify.com"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "dhl": {"dhl.com", "dhl.ae", "dhl.de", "dhl.co.uk"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "usps": {"usps.com"},
    "aramex": {"aramex.com"},
    "royalmail": {"royalmail.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "steampowered": {"steampowered.com"},
    "steamcommunity": {"steamcommunity.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "hsbc": {"hsbc.com", "hsbc.ae", "hsbc.co.uk"},
    "barclays": {"barclays.co.uk", "barclays.com"},
    "visa": {"visa.com"},
    "mastercard": {"mastercard.com"},
    # UAE - some of the most imitated names in Gulf scam texts
    "emiratespost": {"emiratespost.ae"},
    "emiratesnbd": {"emiratesnbd.com"},
    "adcb": {"adcb.com"},
    "mashreq": {"mashreq.com", "mashreqbank.com"},
    "etisalat": {"etisalat.ae", "eand.com"},
    "salik": {"salik.ae"},
    "rta": {"rta.ae"},
    "dubaipolice": {"dubaipolice.gov.ae"},
    "emirates": {"emirates.com"},
    "noon": {"noon.com"},
}

# These hide where a link really goes.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "v.gd", "short.io",
    "bl.ink", "lnkd.in", "amzn.to", "qrco.de", "u.to", "clck.ru",
}

# Free site builders and app hosts: legitimate, but a fake login page costs nothing here.
FREE_HOSTS = {
    "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "netlify.app", "vercel.app",
    "github.io", "glitch.me", "herokuapp.com", "weebly.com", "wixsite.com", "webflow.io",
    "000webhostapp.com", "ngrok.io", "ngrok-free.app", "blogspot.com", "sites.google.com",
    "square.site", "godaddysites.com", "repl.co", "onrender.com", "surge.sh",
}

# Domain endings that show up disproportionately in abuse reports. Weak signal on its own.
RISKY_TLDS = {
    "xyz", "top", "icu", "buzz", "click", "link", "live", "shop", "online", "site", "vip",
    "rest", "cfd", "sbs", "bond", "cyou", "monster", "quest", "lol", "work", "support",
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "su",
}

# Endings we accept when a domain is written without http:// ("go to dhl-fee.top").
# Without this list, prose like "e.g." or "file.txt" would look like a link.
BARE_TLDS = RISKY_TLDS | {
    "com", "net", "org", "info", "biz", "io", "co", "me", "app", "dev", "ly", "cc",
    "ae", "uk", "us", "de", "fr", "in", "sa", "qa", "ru", "cn", "to", "gd", "at", "id",
}

# Second-level labels that act like a suffix: amazon.co.uk -> registrable "amazon.co.uk".
SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "ltd", "plc", "sch"}

# Letters and digits that look alike. Folding both sides to this "skeleton" means
# paypa1, rnicrosoft and аpple (Cyrillic а) all collapse onto the real brand name.
CONFUSABLES = {
    # i, l, 1, | and ! are all folded to "l": "1" stands in for either letter.
    "i": "l", "1": "l", "|": "l", "!": "l",
    "0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "$": "s",
    # Cyrillic and Greek letters that render like Latin ones
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "l",
    "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ս": "u",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "l", "κ": "k",
}
# Multi-letter tricks, applied before the single-letter map.
CONFUSABLE_PAIRS = {"rn": "m", "vv": "w", "cl": "d"}

# Brands that are also ordinary words: "visa-application.com" is not pretending to be Visa.
# They still get the lookalike check (v1sa.com), just not the "name used as decoration" one.
COMMON_WORD_BRANDS = {"visa", "chase", "noon", "steam"}
