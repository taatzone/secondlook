# How it works

Second Look is about 800 lines of plain Python with no dependencies. This page
explains every check: what it looks for, why scammers do it, and how much it counts.

```
            message (text or .eml)
                     │
         ┌───────────┴────────────┐
   email? │                       │ text
         ▼                        │
  email_check.py                  │
  sender, reply-to, SPF/DKIM,     │
  lying links, HTML → text        │
         └───────────┬────────────┘
                     ▼
              links.find_urls  ──(--online)──▶ online.unshorten
                     │                          (judge the real destination too)
          ┌──────────┴──────────┐
          ▼                     ▼
   links.check_url       language.check_text
   (each address)        (the words)
          └──────────┬──────────┘
                     ▼ (--online)
             online.check_age (each unknown domain)
                     ▼
        findings → score → verdict → report
```

## Scoring

Every finding carries **points**: how strongly it suggests a scam.

| Points | Strength | Examples |
|---|---|---|
| 40–60 | decisive | look-alike domain, request for a one-time code, forged sender |
| 20–39 | strong | parcel fee, account threat, short link, secrecy |
| 5–19 | context | risky ending, deadline, "dear customer" |

The verdict is the **sum**: 60+ is *likely scam*, 25+ is *suspicious*, otherwise
*no red flags found*. Thresholds live in `findings.py`.

Why a sum and not machine learning? Because every point can be **explained**. A
person can see exactly which three things added up, learn them, and recognise them
next time without the tool. That matters more here than a few percent of accuracy.

Each rule fires **once** per message, and identical findings are de-duplicated, so
a message can't become "more scammy" by repeating the word *urgent* ten times.

---

## Link checks (`links.py`)

### Finding the links

Three shapes are recognised: `https://…`, `www.…`, and **bare domains** like
`dhl-fee.top/pay`, which scam texts love because they skip the `https://`. A bare
word is only treated as a link if its ending is on a known list (`BARE_TLDS`),
otherwise prose such as "e.g." and "file.txt" would be mistaken for links.

### Who owns this address?

The most important skill in link safety is reading **the registrable domain**: the
part someone actually bought. It is the last two labels, read *right to left*:

```
https://paypal.com.account-verify.xyz/login
        └───decoration───┘└─owner──────┘
```

`registrable()` does this, handling `.co.uk`-style endings and free hosts, where
every site (`yourname.web.app`) counts as its own owner.

### The brand checks, in order

For a domain that isn't on a brand's official list (`data.BRANDS`):

| Check | Points | Catches |
|---|---|---|
| `link.brand-wrong-domain` | 30 | the exact brand name on another ending, e.g. `paypal.help` |
| `link.lookalike` | 60 | `paypa1.com`, `rnicrosoft.com`, `аpple.com`, `amazom.com` |
| `link.brand-decoy` | 45 | the brand appears as decoration: `dhl-redelivery.top`, `paypal.com.secure.xyz` |

### The skeleton trick

How do you spot `paypa1`, `rnicrosoft` and `аpple` (with a Cyrillic `а`) with one rule?
Fold both strings to a **skeleton**, where every look-alike collapses to a single form:

```
rn → m     vv → w     cl → d
0 → o      3 → e      5 → s      $ → s
i, l, 1, |, ! → l          (they're interchangeable in most fonts)
а (Cyrillic) → a   ο (Greek) → o   ...
```

```
skeleton("paypa1")     = "paypal"  = skeleton("paypal")     ✔ lookalike
skeleton("rnicrosoft") = "mlcrosoft" = skeleton("microsoft") ✔ lookalike
```

Brands of six letters or more also match at **one typo** (edit distance 1):
`amazom`, `googel`. Shorter brands don't, because `ups` → `ops` is just another word.

Some brands are ordinary words (`visa`, `chase`, `noon`, `steam`). They keep the
look-alike check but skip the decoy check, so `uae-visa-application.com` isn't
accused of impersonating Visa.

### The other link checks

| Check | Points | Why |
|---|---|---|
| `link.userinfo-trick` | 50 | In `https://paypal.com@evil.top`, everything before `@` is a *username* and ignored. You land on `evil.top`. |
| `link.ip-address` | 35 | `http://203.0.113.9/login`: real services have names. |
| `link.foreign-letters` | 25 | non-Latin letters in an address that isn't a known brand lookalike |
| `link.shortener` | 20 | the real destination is hidden (`--online` unwraps it) |
| `link.free-host` | 15 | fake login pages are free to build on site builders |
| `link.risky-ending` | 10 | endings such as `.top`, `.xyz`, `.cfd` that dominate abuse reports |
| `link.bait-words` | 10 | `login`, `verify`, `secure`… in an unknown address |
| `link.deep-subdomains` | 10 | five or more labels push the real owner out of sight |

Official domains of known brands skip everything except the shortener and free-host
checks, so a genuine Amazon or bank link stays quiet.

---

## Wording checks (`language.py`)

One list, `RULES`. Each rule has points, an id, a title, an explanation and a few
regular expressions. Highlights:

| Rule | Points | The trick |
|---|---|---|
| `ask.code` | 50 | "Send me the code I sent by mistake." The code is your account's key. |
| `pay.untraceable` | 40 | gift cards, crypto, Western Union: irreversible by design |
| `bait.delivery` | 35 | the "parcel on hold, small fee" SMS, the world's most common scam text |
| `bait.prize` | 35 | you won a lottery you never entered |
| `impersonate.family` | 35 | "Hi Mum, this is my new number" |
| `impersonate.tech-support` | 35 | "your computer is infected, call Microsoft" |
| `bait.investment` | 35 | guaranteed or doubled returns |
| `ask.credentials` | 30 | "verify your card details" |
| `pressure.secrecy` | 30 | "don't tell anyone" |
| `pressure.fine` | 30 | unpaid toll, fine or tax, "avoid a penalty" |
| `pressure.account` | 25 | "your account is suspended" (also in Arabic) |
| `bait.job` | 25 | "earn 500 a day liking videos" |
| `pressure.urgency` | 15 | deadlines, "urgent", "final notice" (also in Arabic) |
| `generic.greeting` | 5 | "Dear customer" |

**The combo rule.** If a message has *pressure* (account threat, fee, fine, prize,
credentials request) **and** a link, it earns an extra 15 points
(`combo.pressure-plus-link`): scare first, then offer the exit. That shape is almost
every phishing message ever sent.

**False positives are tested too.** `tests/test_language.py` checks that everyday
messages ("I paid the bill by bank transfer", "your locker code is on the fridge")
stay quiet.

---

## Email checks (`email_check.py`)

A message is treated as an email if it starts with headers (`From:`, `Received:`…).
Python's standard `email` package parses it. HTML parts are turned into text (scripts
and styles dropped), and every `<a href>` is collected along with the text it shows.

| Check | Points | What it reads |
|---|---|---|
| `email.link-mismatch` | 45 | link text shows `www.paypal.com` but `href` goes elsewhere |
| `email.fake-display-address` | 45 | `"service@paypal.com" <x@evil.top>`: the *name* is an address |
| `email.brand-name-wrong-sender` | 40 | `PayPal Security <x@evil.top>` |
| `email.auth-failed` | 40 | `Authentication-Results` shows SPF, DKIM or DMARC failing |
| `email.reply-elsewhere` | 25 | `Reply-To` points to a different domain |

**About SPF, DKIM and DMARC.** When an email arrives, your provider asks the claimed
sender's domain: *"Is this server allowed to send for you? Is this signature yours?"*
The answers are written into the `Authentication-Results` header. Second Look
doesn't redo those checks. It reads what your provider already found, which is more
reliable because the provider saw the connection.

The email's body and links then go through the same link and wording checks as a
text message.

---

## Online checks (`online.py`, only with `--online`)

**Domain age.** For each domain that isn't a known brand or shortener, it asks
[RDAP](https://about.rdap.org/) (the modern, JSON replacement for WHOIS) for the
registration date:

| Age | Finding | Points |
|---|---|---|
| under 30 days | `online.new-domain` | 40 |
| under 180 days | `online.young-domain` | 15 |

Lookup failures (no internet, an unregistered domain, a registry that doesn't publish
dates) become **notes**, never errors, and never a "clean" signal.

**Short links.** For bit.ly, tinyurl and friends it sends a `HEAD` request with
redirects *switched off*, reads the `Location` header, and repeats (up to 5 hops)
until it leaves the shortener. Only the shortener is contacted. The final page is
judged by its address alone.

---

## Guarantees the tests enforce

- **Offline means offline.** `test_every_example_offline` replaces Python's socket
  functions with ones that fail the test, then scans every example.
- **Examples are truthful.** Every `examples/scam-*` must be *likely scam*, and every
  `examples/genuine-*` must have *no red flags*.
- **The tutorial is truthful.** The practice answers in `TUTORIAL.md` are a test.
- **Never says "safe".** Asserted on the output.
