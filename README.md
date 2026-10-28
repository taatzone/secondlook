# 🔍 Second Look

**Get a second look before you tap.**

Second Look reads a suspicious text message, WhatsApp message or email and tells
you, in plain words, whether it looks like a scam and *why*. Every warning comes
with an explanation, so you learn the tricks instead of only being told to be careful.

```
$ secondlook "Dear Customer, we detected unusual sign-in activity. Your account will be
  suspended unless you verify your account details: http://paypa1.com.account-verify.xyz/login"

  LIKELY SCAM    (score 140, text checked)

  !!! Brand name 'paypal' used as decoration
      The address contains 'paypal' but is really owned by 'account-verify.xyz'.
      The brand name is there to borrow trust.
      seen: http://paypa1.com.account-verify.xyz/login

  !!  Asks you to confirm passwords, card or bank details
      Your bank already has your details. Requests to 'verify' or 'update' them
      through a message are how those details get stolen.

  !!  Says your account is suspended, locked or at risk
      'Your account will be closed' is designed to make you panic and tap before thinking.
  ...
  What to do:
   - Do not tap the links, reply, or call any number in the message.
   - If it claims to be a company, open their app or type their website yourself.
```

[![tests](https://github.com/taatzone/secondlook/actions/workflows/tests.yml/badge.svg)](https://github.com/taatzone/secondlook/actions/workflows/tests.yml)
&nbsp;Python 3.8+ · Windows, macOS, Linux · zero dependencies · MIT

---

## Why this exists

Most people who lose money to scams aren't careless. They were rushed, scared, or
the message looked exactly right. Scams work by triggering emotion before
thinking. Second Look slows that moment down and points at the exact sentence or
link that gives the scam away.

It is the first blade of a personal security Swiss-army knife (see the
[roadmap](#roadmap)), built to protect you and the people you care about.

## Three promises

| | |
|---|---|
| 🔒 **Private by default** | Runs entirely on your computer. Your message is never uploaded anywhere. The test suite *proves* it by blocking the network during a full scan. |
| 🗣️ **Explains itself** | Every finding says what was seen, why scammers do it, and what to do next. |
| 🎯 **Honest** | It never says a message is "safe". The best it will say is *no red flags found*, because new scams appear every day. |

## Quick start

```bash
# install (pipx keeps it tidy; plain pip works too)
pipx install git+https://github.com/taatzone/secondlook

# check a message: quote it, pipe it, or point at a file
secondlook "Your parcel is on hold, pay the 2 AED fee: dhl-fee.top"
pbpaste | secondlook            # macOS clipboard
wl-paste | secondlook           # Linux (Wayland) clipboard
secondlook -f suspicious.eml    # a saved email

# no install at all: clone it and run straight from the folder
git clone https://github.com/taatzone/secondlook && cd secondlook
python -m secondlook "Hi Mum, this is my new number"
```

Run `secondlook` with nothing after it and it will ask you to paste the message.

➡️ **New to the command line?** The [step-by-step tutorial](docs/TUTORIAL.md) walks
you through everything, including setting it up for a parent who has never
opened a terminal.

## What it looks at

| Area | What it catches | Example |
|---|---|---|
| 🔗 **Links** | look-alike spellings, brand names used as decoration, hidden `@` tricks, raw IP addresses, short links, free website builders, risky domain endings | `paypa1.com`, `dhl-redelivery.top`, `paypal.com@evil.top` |
| 🔤 **Look-alike letters** | Cyrillic/Greek letters that look Latin, `rn` posing as `m`, digits for letters | `аpple.com` (that `а` is Cyrillic), `rnicrosoft.com` |
| 💬 **Wording** | requests for one-time codes, gift card or crypto payment, parcel fees, prizes, "Hi Mum" impersonation, fake tech support, secrecy, fines, account threats, easy-money jobs, deadlines | "send me the code I sent by mistake" |
| 📧 **Email** | forged sender names, replies redirected elsewhere, failed SPF/DKIM/DMARC checks, links whose text lies about where they go | text shows `paypal.com` but the link opens `paypal-resolution.web.app` |
| 🌐 **Online** *(opt-in)* | how many days old each website is, and where short links really lead | "Website was created 3 days ago" |

How every check works, how points are scored and why: [How it works](docs/HOW-IT-WORKS.md).
The scams themselves, how to recognise and report them: [Scam field guide](docs/SCAM-FIELD-GUIDE.md).

## Verdicts

| Verdict | Score | Meaning |
|---|---|---|
| 🔴 **LIKELY SCAM** | 60+ | At least one decisive sign, or several strong ones. Don't engage. |
| 🟡 **SUSPICIOUS** | 25–59 | Something's off. Verify through a channel you already trust. |
| 🟢 **NO RED FLAGS FOUND** | under 25 | Nothing known matched. That is **not** the same as safe. |

Exit codes are `0`, `10` and `20` respectively (`2` for usage errors), so scripts and
automations can act on the result. `--json` gives the full report as data.

## `--online`: what leaves your machine

Offline mode sends nothing. With `--online`:

- **domain names only** (e.g. `account-verify.xyz`) go to [rdap.org](https://rdap.org),
  the public registration-date service, to find each site's age;
- **short links** get one `HEAD` request each to the shortener (bit.ly, tinyurl…),
  which answers with the destination. The destination page is never opened.

Your message text never leaves your computer. One caveat: a short link made just for
you can tell the scammer that someone looked at it. If that worries you, stay offline,
which is the default.

## What it can't do

- It reads **patterns**, not intentions. A clever scam with no known tells can pass,
  and an unusual genuine message can be flagged.
- It does not open web pages, scan attachments, or check phone numbers.
- It reads English plus a few Arabic phrases. Other languages: links and email checks
  still work, wording checks mostly won't.
- Brand data covers about 40 common global and UAE brands. Adding more is a one-line
  change: see [Extending](docs/EXTENDING.md).

## Project layout

```
secondlook/
  data.py         brands, shorteners, free hosts, look-alike letters (plain data, easy to extend)
  links.py        finds links and judges each by its address
  language.py     the wording rules: one list, each with its own explanation
  email_check.py  sender, reply-to, SPF/DKIM/DMARC, lying links
  online.py       the opt-in domain-age and short-link lookups
  check.py        runs everything and builds the report
  cli.py          the command and the human-friendly output
examples/         real-shaped scam and genuine messages; every one is a test
tests/            46 tests, standard library only
docs/             tutorial, how it works, scam field guide, extending
```

Run the tests: `python -m unittest discover -s tests -v`

## Roadmap

Second Look is blade #1 of a personal security toolkit:

1. ✅ **Scam checker**: this project
2. ⬜ **File triage**: "is this attachment dangerous?" (capa, FLOSS, YARA-X)
3. ⬜ **Stalkerware check** for family phones (MVT, stalkerware indicators)
4. ⬜ **Breach watch**: leaked passwords and accounts (Have I Been Pwned, k-anonymity)
5. ⬜ **Home network watchdog**: "who's on my Wi-Fi?" and DNS blocklists
6. ⬜ **Tracker detection**: AirTags and BLE trackers following you
7. ⬜ **Tripwires**: canary tokens that alert on intrusion
8. ⬜ **Weekly family report**

## Credits and inspiration

The privacy-first, honest-about-limits design is inspired by
[zero-breach](https://github.com/interplains/zero-breach). Scam patterns follow
public consumer-protection guidance from bodies such as the US FTC, the UK NCSC and
UAE police cybercrime units.

## License

MIT. See [LICENSE](LICENSE). Use it, share it, install it on your parents' laptop.
