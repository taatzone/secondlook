# Extending Second Look

Most improvements are **data**, not code. Each recipe below is a few lines plus a test.

## Add a brand

In `secondlook/data.py`, add the brand's name and its **real** domains:

```python
BRANDS = {
    ...
    "careem": {"careem.com"},
}
```

That alone switches on the look-alike (`car33m.com`), decoy (`careem-refund.top`) and
wrong-ending (`careem.help`) checks, plus email sender-name checks. If the brand name
is also an everyday word, add it to `COMMON_WORD_BRANDS` so it skips the decoy check.

## Add a scam pattern

In `secondlook/language.py`, add a tuple to `RULES`:

```python
(35, "bait.visa-renewal", "Fake visa or Emirates ID renewal",
 "Renewals are done in the official ICP or GDRFA apps. A message with a payment "
 "link for your visa is a copy.",
 [r"\b(visa|emirates id)\b.{0,30}\b(expired|expiring|renewal)\b.{0,40}\b(pay|fee)\b"]),
```

- **Points:** 40+ only for something real organisations *never* do. Most rules sit
  at 20–35. Context-only signals stay under 20.
- **Id:** `category.name`. Categories in use: `ask`, `pay`, `bait`, `impersonate`,
  `pressure`, `generic`.
- **Explanation:** written for a 70-year-old: what the trick is, why it works.
- **Patterns:** case-insensitive regexes. Use `\b` word boundaries and `.{0,30}` gaps.
  Any language works (see the Arabic ones).

## Add a shortener, free host or risky ending

Add to `SHORTENERS`, `FREE_HOSTS` or `RISKY_TLDS` in `data.py`. If a new ending should
also be recognised without `https://`, it's covered automatically: `BARE_TLDS`
includes `RISKY_TLDS`.

## Add an example (the best kind of contribution)

Real scams make the best tests. Drop the message into `examples/`:

- `examples/scam-<what>.txt` must come out as **likely scam**;
- `examples/genuine-<what>.txt` must come out as **no red flags**.

`tests/test_end_to_end.py` picks them up automatically. **Remove personal details**
(names, numbers, tracking codes) before committing a real message.

## Run the tests

```bash
python -m unittest discover -s tests -v
```

No dependencies to install. CI runs the same command on Windows, macOS and Linux
with Python 3.8, 3.12 and 3.13.

## Design rules

1. **Offline by default.** Anything that touches the network goes in `online.py`
   behind `--online`, and must send only what it needs (never message text).
2. **Every finding explains itself.** No points without a `why` a non-expert can follow.
3. **Never say safe.** The best verdict is *no red flags found*.
4. **No dependencies.** The people who need this most shouldn't need to install anything.
5. **False positives are bugs.** A tool that cries wolf gets ignored. Add a genuine
   example whenever you tighten a rule.
