# Tutorial: from zero to checking your first scam

This guide assumes you have never used a terminal. Each lesson takes about five
minutes. If you already know Python, skip to [Lesson 2](#lesson-2-your-first-check).

- [Lesson 1: Install](#lesson-1-install)
- [Lesson 2: Your first check](#lesson-2-your-first-check)
- [Lesson 3: Reading the report](#lesson-3-reading-the-report)
- [Lesson 4: Checking an email properly](#lesson-4-checking-an-email-properly)
- [Lesson 5: Going online, carefully](#lesson-5-going-online-carefully)
- [Lesson 6: Set it up for a parent](#lesson-6-set-it-up-for-a-parent)
- [Lesson 7: Automate it](#lesson-7-automate-it)
- [Practice: spot the scam](#practice-spot-the-scam)

---

## Lesson 1: Install

**1. Get Python 3.8 or newer.**

| System | How |
|---|---|
| Windows | Install from [python.org/downloads](https://www.python.org/downloads/) and **tick "Add python.exe to PATH"** on the first screen. |
| macOS | `brew install python`, or the installer from python.org. |
| Linux | Already installed on nearly every distribution. Check with `python3 --version`. |

**2. Open a terminal.** Windows: press Start, type *Terminal*. macOS: Spotlight,
type *Terminal*. Linux: you know where it is. 🙂

**3. Install Second Look.**

```bash
python -m pip install --user pipx
python -m pipx ensurepath          # then close and reopen the terminal
pipx install git+https://github.com/taatzone/secondlook
```

**4. Check it works.**

```bash
secondlook --version
# secondlook 0.1.0
```

> **No internet on that machine, or prefer not to install?** Download the ZIP from
> GitHub, unzip it, open a terminal in that folder and use `python -m secondlook`
> wherever this guide says `secondlook`.

---

## Lesson 2: Your first check

There are four ways to give it a message. Pick whichever is easiest.

**a) Type or paste it after the command, inside quotes:**
```bash
secondlook "Your package could not be delivered. Pay 3 AED: emiratespost-ae.top"
```
> Tip: if the message contains a `"` itself, use single quotes `'...'` around it instead.

**b) Let it ask you.** Run `secondlook` on its own, paste, then press
`Ctrl-D` (macOS/Linux) or `Ctrl-Z` then `Enter` (Windows).

**c) Straight from the clipboard.** Copy the message on your computer, then:
```bash
pbpaste | secondlook                  # macOS
wl-paste | secondlook                 # Linux, Wayland
xclip -o -sel clip | secondlook       # Linux, X11
Get-Clipboard | secondlook            # Windows PowerShell
```

**d) From a file:**
```bash
secondlook -f message.txt
```

Try the examples that ship with the project:

```bash
secondlook -f examples/scam-hi-mum.txt
secondlook -f examples/genuine-friend.txt
```

---

## Lesson 3: Reading the report

```
  LIKELY SCAM    (score 65, text checked)        ← the verdict and why

  !!! Asks you to share a one-time code          ← what was found (!!! = strong)
      This is the number one way accounts get    ← why scammers do it
      stolen...
      seen: …Can you send me the code please?…   ← the exact words that triggered it

  What to do:                                    ← concrete next steps
   - Do not tap the links, reply, or call...
```

- `!!!` is a **strong** signal (40+ points). One of these alone is usually decisive.
- `!!` is **medium** (20–39). Suspicious, more so in company.
- `!` is **weak** (under 20). Context only, never a verdict by itself.

The score is simply the sum. **60+** is *likely scam*, **25–59** is *suspicious*,
below that is *no red flags found*.

> ⚠️ "No red flags found" means *we didn't recognise a trick*, not *this is safe*. If a
> message asks for money, a code or a password, verify it another way regardless.

---

## Lesson 4: Checking an email properly

Pasting just the text of an email works, but you lose the best evidence: the hidden
**headers** that say who really sent it, and the real addresses behind the links.
Save the whole email as a `.eml` file instead:

| Mail app | How to save the original |
|---|---|
| **Gmail (web)** | Open the email → ⋮ (three dots) → **Download message** |
| **Outlook (web)** | Open → ⋯ → **Save** / **Download** (saves `.eml`) |
| **Outlook (desktop)** | Drag the email to your desktop, or **File → Save As** |
| **Apple Mail** | Select → **File → Save As…** → format *Raw Message Source* |
| **Thunderbird** | Select → **File → Save As → File** |

Then:

```bash
secondlook -f "Action required.eml"
```

What the email checks add (try `examples/scam-phishing.eml`):

- **"Sender name contains a different email address"**: the From name says
  `service@paypal.com`, the real address is `billing@secure-paypal-billing.top`.
- **"A link shows one address but opens another"**: the text reads
  `https://www.paypal.com/resolution`, the click goes to `paypal-resolution.web.app`.
- **"Failed the sender checks"**: your mail provider already tested the sender and it
  failed. Second Look reads that verdict from the headers.
- **"Replies go to a different address"**: hitting Reply would mail a Gmail account.

> Saving an email is safe. A `.eml` file is plain text, and Second Look never opens
> attachments or links in it.

---

## Lesson 5: Going online, carefully

```bash
secondlook --online "Claim your refund: https://bit.ly/xyz"
```

This adds two things:

1. **Website age.** Scam sites are usually days or weeks old. *"Website was created 3
   days ago"* is a powerful warning.
2. **Short-link unwrapping.** It asks the shortener where the link goes, then judges
   the *real* destination with all the link checks. The destination is never visited.

**What it sends:** domain names to rdap.org, and short links to their shortener.
**Never** your message. Read [the privacy note](../README.md#--online-what-leaves-your-machine)
for the one caveat.

---

## Lesson 6: Set it up for a parent

The goal: they forward or copy a message, double-click one thing, and read a verdict.

### Linux: a desktop launcher that checks the clipboard

```bash
mkdir -p ~/.local/share/applications
cat > ~/.local/share/applications/secondlook.desktop <<'EOF'
[Desktop Entry]
Name=Check copied message
Comment=Second Look: is the copied message a scam?
Exec=sh -c 'wl-paste | secondlook --no-color; echo; read -p "Press Enter to close" x'
Terminal=true
Type=Application
Icon=security-high
EOF
```

It now appears in the app launcher as **Check copied message**. They copy the
suspicious text, click it, read the result.

### Windows: a desktop shortcut

Create `Check message.bat` on the desktop:

```bat
@echo off
powershell -NoProfile -Command "Get-Clipboard | secondlook --no-color"
echo.
pause
```

### macOS: a Shortcut or a command file

Create `Check message.command` on the desktop, then run `chmod +x` on it once:

```bash
#!/bin/bash
pbpaste | secondlook --no-color
read -p "Press Enter to close"
```

### The most important part isn't software

Sit down with them and run the [practice round](#practice-spot-the-scam) together.
Agree on a **family password**: a word that anyone claiming to be family, from a
new number, must say. It defeats the "Hi Mum" scam and voice-cloning calls
completely, and it costs nothing.

---

## Lesson 7: Automate it

The exit code tells scripts the verdict: `0` none, `10` suspicious, `20` likely scam.

```bash
# warn loudly only on likely scams
secondlook -f msg.txt > /dev/null; [ $? -eq 20 ] && notify-send "⚠️ Likely scam"

# check every saved email in a folder
for f in ~/Downloads/*.eml; do
  secondlook --json -f "$f" | python3 -c \
    "import json,sys; r=json.load(sys.stdin); print(r['verdict'].ljust(14), sys.argv[1])" "$f"
done
```

The JSON report contains `verdict`, `score`, `links`, `findings` (each with
`points`, `check`, `title`, `why`, `evidence`) and `notes`.

---

## Practice: spot the scam

Guess first, then check with Second Look. Answers are below.

1. `Your Salik account has an unpaid toll balance of AED 50. Pay within 24 hours to avoid a penalty: salik-ae.cfd/pay`
2. `Hi, it's Sara from the dentist. Just confirming your appointment Monday at 10. Reply C to confirm.`
3. `Apple: your iCloud storage is full. Upgrade at https://www.apple.com/icloud/`
4. `Dad my phone fell in the water this is my new number, can you send 2000 to my friend's account, I'll pay back tomorrow. Don't tell mum`
5. `Your Netflix payment failed. Update your billing information: https://netflix.account-help.live`

<details>
<summary>Answers</summary>

1. **Scam.** Salik's real site is `salik.ae`. This uses the name on a `.cfd` domain,
   with an unpaid toll, a deadline and a penalty threat.
2. **Probably genuine.** No link, no money, no code, nothing secret. If unsure, call
   the dentist on the number you already have.
3. **Probably genuine.** The link is the real `apple.com`. Still, the safest habit is
   to open the Settings app rather than tap.
4. **Scam.** A new number, an emergency, money to "a friend's account", and secrecy.
   Call your child on their old number.
5. **Scam.** `netflix` is decoration on `account-help.live`, plus a billing request.

</details>
