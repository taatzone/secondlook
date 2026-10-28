# Scam field guide

Software helps, but the best defence is knowing the handful of tricks that nearly
every scam is built from. Read this once, share it with your family, and you'll
spot most scams before any tool does.

## The five golden rules

1. **Codes are keys.** Never share a one-time code (OTP), not with your bank, not
   with "support", not with a friend. The code proves *you* are you.
2. **Urgency is a weapon.** "Within 24 hours", "final notice", "your account will be
   closed". Real organisations give you time. The rush is the scam.
3. **Go around, not through.** Never use the link, number or reply in a suspicious
   message. Open the official app, or type the website, or call the number on your card.
4. **Weird payment = scam.** Gift cards, crypto, wire transfers to strangers: nobody
   legitimate asks for these.
5. **Secrecy is a red flag.** "Don't tell anyone" exists to stop someone warning you.

---

## The scams, one by one

### 📦 The parcel fee
> *"Your package is on hold due to an incomplete address. Pay 3.50 AED to reschedule."*

**The trick:** the fee is tiny so you don't think twice. The page captures your full
card details, which are then used for big purchases. **Tells:** a courier name on a
strange domain (`emiratespost-ae.top`, `dhl-redelivery.live`), a small fee, a deadline.
**Do:** track the parcel in the courier's own app with the tracking number from the shop.

### 👪 "Hi Mum / Hi Dad"
> *"Hi Mum, I dropped my phone, this is my new number. Can you help me pay a bill? Don't tell Dad."*

**The trick:** emotion and urgency, from a number you don't know, and soon an AI-cloned
voice too. **Tells:** a new number, an emergency, money to "a friend's account", secrecy.
**Do:** call your child on their **old** number. Agree on a **family password** today.

### 🔢 The code "sent by mistake"
> *"Sorry, I sent a 6-digit code to you by mistake, can you forward it?"*

**The trick:** they're logging into *your* WhatsApp, email or bank, and the code
went to you. Sharing it hands over the account. Often sent from a hacked friend's account.
**Do:** never forward codes. Turn on two-step verification in WhatsApp (Settings →
Account → Two-step verification).

### 🏦 The account lockout
> *"Unusual sign-in detected. Your account will be suspended. Verify now: [link]"*

**The trick:** panic, then a perfect copy of the login page. **Tells:** a look-alike
address (`paypa1.com`, `paypal.com.verify-account.xyz`), "Dear customer", a deadline.
**Do:** open the real app. If there's a real problem, it'll show there.

### 🚗 Fines, tolls and taxes
> *"You have an unpaid Salik toll of AED 50. Pay within 24h to avoid a penalty."*

**The trick:** the authority of a government name plus fear of a penalty.
**Do:** check fines only in the official app or site that you type in yourself
(e.g. `salik.ae`, `rta.ae`, `dubaipolice.gov.ae`).

### 🎁 You've won!
**The trick:** a prize for a draw you never entered, unlocked by a "processing fee" or
your details. **Rule:** you can't win what you didn't enter.

### 💼 The easy job
> *"Part-time remote job: earn 500 AED/day liking videos."*

**The trick:** small real payouts build trust, then you must "deposit" crypto to unlock
bigger tasks, and that money is gone. **Rule:** a job never asks *you* to pay.

### 📈 Guaranteed returns
**The trick:** fake trading dashboards show growing "profits" until you try to withdraw.
Often starts as a friendly wrong-number chat or romance. **Rule:** guaranteed returns
don't exist.

### 💻 Fake tech support
> *"Your computer is infected! Call Microsoft support now."*

**The trick:** they ask you to install a remote-control app, then "find" problems and
charge, or empty your bank while connected. **Rule:** Microsoft and Apple never call or
pop up asking you to phone them.

### 📧 The forged email
**The trick:** a display name of `PayPal` or even `service@paypal.com` over a random
real address, and a link whose *text* shows the real site while the *link* goes
elsewhere. **Do:** hover over (or long-press) links to see where they really go, or
let Second Look read the `.eml` file.

---

## Reading a web address in 5 seconds

Find the **first single slash** after `://`, then read **leftwards** to the second dot
from the end. That's the owner.

```
https://www.amazon.ae/orders              → amazon.ae            ✔
https://amazon.ae.orders-check.top/login  → orders-check.top     ✘
https://paypal.com@login-help.site/       → login-help.site      ✘  (everything before @ is ignored)
https://аpple.com                         → ?? look-alike letters ✘  (Second Look catches these)
```

---

## If you've already clicked or paid

Don't be embarrassed: these are made by professionals, and speed matters more than pride.

1. **Card details entered?** Call your bank on the number on the back of your card
   and freeze it.
2. **Password entered?** Change it on the real site, and anywhere else you reused it.
   Turn on two-step verification.
3. **Code shared?** Sign out of all devices (the account's security settings) and
   change the password.
4. **Installed an app because someone asked?** Disconnect from the internet,
   uninstall it, and have the device checked.
5. **Report it** (see below), even if you lost nothing. Reports shut sites down.

## Where to report

| Country | Where |
|---|---|
| 🇦🇪 UAE | Dubai Police eCrime platform (`ecrime.ae`), Abu Dhabi Police *Aman* service, or 999 in an emergency. Report fraud on your account to your bank first. |
| 🇬🇧 UK | Forward scam texts to **7726** (free). Emails to `report@phishing.gov.uk`. Fraud: Action Fraud. |
| 🇺🇸 US | `reportfraud.ftc.gov`. Forward scam texts to **7726** (SPAM). |
| 🇪🇺 EU | Your national police cybercrime unit or consumer protection centre. |
| Everywhere | Report the message as spam/junk in WhatsApp, Gmail or Outlook. It trains their filters. |

*Contact details change; check the official site of each body before relying on them.*
