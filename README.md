# Payment Phish Guard

Scam and phishing detection built around how Indian digital-payment fraud actually reaches people. It checks:
- SMS and WhatsApp messages
- links
- UPI payment links, QR codes and UPI IDs
- fake bank and KYC apps sent as APK files
- cloned net-banking pages

You can use it from a web page, a browser extension, an HTTP API or the command line. Every verdict says **why**, in plain language, along with what to do next.

| Input | What is checked |
|---|---|
| **Link** | Look-alike bank domains (typos, digit swaps, `rn`→`m`), Cyrillic and Unicode homoglyphs (punycode decoded), brand name on someone else's domain, `@` tricks, raw IPs, shorteners, free hosting and tunnels used by phishing kits, abused TLDs, APK downloads, lure words. Plus a gradient-boosted model over 25 link features. |
| **UPI link / QR** | The "you will receive a refund" story attached to a link that *takes* money, collect and mandate requests, an institution name with no merchant code, an institution name on a personal mobile-number UPI ID, unknown PSP handles, malformed amounts and currencies |
| **UPI ID** | Validity, a known bank/PSP handle, a brand name or "refund/kyc/support" in a personal ID |
| **Message** | 14 scam patterns (OTP/PIN requests, block/suspend threats, KYC/PAN/Aadhaar, electricity disconnection, parcel/customs, task-job, instant loan, remote-access app install, police/"digital arrest", family on a new number...), a TF-IDF classifier, and every link, UPI link, UPI ID and phone number inside it scored on its own |
| **APK** | A built-in parser for the binary `AndroidManifest.xml` (no Android SDK needed), and the signing certificate from v1 (PKCS#7) or v2/v3 (APK Signing Block). It flags package names imitating a bank, SMS interception, accessibility-service abuse, overlays, notification snooping, call forwarding, device admin, debug signing, and the full banking-trojan combination. If you add official certificate fingerprints, repackaged copies of real apps are caught outright. |
| **Web page** | Forms asking for password, OTP, card, **UPI PIN** or Aadhaar/PAN, bank branding on a foreign domain, form posts to other sites, Telegram-bot and webhook exfiltration, obfuscated JS, right-click/devtools blocking, hidden iframes, logos hot-linked from the real bank, meta-refresh redirects |

## Examples

```
$ python -m phishguard check "upi://pay?pa=9876543210@ybl&pn=SBI%20Refund%20Desk&am=4999&tn=Refund%20receive%20now"
DANGEROUS  risk 88/100  (upi)
  +3.5  the note promises money ('Refund'), but this link takes money: you never enter a UPI PIN to receive
  +3.0  payee claims to be 'SBI Refund Desk' but the UPI ID is a personal mobile number
  +2.0  payee name 'SBI Refund Desk' claims to be an institution but the link has no merchant code

Entering your UPI PIN always sends money out of your account. Nobody needs your PIN to pay you.
```

```
$ python -m phishguard check "Dear customer your SBI account will be blocked today. Update KYC immediately https://sbi-kyc-update.xyz/login"
DANGEROUS  risk 95/100  (message)
  +3.5  link sbi-kyc-update.xyz looks dangerous (88/100)
  +2.5  threatens to block, suspend or disconnect
  +2.0  KYC / PAN / Aadhaar update demand
  +1.5  urgency
  +1.0  combines a pressure story with a link
```

A genuine bank alert ("INR 2,340 debited from A/c XX4412 ... Not you? Call HDFC Bank customer care.") scores 0 / safe.

## Run it

```bash
pip install -r requirements.txt
python -m pytest -q                     # 21 tests (includes generated APKs, v2 signing blocks and QR images)
python -m phishguard serve              # web scanner + API on http://127.0.0.1:8006
python -m phishguard check "<message, link or UPI ID>"
python -m phishguard qr photo.jpg
python -m phishguard apk suspicious.apk
python -m phishguard page https://suspicious.example/login
python -m phishguard train              # retrain models (optionally with your own data, see below)
```

### Browser extension (Chrome / Edge / Brave)

1. Start the API: `python -m phishguard serve`
2. Open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked** and choose the `extension/` folder.

What the extension does:
- **Before you leave a site:** clicks on external and `upi:` links are checked first. Safe links open normally. Risky ones get a warning screen with the reasons, a "Go back" button, and an option to open anyway.
- **On pages that ask for secrets:** a page that asks for a password, OTP, card number or UPI PIN is scanned, and the same warning appears if it looks like a phishing kit.
- **On demand:** right-click any link or selected text to check it. The toolbar popup rates the current site and lets you paste a message to check.
- **If the scanner can't be reached, browsing carries on normally.** Pages are never broken because the API is down.

### API

| Endpoint | Body |
|---|---|
| `POST /v1/scan` | `{"input": "..."}`: works out whether it's a link, UPI link, UPI ID or message |
| `POST /v1/scan/url`, `/v1/scan/upi`, `/v1/scan/message` | `{"input": "..."}` |
| `POST /v1/scan/page` | `{"url": "...", "html": "..."}` (html optional when `PHISHGUARD_FETCH=1`) |
| `POST /v1/scan/qr` | multipart `image` |
| `POST /v1/scan/apk` | multipart `apk` (up to 150 MB) |
| `GET /healthz` | status and which models are loaded |

Every response has the same shape: `risk` (0–100), `level` (safe / suspicious / dangerous), `findings` (each with a weight, message and category), `entities` (what was extracted) and `advice`.

Deployment settings:
- `PHISHGUARD_API_KEY` requires an `X-API-Key` header.
- `PHISHGUARD_RATE` sets a per-client token-bucket rate limit (default 120/min).
- `PHISHGUARD_ORIGINS` adds allowed CORS origins. Browser-extension origins are allowed by default.
- Pages are only fetched server-side when `PHISHGUARD_FETCH=1`, and are never executed.

## Models and your own data

The shipped models are trained on generated corpora: 6,000 links (official bank/payment domains vs. typosquats, homoglyphs, subdomain abuse, free hosting, IPs, shorteners, `@` tricks, APK links) and 4,000 messages built from real-world Indian scam and genuine-alert templates. The rules carry the explanations; the models add generalisation. To adapt the models to real traffic:

```bash
python -m phishguard train --urls my_urls.csv            # url,label
python -m phishguard train --messages my_sms.csv         # text,label
python -m phishguard train --uci-sms SMSSpamCollection   # UCI SMS Spam Collection
```

`phishguard/brands.py` holds the reference data: each brand's official domains, official Android package names, and known UPI handles. Keep it current. Put official signing-certificate SHA-256 fingerprints in `phishguard/official_certs.json` (`{"com.sbi.lotusintouch": ["<sha256>"]}`) to detect repackaged copies of real apps.

## Layout

```
phishguard/
  brands.py    reference data: brands, domains, packages, UPI handles, look-alike table
  url.py       link features, typosquat/homoglyph detection, rules + model
  upi.py       UPI link / VPA analysis
  message.py   scam-message patterns, entity extraction, classifier
  apk.py       AXML parser, v1/v2/v3 certificate extraction, trojan-profile scoring
  page.py      phishing-kit page analysis, safe fetcher
  engine.py    input routing, QR decoding (OpenCV)
  verdict.py   shared result type and risk scale
  train.py     corpora and model training
  api.py       FastAPI service with API key, rate limit, CORS
web/index.html web scanner
extension/     Manifest V3 browser extension
```
