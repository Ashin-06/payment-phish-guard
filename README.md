# Payment Phish Guard

Scam and phishing detection for the ways Indian digital-payment fraud reaches people: SMS and WhatsApp messages, links, UPI payment links and QR codes, fake bank apps sent as APK files, and cloned net-banking pages.

It works from a web page, a browser extension, an HTTP API or the command line. Every verdict explains why in plain language and says what to do next.

## What it checks

| Input | Checks |
|---|---|
| Link | look-alike bank domains, homoglyphs, brand names on other domains, raw IPs, shorteners, free hosting, risky TLDs, APK downloads, plus a model over 25 link features |
| UPI link or QR code | a "refund" story on a link that actually takes money, collect and mandate requests, an institution name on a personal UPI ID, unknown handles |
| UPI ID | validity, known bank handle, brand or "refund/kyc/support" words in a personal ID |
| Message | 14 scam patterns (OTP requests, account-block threats, KYC demands, parcel and job scams, remote-access apps, "digital arrest", family on a new number and more), a text classifier, and every link, UPI ID and phone number inside |
| APK | reads the manifest and signing certificate without the Android SDK; flags bank look-alike package names, SMS interception, accessibility abuse, overlays and debug signing; with official certificate fingerprints it catches repackaged real apps |
| Web page | forms asking for passwords, OTPs, card numbers, UPI PINs or Aadhaar, bank branding on a foreign domain, data sent to Telegram bots or webhooks, obfuscated scripts |

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

A genuine bank alert such as "INR 2,340 debited from A/c XX4412 ... Not you? Call HDFC Bank customer care." scores 0 (safe).

## Quick start

```bash
pip install -r requirements.txt
python -m pytest -q                     # 49 tests
python -m phishguard serve              # web scanner and API on http://127.0.0.1:8006
python -m phishguard check "<message, link or UPI ID>"
python -m phishguard qr photo.jpg
python -m phishguard apk suspicious.apk
python -m phishguard page https://suspicious.example/login
```

To run it in a container:

```bash
docker build -t payment-phish-guard .
docker run -p 8006:8006 -e PHISHGUARD_API_KEYS='{"sha256:...": {"user": "extension", "role": "scanner"}}' payment-phish-guard
```

## Browser extension

1. Start the API with `python -m phishguard serve`.
2. Open `chrome://extensions`, turn on Developer mode, click Load unpacked and choose the `extension/` folder.

The extension checks external and `upi:` links before you follow them and shows a warning with the reasons for risky ones. It also scans pages that ask for a password, OTP, card number or UPI PIN. You can right-click a link or selected text to check it. If the API can't be reached, browsing carries on normally.

## API

| Endpoint | Body |
|---|---|
| `POST /v1/scan` | `{"input": "..."}`; works out whether it is a link, UPI link, UPI ID or message |
| `POST /v1/scan/url`, `/v1/scan/upi`, `/v1/scan/message` | `{"input": "..."}` |
| `POST /v1/scan/page` | `{"url": "...", "html": "..."}` |
| `POST /v1/scan/qr` | multipart `image` |
| `POST /v1/scan/apk` | multipart `apk` (up to 150 MB) |
| `GET /healthz`, `/readyz`, `/metrics` | health, readiness and Prometheus metrics |

Every response has `risk` (0–100), `level` (safe, suspicious or dangerous), `findings` with a weight and message each, `entities` and `advice`.

## Results

| Test | Result |
|---|---|
| Real phishing hostnames (PhiUSIIL, 44,481 test hosts) | PR-AUC 0.763 before retraining, 0.880 after |
| Real SMS spam (UCI, 1,394 test messages) | PR-AUC 0.218 before retraining, 0.977 after; false alarms fell from 75% to 0.4% |

Details are in [docs/evaluation.md](docs/evaluation.md). To adapt the models to your own traffic:

```bash
python -m phishguard train --urls my_urls.csv            # url,label
python -m phishguard train --messages my_sms.csv         # text,label
```

`phishguard/brands.py` holds each brand's official domains, app package names and UPI handles, and needs to be kept current. Official signing-certificate fingerprints go in `phishguard/official_certs.json`.

## Configuration

| Variable | Purpose |
|---|---|
| `PHISHGUARD_ENV=production` | refuse to start without hashed API keys |
| `PHISHGUARD_API_KEYS` / `PHISHGUARD_KEYS_FILE` | API keys with roles: `scanner`, `monitor`, `admin` |
| `PHISHGUARD_RATE_LIMIT` | requests per minute per client (default 120) |
| `PHISHGUARD_MAX_BODY_BYTES` | largest request body (default 160 MB) |
| `PHISHGUARD_CORS_ORIGINS` | extra allowed origins; browser extensions are allowed by default |
| `PHISHGUARD_FETCH=1` | allow the server to fetch pages; only public http(s) addresses are allowed and pages are never executed |

All settings: [docs/runbook.md](docs/runbook.md).

## Project layout

```
phishguard/
  brands.py    brands, official domains, packages, UPI handles
  url.py       link checks and model
  upi.py       UPI link and ID checks
  message.py   scam patterns and text classifier
  apk.py       APK manifest and certificate parsing
  page.py      phishing page checks and safe fetcher
  engine.py    routes input to the right checker, decodes QR codes
  train.py     model training
  realdata.py  tests on public data
  api.py       FastAPI service
web/index.html web scanner
extension/     browser extension
```

## Limitations

- The real-data tests use a global phishing URL set and an English SMS set, not Indian payment scams. The bank's own fraud reports are needed to measure it properly.
- The brand rules focus on Indian banks, so generic global phishing is caught mainly by the model.
- The service stores nothing a user submits.
- The code has not had an independent security review, which matters most for the APK and page parsers that read hostile files. The browser extension also needs a store-reviewed release before customers use it.

See [SECURITY.md](SECURITY.md), [docs/threat-model.md](docs/threat-model.md) and [docs/model-card.md](docs/model-card.md).
