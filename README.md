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
python -m pytest -q                     # 49 tests (includes generated APKs, v2 signing blocks, QR images and SSRF checks)
python -m phishguard serve              # web scanner + API on http://127.0.0.1:8006 (demo mode, no keys)
python -m phishguard check "<message, link or UPI ID>"
python -m phishguard qr photo.jpg
python -m phishguard apk suspicious.apk
python -m phishguard page https://suspicious.example/login
python -m phishguard train              # retrain models (optionally with your own data, see below)
```

In a container (production mode; see [docs/runbook.md](docs/runbook.md)):

```bash
docker build -t payment-phish-guard:1.0.0 .
docker run -p 8006:8006 -e PHISHGUARD_API_KEYS='{"sha256:...": {"user": "extension", "role": "scanner"}}' payment-phish-guard:1.0.0
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
| `GET /healthz`, `/readyz` | liveness; readiness (both models loaded) |
| `GET /metrics` | Prometheus metrics (role `monitor`) |

Every response has the same shape: `risk` (0–100), `level` (safe / suspicious / dangerous), `findings` (each with a weight, message and category), `entities` (what was extracted) and `advice`.

Deployment settings come from `PHISHGUARD_*` environment variables (full table in [docs/runbook.md](docs/runbook.md)):
- `PHISHGUARD_API_KEYS` (or `PHISHGUARD_KEYS_FILE`) lists the API keys, stored as `sha256:<hex>` with a user and a role: `scanner` may scan, `monitor` reads `/metrics`, `admin` both. Callers send `X-API-Key` (the extension's Options page has a field for it) or `Authorization: Bearer`. Without keys the service runs in demo mode and only listens on loopback; `python -m phishguard.ops keygen` makes a key. `PHISHGUARD_ENV=production` refuses to start without hashed keys.
- `PHISHGUARD_RATE_LIMIT` sets a per-client token-bucket rate limit (default 120/min); `PHISHGUARD_MAX_BODY_BYTES` caps request bodies (default 160 MB, enough for one APK).
- `PHISHGUARD_CORS_ORIGINS` adds allowed CORS origins. Browser-extension origins are allowed by default.
- Pages are only fetched server-side when `PHISHGUARD_FETCH=1`, and are never executed. Every hop, redirects included, must be http(s) to a public address, so the scanner cannot be used to reach localhost, private networks or cloud metadata endpoints.

## Models and real data

The models started out trained only on generated corpora: 6,000 links (official bank and payment domains against typosquats, homoglyphs, subdomain abuse, free hosting, IPs, shorteners, `@` tricks, APK links) and 4,000 messages built from real Indian scam and genuine-alert templates. The rules carry the explanations; the models add generalisation.

`python -m phishguard realdata` measured those models on public real data, then retrained them (results in `results/real_data.json`):
- **PhiUSIIL** ([UCI #967](https://archive.ics.uci.edu/dataset/967), 235,795 URLs).
- **SMS Spam Collection** (UCI #228, 5,574 real SMS).

| Real data | Model | PR-AUC | Caught | False alarms |
|---|---|---|---|---|
| PhiUSIIL hostnames, split by domain (44,481 test, 17,402 phishing) | generated data only | 0.763 | 29.9% | 0.5% |
| | **generated + real (shipped now)** | **0.880** | 41.3% | 0.8% |
| UCI SMS (1,394 test, 187 spam) | generated data only | 0.218 | 79% | **75%** |
| | **generated + real (shipped now)** | **0.977** | 90.9% | 0.4% |

Notes:
- **Only hostnames are used from PhiUSIIL.** In that dataset every legitimate URL is a bare `https://` homepage, while phishing URLs often have paths or plain `http`. A model trained on full URLs learns "has a path = phishing" and would flag real bank pages.
- **Train and test are split by registered domain**, so no site appears on both sides.
- **URL "caught" is the full verdict** (rules + model) at the suspicious level. Generic global phishing rarely trips the Indian-bank brand rules, and the model alone can add at most 30 of the 100 risk points. So the share caught is modest, and false alarms stay under 1%.
- **The original message model was badly off on real SMS:** it rated three quarters of ordinary texts as scams. Retraining on real data fixed that.
- **The generated Indian-bank cases are unchanged** (held-out PR-AUC 0.997), and the test suite still passes.

To adapt the models to your own traffic:

```bash
python -m phishguard train --urls my_urls.csv            # url,label
python -m phishguard train --messages my_sms.csv         # text,label
python -m phishguard realdata --phiusiil PhiUSIIL_Phishing_URL_Dataset.csv --uci-sms SMSSpamCollection --update-models
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
  realdata.py  scoring and retraining on PhiUSIIL URLs and UCI SMS
  api.py       FastAPI service with API key, rate limit, CORS
web/index.html web scanner
extension/     Manifest V3 browser extension
```

## Production readiness

**In place** (see [docs/runbook.md](docs/runbook.md), [docs/threat-model.md](docs/threat-model.md) and [docs/model-card.md](docs/model-card.md)):
- Pinned dependencies (`requirements.lock`, with scikit-learn held at the version the shipped models were saved with), `pyproject.toml`, a container image that runs as a non-root user with a health check, and CI (ruff, bandit, pip-audit, tests with coverage).
- Production mode that refuses to start without hashed per-client API keys, and no public listener without keys.
- Roles on keys, per-client rate limits, a body size cap, security headers, CORS only for listed origins and browser extensions, errors that don't echo input or fetch failures, and the SSRF-safe page fetcher off by default.
- JSON logs with request IDs, `/healthz`, `/readyz` (models loaded) and Prometheus metrics, including a count of safe / suspicious / dangerous verdicts.
- The service keeps no state: nothing a customer submits is stored.

**Still needed before customers rely on it**, none of which code can supply:
- An independent security review and penetration test, especially of the APK and page parsers that read hostile files. Nobody outside this project has reviewed it.
- Validation on the bank's own fraud reports. The real-data numbers come from a global phishing URL set and an English SMS spam set, not Indian payment scams; on PhiUSIIL the full verdict catches 41% of phishing hostnames.
- RBI and DPDP Act 2023 sign-off on scanning customers' messages and browsing, including what the extension sends and whether messages may leave the device.
- Real integrations: brand reference data and official signing certificates kept current by the bank, threat-intelligence feeds (CERT-In, NPCI, reported VPAs), and a route from a "dangerous" verdict to the bank's fraud desk.
- A store-reviewed release of the extension pinned to the bank's API host, instead of the unpacked developer build.
- TLS and a shared rate limiter at the ingress; an on-call team with SLOs and alerting on the metrics above.
