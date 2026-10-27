# Threat model

What the scanner protects, from whom, and what is still open. Written for the 1.0.0 code; it has
not been reviewed by anyone independent.

## What it protects

| Asset | Where it lives |
|---|---|
| Customers' money, by warning them before they pay a scammer, open a phishing page or install a trojan APK | verdicts returned to the web page, the extension or the bank's app |
| What customers submit: messages, links, UPI requests, page HTML, QR images, APKs | in memory for the duration of the request only; never stored |
| Service API keys | callers hold the key; the service holds only SHA-256 hashes |
| The service host and its network | the page fetcher must never reach internal addresses |
| Model files and brand reference data | `phishguard/models/`, `phishguard/brands.py`, read only |

## Trust boundaries

```
customer (browser extension / web page / bank app) ──(TLS at your ingress)──► scanner
                                                                                 │
                                                       (only with PHISHGUARD_FETCH=1) └──► public web pages
```

1. **Caller → scanner.** Everything submitted is attacker-controlled: scam authors can craft
   messages, pages and APKs aimed at the parsers, not just at the customer.
2. **Scanner → the web.** The optional fetcher reads pages a scammer chose. It must not be usable
   to reach localhost, private networks or cloud metadata.
3. **Scanner → caller.** A wrong "safe" verdict is the main harm: it lends the scam credibility.

## Threats and what stops them

| Threat | Mitigation | Residual risk |
|---|---|---|
| A scam is rated safe | Rules for Indian payment scams (brand look-alikes, UPI collect tricks, OTP and KYC pressure), models retrained on real data | **Detection misses things**: on PhiUSIIL the full verdict catches 41.3% of phishing hostnames; the real SMS data is English spam, not Indian payment scams. A "safe" verdict must never be shown as a guarantee |
| A genuine bank message or site is rated dangerous | Official domains, packages and handles in `brands.py`; genuine-alert templates in training | False alarms were 0.8% (URLs) and 0.4% (SMS) on the real test sets; stale brand data raises them |
| Hostile APK or page attacks the parser (zip bombs, malformed signing blocks, huge AXML) | Size limits per upload, hardened APK parsing (oversized archives and malformed signing blocks are refused), pages are parsed, never executed | A bug in the zip, AXML, OpenCV or HTML handling could still crash or slow a worker; the request then fails with a 500 and a request ID |
| SSRF through `/v1/scan/page` | Fetching is off by default; when on, every hop including redirects must be http(s) to a public address; responses capped at 2 MB | DNS can change between the check and the connection (rebinding); run the service without access to internal networks |
| Upload floods | 160 MB body cap (150 MB per APK, 10 MB per image), per-client rate limit | The body is buffered in memory: lower `PHISHGUARD_MAX_BODY_BYTES` if APK scanning isn't offered |
| Stolen API key | Per-client keys, roles, rate limit per key | An extension key ships to every user's browser; treat it as public and rely on the rate limit, or issue keys per user from the bank's app |
| XSS in the extension's warning overlay or the web page | All scanner text is escaped before display; security headers and CSP on the page | — |
| Errors leak data | Validation errors carry no input; unhandled errors return only a request ID; fetch failures don't return the network error | — |
| Misconfigured production start | `PHISHGUARD_ENV=production` refuses to start without hashed keys; no public bind without keys | — |

## Not covered

- TLS. Terminate it at your ingress; the service speaks plain HTTP.
- Dynamic analysis of APKs (running them) and of pages (running their scripts).
- Messages and links that never reach the scanner: the extension sees only the browser; SMS and
  WhatsApp need the bank's own app to submit them.
- Retention or reporting of scams found; if the bank wants a scam database, that is a separate,
  access-controlled store with its own retention rules.
