# Model card: Payment Phish Guard 1.0.0

Numbers come from `results/real_data.json` and the README. Nothing here has been measured on a
bank's own fraud reports or on Indian payment scams collected in the field.

## What it is

Rules plus two small learned models, combined into a 0–100 risk score and a level
(safe / suspicious / dangerous) with plain-language reasons:

| Part | Method | File |
|---|---|---|
| Link model | gradient boosting over 25 hostname features | `phishguard/models/url_model.joblib` |
| Message model | TF-IDF text classifier | `phishguard/models/text_model.joblib` |
| Rules | brand look-alikes, UPI collect and refund tricks, 14 scam-message patterns, APK permission and signing checks, phishing-kit page checks | `phishguard/*.py`, `brands.py` |

The rules carry the explanations; the models add generalisation. On links, the model alone can
add at most 30 of the 100 risk points. UPI, QR, APK and page verdicts are rules only.

## Intended use

Warning customers before they act on a link, message, UPI request, QR code, page or APK, inside
the bank's app, a browser extension or a support tool. A second opinion that explains itself, not
a block list and not proof that something is safe.

## Data

| Data | Used for |
|---|---|
| Generated: 6,000 links (official bank and payment domains against typosquats, homoglyphs, subdomain abuse, free hosting, IPs, shorteners, `@` tricks, APK links) and 4,000 messages from real Indian scam and genuine-alert templates | the original models; still part of training |
| PhiUSIIL (UCI #967), 235,795 URLs, used as hostnames only (220,077 after cutting), split by registered domain | measuring and retraining the link model |
| SMS Spam Collection (UCI #228), 5,574 real SMS | measuring and retraining the message model |

The shipped models were retrained on generated plus all real data after the measurements below.

## Metrics

**Links, PhiUSIIL hostnames, held-out domains (44,481 test, 17,402 phishing).** "Caught" is the
full verdict (rules + model) at the suspicious level.

| Model | PR-AUC | ROC-AUC | Caught | False alarms |
|---|---|---|---|---|
| Generated data only (the original model) | 0.763 | 0.783 | 29.9% | 0.5% |
| Real data only | 0.881 | 0.873 | 41.0% | 0.7% |
| Generated + real (approach shipped) | 0.880 | 0.873 | 41.3% | 0.8% |

Generated Indian-bank links held out from training: PR-AUC 0.997 with the generated + real model.

**Messages, UCI SMS (1,394 test, 187 spam).**

| Model | PR-AUC | ROC-AUC | Caught | False alarms |
|---|---|---|---|---|
| Generated data only (the original model) | 0.218 | 0.562 | 79.1% | 75.5% |
| Generated + real (approach shipped) | 0.977 | 0.991 | 90.9% | 0.4% |

## Known failure modes

- Generic global phishing rarely trips the Indian-bank brand rules, so the full verdict catches
  only about 41% of PhiUSIIL phishing hostnames.
- The original message model rated three quarters of ordinary texts as scams on real SMS; the
  retrained one fixed that, but its real data is English spam, not Hindi, Hinglish or regional
  scam messages.
- Brand data goes stale: a bank's new domain or app package is flagged until `brands.py` is
  updated.
- APK checks are static; a trojan that downloads its payload later looks like an ordinary app.

## Caveats

- **Only hostnames are used from PhiUSIIL.** Every legitimate URL there is a bare `https://`
  homepage while phishing URLs often have paths or plain `http`; a model trained on full URLs
  learns "has a path = phishing" and would flag real bank pages.
- Train and test are split by registered domain, so no site appears on both sides.
- The shipped models were then trained on all of the real data, so the numbers above describe the
  approach on held-out data, not the exact shipped files on unseen data.
- Retrain and re-measure on the bank's own reported scams and genuine messages before relying on
  the scores; keep scikit-learn at the version the models were saved with.
