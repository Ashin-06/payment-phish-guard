# Evaluation

## Training data

The models were first trained only on generated data: 6,000 links (official bank and payment domains against typosquats, homoglyphs, subdomain abuse, free hosting, raw IPs, shorteners, `@` tricks and APK links) and 4,000 messages built from real Indian scam and genuine-alert templates. The rules provide the explanations; the models add generalisation. On the generated Indian-bank cases the held-out PR-AUC is 0.997.

## Real data

`python -m phishguard realdata` measured those models on public data, then retrained them on generated plus real data. Results go to `results/real_data.json`.

- PhiUSIIL ([UCI #967](https://archive.ics.uci.edu/dataset/967)): 235,795 URLs.
- SMS Spam Collection (UCI #228): 5,574 real SMS.

| Data | Model | PR-AUC | Caught | False alarms |
|---|---|---|---|---|
| PhiUSIIL hostnames, split by domain (44,481 test, 17,402 phishing) | generated data only | 0.763 | 29.9% | 0.5% |
| | generated + real (current) | 0.880 | 41.3% | 0.8% |
| UCI SMS (1,394 test, 187 spam) | generated data only | 0.218 | 79% | 75% |
| | generated + real (current) | 0.977 | 90.9% | 0.4% |

Notes:
- Only hostnames are used from PhiUSIIL. Every legitimate URL in it is a bare homepage while phishing URLs often have paths, so a model trained on full URLs would learn that any path means phishing.
- Train and test are split by registered domain, so no site appears in both.
- For links, "caught" is the full verdict (rules plus model) at the suspicious level. Global phishing rarely matches the Indian-bank brand rules, and the model alone can add at most 30 of the 100 risk points, so fewer are caught but false alarms stay under 1%.
- The original message model rated three quarters of ordinary real texts as scams. Retraining on real data fixed that.
- After retraining, the generated Indian-bank cases score the same as before and all tests pass.
