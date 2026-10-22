"""Train the URL and message models.

Without arguments both are trained on generated corpora that reproduce the shapes of
real Indian payment scams. For production, add your own labelled data:

    python -m phishguard train --urls urls.csv        # columns: url,label (1 = phishing)
    python -m phishguard train --messages sms.csv     # columns: text,label
    python -m phishguard train --uci-sms SMSSpamCollection   # UCI SMS spam file (label<TAB>text)
"""
from __future__ import annotations

import argparse
import random
import string
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, make_pipeline

from .brands import BRANDS, COMMON_SAFE, FREE_HOSTING, RISKY_TLDS, SHORTENERS
from .url import FEATURE_NAMES, features, vector

MODELS = Path(__file__).resolve().parent / "models"
NEWS = ["thehindu.com", "ndtv.com", "indiatoday.in", "moneycontrol.com", "livemint.com", "zerodha.com", "groww.in",
        "cred.club", "nykaa.com", "bookmyshow.com", "olacabs.com", "uber.com", "practo.com", "naukri.com", "stackoverflow.com",
        "reddit.com", "medium.com", "bbc.com", "nytimes.com", "airtel.in", "jio.com", "tatacliq.com", "ajio.com"]
PATH_WORDS = ["personal", "banking", "cards", "loans", "offers", "about", "contact", "products", "blog", "news", "help",
              "faq", "careers", "investor", "accounts", "deposit", "insurance", "travel", "shop", "orders", "profile"]
LURES = ["kyc", "update", "verify", "refund", "reward", "cashback", "login", "secure", "unlock", "claim", "bonus", "pan",
         "aadhaar", "points", "redeem", "limit", "upgrade", "alert", "support", "help"]


def _rand_path(r: random.Random, lure: bool = False) -> str:
    words = r.sample(LURES if lure else PATH_WORDS, r.randint(1, 3))
    p = "/" + "/".join(words)
    if r.random() < 0.3:
        p += f"?id={r.randint(100, 99999)}"
    if r.random() < 0.2 and not lure:
        p += f"/{r.randint(2019, 2026)}/" + "-".join(r.sample(PATH_WORDS, 3))
    return p


def _typo(r: random.Random, s: str) -> str:
    i = r.randrange(len(s))
    op = r.choice(["swap", "drop", "dup", "sub", "homoglyph"])
    if op == "swap" and i < len(s) - 1:
        return s[:i] + s[i + 1] + s[i] + s[i + 2:]
    if op == "drop":
        return s[:i] + s[i + 1:]
    if op == "dup":
        return s[:i] + s[i] + s[i:]
    if op == "homoglyph":
        return s.replace("o", "0", 1).replace("l", "1", 1) if r.random() < 0.5 else s.replace("m", "rn", 1)
    return s[:i] + r.choice(string.ascii_lowercase) + s[i + 1:]


def url_corpus(n: int = 6000, seed: int = 0) -> tuple[list[str], np.ndarray]:
    r = random.Random(seed)
    official = [d for b in BRANDS.values() for d in b["domains"]] + COMMON_SAFE + NEWS
    urls, y = [], []
    for _ in range(n // 2):
        d = r.choice(official)
        host = d if r.random() < 0.4 else f"{r.choice(['www', 'm', 'retail', 'netbanking', 'pay', 'help', 'shop'])}.{d}"
        urls.append(f"https://{host}{_rand_path(r) if r.random() < 0.8 else '/'}")
        y.append(0)
    names = [n.replace(" ", "") for b in BRANDS.values() for n in b["names"]]
    for _ in range(n // 2):
        brand, lure, tld = r.choice(names), r.choice(LURES), r.choice(sorted(RISKY_TLDS) + ["com", "in", "net", "org"])
        kind = r.randint(0, 8)
        if kind == 0:
            u = f"https://{brand}-{lure}-{r.choice(LURES)}.{tld}{_rand_path(r, True)}"
        elif kind == 1:
            d = r.choice([d for b in BRANDS.values() for d in b["domains"]])
            u = f"https://{d}.{lure}-{r.choice(['secure', 'online', 'portal'])}.{tld}{_rand_path(r, True)}"
        elif kind == 2:
            d = r.choice([d for b in BRANDS.values() for d in b["domains"]])
            base, rest = d.split(".", 1)
            u = f"https://{_typo(r, base)}.{rest}{_rand_path(r, r.random() < 0.7)}"
        elif kind == 3:
            u = f"https://{brand}-{lure}{r.randint(1, 999)}.{r.choice(sorted(FREE_HOSTING))}{_rand_path(r, True)}"
        elif kind == 4:
            u = f"http://{r.randint(11, 223)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}/{brand}/{lure}"
        elif kind == 5:
            u = f"https://{r.choice(sorted(SHORTENERS))}/{''.join(r.choices(string.ascii_letters + string.digits, k=7))}"
        elif kind == 6:
            u = f"http://{brand}.com@{''.join(r.choices(string.ascii_lowercase, k=8))}.{tld}/{lure}"
        elif kind == 7:
            u = f"https://{''.join(r.choices(string.ascii_lowercase + string.digits, k=r.randint(10, 18)))}.{tld}/{brand}-{lure}.apk"
        else:
            u = f"https://{lure}-{r.choice(['india', 'online', 'portal', 'gov', 'center'])}.{tld}/{brand}{_rand_path(r, True)}"
        urls.append(u)
        y.append(1)
    return urls, np.array(y)


SCAM_TEMPLATES = [
    "Dear customer your {bank} account will be blocked today. Update KYC immediately {url}",
    "Your {bank} YONO / net banking access is suspended. Click {url} to update PAN card details",
    "Dear consumer your electricity power will be disconnected tonight at 9.30pm because your previous month bill was not updated. Call {phone}",
    "Congratulations! You have won Rs {amt} cashback from {brand}. Claim now {url}",
    "Your {brand} reward points worth Rs.{amt} expire today. Redeem at {url}",
    "Income tax refund of Rs {amt} approved. Verify your account {url} to receive it",
    "Your parcel is held at customs. Pay clearance fee of Rs {amt} at {url}",
    "Part time job: earn Rs {amt} daily by liking youtube videos. WhatsApp {phone}",
    "Pre-approved instant loan of Rs {amt} credited in 5 mins, no documents. Install app {url}",
    "This is CBI cyber cell. Your Aadhaar is linked to a money laundering case. Do not tell anyone, call {phone} immediately",
    "Dear user, to receive your refund of Rs {amt} please scan the QR and enter UPI PIN. Pay to {vpa}",
    "Your {bank} credit card limit increased. Share OTP received to activate, call {phone}",
    "Hi mom my phone is broken, this is my new number. Send Rs {amt} urgently to {vpa}",
    "Your {bank} debit card has been blocked due to KYC pending. Download the {bank} KYC app from {url} to unblock",
    "FASTag KYC expired. Update now or your FASTag will be deactivated {url}",
    "Your SIM will be deactivated in 2 hours as per TRAI. Call {phone} to verify",
]
LEGIT_TEMPLATES = [
    "{otp} is your OTP for transaction of INR {amt} at {merchant} on your {bank} card ending {last4}. Valid for 10 mins. Do not share it with anyone.",
    "INR {amt} debited from A/c XX{last4} on {date} to {merchant}. Avl Bal INR {bal}. Not you? Call {bank} customer care.",
    "Your {bank} account XX{last4} is credited with INR {amt} on {date}. Avl bal INR {bal}.",
    "{otp} is the OTP to log in to {brand}. Never share your OTP with anyone, {bank} never asks for it.",
    "Your order of {item} has been shipped and will be delivered by {date}. Track in the app.",
    "Reminder: your appointment with Dr. {name} is on {date} at 11:30 AM.",
    "Your electricity bill of Rs {amt} for consumer no {last4}{last4} is due on {date}. Pay via your bank app or the official portal.",
    "Hi, are we still meeting for lunch tomorrow at 1?",
    "Your SIP of Rs {amt} in {fund} has been processed successfully on {date}.",
    "Dear customer, your cheque no {last4} for Rs {amt} has been cleared.",
    "Payment of Rs {amt} to {merchant} via UPI successful. UPI Ref {last4}{last4}{otp}.",
    "Your {brand} statement for {date} is ready. Total due Rs {amt}, due date {date}.",
]


def message_corpus(n: int = 4000, seed: int = 0) -> tuple[list[str], np.ndarray]:
    r = random.Random(seed)
    banks = ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "Kotak", "PNB", "Bank of Baroda"]
    brands = ["Paytm", "PhonePe", "Amazon Pay", "Google Pay", "HDFC Bank", "SBI Card", "Flipkart"]
    bad = [u for u, lab in zip(*url_corpus(400, seed + 1)) if lab == 1]
    fill = lambda t, scam: t.format(
        bank=r.choice(banks), brand=r.choice(brands), url=r.choice(bad) if scam else "",
        phone=f"{r.choice('6789')}{r.randint(100000000, 999999999)}", amt=f"{r.randint(1, 99) * r.choice([10, 100, 1000]):,}",
        vpa=f"{r.choice(['refund', 'help', 'customer.care', 'kyc', 'rahul', 'mom'])}{r.randint(1, 999)}@{r.choice(['ybl', 'okaxis', 'paytm', 'axl'])}",
        otp=r.randint(100000, 999999), merchant=r.choice(["AMAZON", "SWIGGY", "ZOMATO", "IRCTC", "BIGBASKET", "UBER"]),
        last4=r.randint(1000, 9999), bal=f"{r.randint(1000, 500000):,}", date=f"{r.randint(1, 28)}-{r.choice(['Jan', 'Mar', 'Jun', 'Oct', 'Nov'])}",
        item=r.choice(["headphones", "a phone case", "books", "shoes"]), name=r.choice(["Mehta", "Rao", "Iyer"]),
        fund=r.choice(["Parag Parikh Flexi Cap", "Nifty 50 Index Fund"]))
    texts, y = [], []
    for _ in range(n // 2):
        t = fill(r.choice(SCAM_TEMPLATES), True)
        texts.append(t.lower() if r.random() < 0.2 else t)
        y.append(1)
    for _ in range(n // 2):
        texts.append(fill(r.choice(LEGIT_TEMPLATES), False))
        y.append(0)
    return texts, np.array(y)


def train_urls(urls, y):
    X = np.array([vector(features(u)) for u in urls])
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y, random_state=0)
    clf = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08).fit(Xtr, ytr)
    p = clf.predict_proba(Xte)[:, 1]
    print(f"URL model: {len(y)} samples, PR-AUC {average_precision_score(yte, p):.4f}")
    print(classification_report(yte, p > 0.5, digits=3, target_names=["legit", "phishing"]))
    return clf


def train_messages(texts, y):
    vec = FeatureUnion([("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
                        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True, max_features=40000))])
    model = make_pipeline(vec, LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced"))
    Xtr, Xte, ytr, yte = train_test_split(texts, y, test_size=0.25, stratify=y, random_state=0)
    model.fit(Xtr, ytr)
    p = model.predict_proba(Xte)[:, 1]
    print(f"message model: {len(y)} samples, PR-AUC {average_precision_score(yte, p):.4f}")
    return model


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--urls", help="CSV with url,label")
    ap.add_argument("--messages", help="CSV with text,label")
    ap.add_argument("--uci-sms", help="UCI SMSSpamCollection file")
    a = ap.parse_args(argv)
    MODELS.mkdir(exist_ok=True)

    urls, uy = url_corpus()
    if a.urls:
        df = pd.read_csv(a.urls)
        urls, uy = urls + df["url"].astype(str).tolist(), np.r_[uy, df["label"].astype(int).to_numpy()]
    joblib.dump(train_urls(urls, uy), MODELS / "url_model.joblib", compress=3)

    texts, ty = message_corpus()
    if a.messages:
        df = pd.read_csv(a.messages)
        texts, ty = texts + df["text"].astype(str).tolist(), np.r_[ty, df["label"].astype(int).to_numpy()]
    if a.uci_sms:
        df = pd.read_csv(a.uci_sms, sep="\t", header=None, names=["label", "text"], quoting=3)
        texts, ty = texts + df["text"].tolist(), np.r_[ty, (df["label"] == "spam").astype(int).to_numpy()]
    joblib.dump(train_messages(texts, ty), MODELS / "text_model.joblib", compress=3)
    print(f"saved models to {MODELS}")


if __name__ == "__main__":
    main()
