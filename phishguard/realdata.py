"""Measure the URL and message models on public real-world data, and retrain on it.

PhiUSIIL Phishing URL Dataset (UCI #967, CC BY 4.0): 235,795 URLs, 100,945 phishing.
    Every legitimate URL in it is a bare https:// homepage while phishing URLs often carry
    paths and plain http, so a model trained on the raw URLs learns "has a path = phishing"
    and would flag real bank pages. Here every URL is cut to https://<host>/ so only the
    hostname is judged, and train/test are split by registered domain so no site appears
    on both sides.
SMS Spam Collection (UCI #228, CC BY 4.0): 5,574 real SMS, 747 spam.

    python -m phishguard realdata --phiusiil PhiUSIIL_Phishing_URL_Dataset.csv --uci-sms SMSSpamCollection
    python -m phishguard realdata ... --update-models     # also ship the retrained models
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from .message import _model as shipped_text_model
from .train import MODELS, message_corpus, train_messages, url_corpus
from .url import _model as shipped_url_model
from .url import analyze_url, features, vector


def load_phiusiil(path: str | Path) -> pd.DataFrame:
    df = pd.read_csv(path, usecols=["URL", "label"], encoding="utf-8-sig")
    host = df["URL"].map(lambda u: (urlsplit(u).hostname or "").lower())
    out = pd.DataFrame({"url": "https://" + host + "/", "phish": 1 - df["label"]})  # the file uses 1 = legitimate
    return out[host.str.len() > 0].drop_duplicates("url").reset_index(drop=True)


def load_uci_sms(path: str | Path) -> tuple[list[str], np.ndarray]:
    df = pd.read_csv(path, sep="\t", header=None, names=["label", "text"], quoting=3)
    return df["text"].astype(str).tolist(), (df["label"] == "spam").astype(int).to_numpy()


def _scores(y: np.ndarray, p: np.ndarray, flagged: np.ndarray | None = None) -> dict:
    out = {"pr_auc": round(float(average_precision_score(y, p)), 4), "roc_auc": round(float(roc_auc_score(y, p)), 4)}
    if flagged is not None:
        out["caught_share"] = round(float(flagged[y == 1].mean()), 4)          # phishing/spam rated >= suspicious
        out["false_alarm_share"] = round(float(flagged[y == 0].mean()), 4)     # legitimate rated >= suspicious
    return out


def _engine(urls: list[str], feats: list[dict], model) -> tuple[np.ndarray, np.ndarray]:
    """Model probability and the full verdict (rules + model) for each URL."""
    X = np.array([vector(f) for f in feats])
    p = model.predict_proba(X)[:, 1]
    flagged = np.array([analyze_url(u, f, model).risk >= 40 for u, f in zip(urls, feats)])
    return p, flagged


def evaluate_urls(path: str | Path, update: bool = False) -> dict:
    df = load_phiusiil(path)
    feats = [features(u) for u in df["url"]]
    y = df["phish"].to_numpy()
    groups = [f["_reg"] for f in feats]
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=0).split(df, y, groups))
    te_urls, te_feats = df["url"].iloc[te].tolist(), [feats[i] for i in te]

    res = {"dataset": "PhiUSIIL (UCI #967), hostnames only, split by registered domain",
           "urls": len(df), "test_urls": len(te), "test_phishing": int(y[te].sum())}
    res["shipped_model_synthetic_only"] = _scores(y[te], *_engine(te_urls, te_feats, shipped_url_model()))

    X = np.array([vector(f) for f in feats])
    real_only = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08).fit(X[tr], y[tr])
    res["trained_on_real_only"] = _scores(y[te], *_engine(te_urls, te_feats, real_only))

    # the shipped model keeps the generated Indian-bank cases and adds the real hostnames
    s_urls, s_y = url_corpus()
    s_tr, s_te = train_test_split(np.arange(len(s_urls)), test_size=0.25, stratify=s_y, random_state=0)
    Xs = np.array([vector(features(u)) for u in s_urls])
    combined = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08).fit(
        np.r_[Xs[s_tr], X[tr]], np.r_[s_y[s_tr], y[tr]])
    res["trained_on_generated_plus_real"] = _scores(y[te], *_engine(te_urls, te_feats, combined))
    res["trained_on_generated_plus_real"]["generated_holdout_pr_auc"] = round(
        float(average_precision_score(s_y[s_te], combined.predict_proba(Xs[s_te])[:, 1])), 4)
    if update:
        final = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08).fit(np.r_[Xs, X], np.r_[s_y, y])
        joblib.dump(final, MODELS / "url_model.joblib", compress=3)
        res["shipped"] = "url_model.joblib retrained on generated + all real hostnames"
    return res


def evaluate_messages(path: str | Path, update: bool = False) -> dict:
    texts, y = load_uci_sms(path)
    tr, te = train_test_split(np.arange(len(texts)), test_size=0.25, stratify=y, random_state=0)
    te_texts = [texts[i] for i in te]
    res = {"dataset": "SMS Spam Collection (UCI #228)", "messages": len(texts), "test_messages": len(te),
           "test_spam": int(y[te].sum())}
    p = shipped_text_model().predict_proba(te_texts)[:, 1]
    res["shipped_model_synthetic_only"] = _scores(y[te], p, p >= 0.5)

    s_texts, s_y = message_corpus()
    model = train_messages(s_texts + [texts[i] for i in tr], np.r_[s_y, y[tr]])
    p = model.predict_proba(te_texts)[:, 1]
    res["trained_on_generated_plus_real"] = _scores(y[te], p, p >= 0.5)
    if update:
        joblib.dump(train_messages(s_texts + texts, np.r_[s_y, y]), MODELS / "text_model.joblib", compress=3)
        res["shipped"] = "text_model.joblib retrained on generated + all real SMS"
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--phiusiil", help="PhiUSIIL_Phishing_URL_Dataset.csv")
    ap.add_argument("--uci-sms", help="SMSSpamCollection")
    ap.add_argument("--update-models", action="store_true", help="retrain the shipped models on generated + real data")
    ap.add_argument("--out", default="results/real_data.json")
    a = ap.parse_args(argv)
    res = {}
    if a.phiusiil:
        res["urls"] = evaluate_urls(a.phiusiil, a.update_models)
    if a.uci_sms:
        res["messages"] = evaluate_messages(a.uci_sms, a.update_models)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
