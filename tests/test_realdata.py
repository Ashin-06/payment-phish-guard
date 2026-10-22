from phishguard.realdata import load_phiusiil, load_uci_sms


def test_phiusiil_is_cut_to_hostnames_with_phishing_as_one(tmp_path):
    f = tmp_path / "p.csv"
    f.write_text("FILENAME,URL,label\n"
                 "a.txt,https://www.example.com,1\n"
                 "b.txt,http://evil-login.example.net/verify/account?id=3,0\n"
                 "c.txt,https://www.example.com,1\n", encoding="utf-8")
    df = load_phiusiil(f)
    assert df["url"].tolist() == ["https://www.example.com/", "https://evil-login.example.net/"]  # no path, no scheme hint
    assert df["phish"].tolist() == [0, 1]


def test_uci_sms_labels(tmp_path):
    f = tmp_path / "SMSSpamCollection"
    f.write_text('ham\tsee you at 6\nspam\tFREE entry "now"\n', encoding="utf-8")
    texts, y = load_uci_sms(f)
    assert texts[1] == 'FREE entry "now"' and y.tolist() == [0, 1]
