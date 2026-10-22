"""Scam and phishing detection for Indian digital payments."""
import os

os.environ.setdefault("LOKY_MAX_CPU_COUNT", str(os.cpu_count() or 1))  # silences a joblib warning on Windows
