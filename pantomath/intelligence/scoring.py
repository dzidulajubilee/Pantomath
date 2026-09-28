"""
Lightweight keyword heuristic for triage. Not a replacement for real CTI
scoring (CVSS/EPSS), just a fast visual signal so a human can prioritize
what to read first. Tune the lists below freely.

Keywords match as whole words, not substrings. Substring matching (the
original approach) made "rce" fire on "source", "resources" and
"enforcement" (-> high) and "apt" on "chapter", "laptop" and "adapt"
(-> medium). With deep extraction on, a full article page almost always
contains "source" somewhere, so nearly everything scored high — which
made the Critical view, the critical-alerts count, desktop notification
thresholds and webhook severity filters all unreliable.

Matching rules, so the lists stay plain phrases:
  - a keyword must not be glued to a letter/digit on its left;
  - on its right it may take a plain plural/past suffix (s, es, ed), so
    "breach" still covers "breaches"/"breached" and "zero-day" covers
    "zero-days" — the one thing substring matching got right for free;
  - a keyword ending in "-" is a prefix ("cve-" matches "CVE-2026-1234").
"""
import re

KEYWORDS_HIGH = [
    "ransomware", "zero-day", "0-day", "critical",
    "exploited in the wild", "rce", "actively exploited",
    "remote code execution", "critical vulnerability",
]

KEYWORDS_MEDIUM = [
    "cve-", "vulnerability", "vulnerabilities", "apt", "breach", "malware",
    "phishing", "backdoor", "supply chain", "data leak",
]


def _keyword_pattern(keywords: list[str]) -> re.Pattern:
    parts = []
    for k in keywords:
        body = re.escape(k.lower())
        tail = "" if k.endswith("-") else r"(?:s|es|ed)?(?![a-z0-9])"
        parts.append(rf"(?<![a-z0-9]){body}{tail}")
    return re.compile("|".join(parts))


_HIGH = _keyword_pattern(KEYWORDS_HIGH)
_MEDIUM = _keyword_pattern(KEYWORDS_MEDIUM)


def score_severity(title: str, summary: str) -> str:
    text = f"{title} {summary}".lower()
    if _HIGH.search(text):
        return "high"
    if _MEDIUM.search(text):
        return "medium"
    return "low"
