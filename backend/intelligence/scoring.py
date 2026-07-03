"""
Lightweight keyword heuristic for triage. Not a replacement for real CTI
scoring (CVSS/EPSS), just a fast visual signal so a human can prioritize
what to read first. Tune the lists below freely.
"""

KEYWORDS_HIGH = [
    "ransomware", "zero-day", "0-day", "critical",
    "exploited in the wild", "rce", "actively exploited",
    "remote code execution", "critical vulnerability",
]

KEYWORDS_MEDIUM = [
    "cve-", "vulnerability", "apt", "breach", "malware",
    "phishing", "backdoor", "supply chain", "data leak",
]


def score_severity(title: str, summary: str) -> str:
    text = f"{title} {summary}".lower()
    if any(k in text for k in KEYWORDS_HIGH):
        return "high"
    if any(k in text for k in KEYWORDS_MEDIUM):
        return "medium"
    return "low"
