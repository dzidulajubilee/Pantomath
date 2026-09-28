import pytest

from pantomath.intelligence.scoring import score_severity


def test_high_severity_keywords():
    assert score_severity("Critical zero-day RCE", "Actively exploited in the wild") == "high"
    assert score_severity("Ransomware gang strikes again", "") == "high"


def test_medium_severity_keywords():
    assert score_severity("New CVE-2026-1234 disclosed", "affects multiple vendors") == "medium"
    assert score_severity("Malware campaign targets", "finance sector") == "medium"


def test_low_severity_default():
    assert score_severity("Routine patch notes", "Minor bug fixes, no security impact") == "low"


def test_high_takes_priority_over_medium():
    # a title matching both a high and a medium keyword should score high
    text_title = "Zero-day vulnerability actively exploited"
    assert score_severity(text_title, "") == "high"


def test_case_insensitive():
    assert score_severity("ACTIVELY EXPLOITED ZERO-DAY", "") == "high"


# --- Regressions: keywords used to match as substrings of ordinary words ---

@pytest.mark.parametrize("text", [
    "Open-source maintainers sign new security pledge",  # "rce" in "source"
    "Cyber insurance: resources for SMEs",               # "rce" in "resources"
    "Police enforcement action announced",               # "rce" in "enforcement"
    "Workforce training survey",                         # "rce" in "workforce"
])
def test_rce_does_not_match_inside_words(text):
    assert score_severity(text, "") != "high"


@pytest.mark.parametrize("text", ["Chapter 3: adapting to change", "Laptop buying guide", "Captured the flag"])
def test_apt_does_not_match_inside_words(text):
    assert score_severity(text, "") == "low"


@pytest.mark.parametrize("text, expected", [
    ("Unauthenticated RCE in edge gateway", "high"),
    ("Flaw exploited as a zero-day", "high"),
    ("Two zero-days patched", "high"),
    ("APT29 phishing campaign", "medium"),
    ("New CVE-2026-1234 disclosed", "medium"),
    ("Patch Tuesday fixes 12 vulnerabilities", "medium"),  # plural used to be missed entirely
    ("Hospital breached by attackers", "medium"),
    ("Two breaches disclosed", "medium"),
])
def test_real_keywords_still_match(text, expected):
    assert score_severity(text, "") == expected
