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
