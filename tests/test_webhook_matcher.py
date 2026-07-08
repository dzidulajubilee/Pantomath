from pantomath.alerts.matcher import matches_webhook


def _item(**overrides):
    base = {
        "id": "i1", "title": "Ransomware hits Acme Corp",
        "summary": "LockBit affiliates exploited a Microsoft flaw",
        "severity": "high", "source_id": "src-1",
    }
    base.update(overrides)
    return base


def test_no_filters_matches_everything():
    webhook = {"keyword": "", "source_id": "", "min_severity": ""}
    assert matches_webhook(webhook, _item()) is True


def test_keyword_filter_matches_title():
    webhook = {"keyword": "ransomware", "source_id": "", "min_severity": ""}
    assert matches_webhook(webhook, _item()) is True


def test_keyword_filter_matches_summary():
    webhook = {"keyword": "lockbit", "source_id": "", "min_severity": ""}
    assert matches_webhook(webhook, _item()) is True


def test_keyword_filter_rejects_non_matching():
    webhook = {"keyword": "phishing", "source_id": "", "min_severity": ""}
    assert matches_webhook(webhook, _item()) is False


def test_keyword_filter_is_or_matched_across_commas():
    webhook = {"keyword": "phishing, ransomware, malware", "source_id": "", "min_severity": ""}
    assert matches_webhook(webhook, _item()) is True


def test_source_filter_matches_exact_source():
    webhook = {"keyword": "", "source_id": "src-1", "min_severity": ""}
    assert matches_webhook(webhook, _item()) is True


def test_source_filter_rejects_other_source():
    webhook = {"keyword": "", "source_id": "src-2", "min_severity": ""}
    assert matches_webhook(webhook, _item()) is False


def test_min_severity_high_rejects_low_item():
    webhook = {"keyword": "", "source_id": "", "min_severity": "high"}
    assert matches_webhook(webhook, _item(severity="low")) is False


def test_min_severity_high_accepts_high_item():
    webhook = {"keyword": "", "source_id": "", "min_severity": "high"}
    assert matches_webhook(webhook, _item(severity="high")) is True


def test_min_severity_medium_accepts_high_item():
    webhook = {"keyword": "", "source_id": "", "min_severity": "medium"}
    assert matches_webhook(webhook, _item(severity="high")) is True


def test_all_filters_combined_must_all_pass():
    webhook = {"keyword": "ransomware", "source_id": "src-1", "min_severity": "high"}
    assert matches_webhook(webhook, _item()) is True
    assert matches_webhook(webhook, _item(source_id="other")) is False
    assert matches_webhook(webhook, _item(severity="low")) is False
