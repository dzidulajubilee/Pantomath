from pantomath.intelligence.tagging import extract_tags


def test_extracts_known_vendor():
    vendors, actors = extract_tags("Microsoft Exchange flaw", "affects on-prem servers")
    assert "Microsoft" in vendors


def test_extracts_named_ransomware_gang():
    vendors, actors = extract_tags("LockBit claims new victim", "ransomware group")
    assert "LockBit" in actors


def test_extracts_apt_style_codename_via_regex():
    vendors, actors = extract_tags("APT29 linked to new campaign", "")
    assert "APT29" in actors


def test_extracts_unc_style_codename():
    vendors, actors = extract_tags("UNC1234 observed exploiting", "a known flaw")
    assert "UNC1234" in actors


def test_no_false_positives_on_unrelated_text():
    vendors, actors = extract_tags("Routine software update released", "no security impact")
    assert vendors == []
    assert actors == []


def test_multiple_vendors_deduped_and_ordered():
    vendors, _ = extract_tags("Cisco and Fortinet interop issue, also Cisco again", "")
    assert vendors.count("Cisco") == 1
    assert "Fortinet" in vendors
