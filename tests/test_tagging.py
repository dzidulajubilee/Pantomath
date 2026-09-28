import pytest

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


# --- Regressions: names used to match as substrings of ordinary words ---
# Each of these produced a wrong vendor/actor tag with substring matching,
# and several are everyday vocabulary in exactly the feeds Pantomath reads.

@pytest.mark.parametrize("text, wrong_tag", [
    ("New threat intelligence report released", "Intel"),
    ("Weekly Threat Intel roundup", "Intel"),
    ("Critical PHP flaw patched", "HP"),
    ("Please patch ASAP", "SAP"),
    ("SHA256 3af5c0e9d1b2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4", "F5"),
    ("a meta-analysis of breach costs", "Meta"),
    ("attack uses a padding oracle", "Oracle"),
    ("users can zoom in on the map", "Zoom"),
])
def test_vendor_names_do_not_match_inside_ordinary_words(text, wrong_tag):
    vendors, _ = extract_tags(text, "")
    assert wrong_tag not in vendors


@pytest.mark.parametrize("text, wrong_tag", [
    ("Attackers continue to target edge devices", "Conti"),
    ("Malicious ads on display networks", "Play"),
    ("Replay attack bypasses MFA", "Play"),
    ("Identity plays a key role", "Play"),
    ("Regulators play a role in disclosure", "Play"),
])
def test_actor_names_do_not_match_inside_ordinary_words(text, wrong_tag):
    _, actors = extract_tags(text, "")
    assert wrong_tag not in actors


@pytest.mark.parametrize("text, vendor", [
    ("Intel patches CPU flaw", "Intel"),
    ("HP printers vulnerable", "HP"),
    ("SAP NetWeaver zero-day", "SAP"),
    ("F5 BIG-IP exploited", "F5"),
    ("Oracle WebLogic RCE", "Oracle"),
    ("Meta fixes WhatsApp bug", "Meta"),
    ("Linux-based routers hijacked", "Linux"),
    ("GitHub's token leak", "GitHub"),
    ("Flaw in TP-Link routers", "TP-Link"),
    ("palo alto firewall bug", "Palo Alto"),  # non-ambiguous names stay case-insensitive
])
def test_real_vendor_mentions_still_match(text, vendor):
    vendors, _ = extract_tags(text, "")
    assert vendor in vendors


@pytest.mark.parametrize("text, actor", [
    ("Play ransomware hits city", "Play"),
    ("Conti leaks resurface", "Conti"),
    ("Cl0p exploits MOVEit", "Cl0p"),
    ("Scattered Spider targets help desks", "Scattered Spider"),
])
def test_real_actor_mentions_still_match(text, actor):
    _, actors = extract_tags(text, "")
    assert actor in actors
