from pantomath.intelligence.ioc_extraction import extract_iocs


def test_extracts_cve():
    iocs = extract_iocs("Oracle patches CVE-2026-46817", "actively exploited")
    assert "CVE-2026-46817" in iocs["cve"]


def test_cve_case_insensitive_normalized_to_upper():
    iocs = extract_iocs("cve-2026-12345 disclosed", "")
    assert "CVE-2026-12345" in iocs["cve"]


def test_extracts_valid_ipv4():
    iocs = extract_iocs("C2 server at 91.132.163.78 observed", "")
    assert "91.132.163.78" in iocs["ip"]


def test_rejects_invalid_octet_ranges():
    # 999 and 300 aren't valid IP octets — this shouldn't match as an IP at all
    iocs = extract_iocs("Version 999.300.1.1 released", "")
    assert iocs["ip"] == []


def test_filters_common_noise_ips():
    iocs = extract_iocs("Example config uses 127.0.0.1 and 8.8.8.8", "for local testing")
    assert iocs["ip"] == []


def test_extracts_md5_hash():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    iocs = extract_iocs(f"Malware sample hash {md5} identified", "")
    assert md5 in iocs["hash"]


def test_extracts_sha256_hash():
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"[:64]
    iocs = extract_iocs(f"Payload hash {sha256}", "")
    assert sha256 in iocs["hash"]


def test_extracts_email():
    iocs = extract_iocs("Contact phisher@malicious-domain.com for details", "")
    assert "phisher@malicious-domain.com" in iocs["email"]


def test_hash_case_insensitive_deduped_and_lowercased():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    iocs = extract_iocs(f"Sample hash {md5} also seen as {md5.upper()}", "")
    assert iocs["hash"] == [md5]


def test_email_case_insensitive_deduped_and_lowercased():
    iocs = extract_iocs("From Phisher@Malicious-Domain.com to phisher@malicious-domain.com", "")
    assert iocs["email"] == ["phisher@malicious-domain.com"]


def test_no_false_positives_on_clean_text():
    iocs = extract_iocs("Routine software update released", "no security impact, nothing notable")
    assert iocs == {"cve": [], "ip": [], "hash": [], "email": []}


def test_multiple_cves_deduped():
    iocs = extract_iocs("Affects CVE-2026-1111 and CVE-2026-1111 again, also CVE-2026-2222", "")
    assert iocs["cve"].count("CVE-2026-1111") == 1
    assert "CVE-2026-2222" in iocs["cve"]
