"""
Rule-based IOC (Indicator of Compromise) extraction — same philosophy as
pantomath/intelligence/tagging.py: fast regex matching, zero external
dependencies, transparent about what it can and can't catch. No IOC
validation service, no threat-intel API lookups — just pattern matching
against article text at store time.

Extend/tune the patterns below as needed; this is the one file to touch
if you want smarter or additional IOC types later.
"""
import re

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Deliberately requires each octet to be a valid 0-255 value, so we don't
# match arbitrary "x.y.z.w"-shaped version numbers or IDs as if they were
# IP addresses.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4_PATTERN = re.compile(rf"\b{_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET}\b")

MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Common false-positive IPs that show up in prose/examples constantly —
# not real indicators, just noise worth filtering by default.
_IP_NOISE = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8"}


def extract_iocs(title: str, summary: str) -> dict[str, list[str]]:
    text = f"{title} {summary}"

    cves = list(dict.fromkeys(m.upper() for m in CVE_PATTERN.findall(text)))
    ips = list(dict.fromkeys(m for m in IPV4_PATTERN.findall(text) if m not in _IP_NOISE))
    # Local-part is technically case-sensitive per RFC 5321, but every real
    # mailbox provider treats it as case-insensitive in practice, and leaving
    # case untouched here let the same address masquerade as two "distinct"
    # IOCs whenever a source happened to capitalize it differently.
    emails = list(dict.fromkeys(m.lower() for m in EMAIL_PATTERN.findall(text)))

    # Hashes: check the longer patterns first so a 64-char SHA256 isn't
    # also reported as containing a 32-char MD5 substring match. Lowercased
    # for the same reason as emails above — hex hashes are case-insensitive,
    # so normalize before dedup or "ABCD..." and "abcd..." count as two
    # distinct IOCs instead of one seen twice.
    hashes = list(dict.fromkeys(h.lower() for h in SHA256_PATTERN.findall(text)))
    matched_spans = set(hashes)
    hashes += [h.lower() for h in SHA1_PATTERN.findall(text) if h.lower() not in matched_spans]
    matched_spans.update(hashes)
    hashes += [h.lower() for h in MD5_PATTERN.findall(text) if h.lower() not in matched_spans]
    hashes = list(dict.fromkeys(hashes))

    return {"cve": cves, "ip": ips, "hash": hashes, "email": emails}
