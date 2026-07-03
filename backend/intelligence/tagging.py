"""
Lightweight rule-based tagging — the "Generate Tags" step of the intel
pipeline (fetch -> normalize -> ... -> generate tags -> score -> store).

This is intentionally simple: curated keyword/pattern matching, not NLP or
an LLM call. It's fast, has zero external dependencies, and is transparent
about what it can and can't catch. Extend the lists below as needed; if
you outgrow keyword matching, this is the file to replace with something
smarter without touching any other module.
"""
import re

VENDORS = [
    "Microsoft", "Cisco", "Fortinet", "Ivanti", "VMware", "Oracle", "Apple",
    "Google", "Adobe", "SAP", "IBM", "Citrix", "Juniper", "Palo Alto",
    "Zoom", "SolarWinds", "Atlassian", "GitLab", "GitHub", "Amazon", "AWS",
    "Meta", "Samsung", "Dell", "HP", "Intel", "Linux", "Android", "Chrome",
    "Firefox", "WordPress", "MOVEit", "Okta", "CrowdStrike", "Check Point",
    "SonicWall", "F5", "Zyxel", "QNAP", "Synology", "TP-Link", "D-Link",
]

# Named ransomware/APT groups worth flagging explicitly, plus generic
# actor-naming conventions (APT29, UNC1234, FIN7, TA453, ...).
THREAT_ACTORS = [
    "LockBit", "BlackCat", "ALPHV", "Conti", "REvil", "Cl0p", "Clop",
    "BianLian", "Akira", "Rhysida", "Medusa", "RansomHub", "Scattered Spider",
    "Lazarus", "Sandworm", "Volt Typhoon", "Salt Typhoon", "Play", "Hunters International",
]
ACTOR_PATTERN = re.compile(r"\b(APT[-\s]?\d{1,3}|UNC\d{3,5}|FIN\d{1,2}|TA\d{3,4})\b", re.IGNORECASE)


def extract_tags(title: str, summary: str) -> tuple[list[str], list[str]]:
    text = f"{title} {summary}"
    text_lower = text.lower()

    vendors = [v for v in VENDORS if v.lower() in text_lower]
    actors = [a for a in THREAT_ACTORS if a.lower() in text_lower]
    actors += [m.upper().replace(" ", "") for m in ACTOR_PATTERN.findall(text)]

    # de-dupe, preserve order
    vendors = list(dict.fromkeys(vendors))
    actors = list(dict.fromkeys(actors))
    return vendors, actors
