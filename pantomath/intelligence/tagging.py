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


# Matching is whole-word, not substring. Substring matching (the original
# approach) tagged ordinary text constantly, and in a threat-intel feed the
# damage compounds: "intelligence" -> Intel, "PHP" -> HP, "ASAP" -> SAP,
# "continue" -> Conti, "display"/"replay" -> Play, and any hash with "f5"
# in it -> F5. A name now only matches when it isn't glued to another
# letter or digit, so "Linux-based", "GitHub's" and "(Cisco)" still match.
_NOT_AFTER_ALNUM = r"(?<![A-Za-z0-9])"
_NOT_BEFORE_ALNUM = r"(?![A-Za-z0-9])"

# Names that are also everyday English words only match with their real
# capitalization: "play a role", "padding oracle" (itself a crypto attack
# name), "threat intel", "zoom in", "meta tags". The residual cost is
# title-case headlines ("Threat Actors At Play") — far rarer than the
# lowercase prose this rules out.
CASE_SENSITIVE_NAMES = {"Apple", "Chrome", "Intel", "Juniper", "Meta", "Oracle", "Play", "Zoom"}

# Extra guards for phrases that are common in exactly this app's feeds.
# "Threat Intel" is capitalized in headlines all the time and is never
# about the chip maker.
_EXTRA_GUARDS = {"Intel": r"(?<![Tt]hreat )"}


def _name_pattern(name: str) -> re.Pattern:
    flags = 0 if name in CASE_SENSITIVE_NAMES else re.IGNORECASE
    guard = _EXTRA_GUARDS.get(name, "")
    return re.compile(guard + _NOT_AFTER_ALNUM + re.escape(name) + _NOT_BEFORE_ALNUM, flags)


# Compiled once at import — extract_tags runs for every stored item and on
# every reprocess, against up to MAX_TEXT_LENGTH chars of article text.
_VENDOR_PATTERNS = [(v, _name_pattern(v)) for v in VENDORS]
_ACTOR_PATTERNS = [(a, _name_pattern(a)) for a in THREAT_ACTORS]


def extract_tags(title: str, summary: str) -> tuple[list[str], list[str]]:
    text = f"{title} {summary}"

    vendors = [name for name, pattern in _VENDOR_PATTERNS if pattern.search(text)]
    actors = [name for name, pattern in _ACTOR_PATTERNS if pattern.search(text)]
    actors += [m.upper().replace(" ", "") for m in ACTOR_PATTERN.findall(text)]

    # de-dupe, preserve order
    vendors = list(dict.fromkeys(vendors))
    actors = list(dict.fromkeys(actors))
    return vendors, actors
