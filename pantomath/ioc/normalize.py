"""
What an indicator is, and its one canonical spelling.

Every value goes through here before it is stored or looked up, so
"HXXP://Evil[.]Example./x" from one feed and "http://evil.example/x" from
another are the same row. The rules:

  - IPs: Python's ipaddress form. Only globally routable addresses are
    accepted: private, loopback, link-local, multicast, reserved and the
    documentation ranges are rejected, so your own networks can't become
    indicators. "ip:port" keeps the IP; the port goes into the context.
  - Domains: lowercase, no trailing dot, international names as punycode.
  - URLs: scheme and host lowercased (host as punycode), path kept as is.
  - Hashes, JA3, certificate fingerprints: lowercase hex of the right length.
  - Defanged text (hxxp, [.], [at] ...) is restored first.

JA3 and certificate fingerprints look exactly like MD5 / SHA-1 / SHA-256
hashes, so they are never detected automatically: a feed or an analyst
has to say that's what a list holds. Lookups try every type a value could
be (see `candidates`).
"""
import ipaddress
import re
import urllib.parse

TYPES = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "ja3", "ja4", "x509")
TYPE_LABELS = {
    "ipv4": "IPv4", "ipv6": "IPv6", "domain": "Domain", "url": "URL", "email": "Email",
    "md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "ja3": "JA3", "ja4": "JA4", "x509": "Certificate",
}
# Lifetime in days, counted from the last time any source reported the
# indicator. None = never expires.
DEFAULT_LIFETIME_DAYS = {
    "ipv4": 30, "ipv6": 30, "domain": 90, "url": 90, "email": 90,
    "ja3": 180, "ja4": 180, "x509": 180, "md5": None, "sha1": None, "sha256": None,
}
MAX_VALUE_LENGTH = 2048

_HEX = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX_RE = re.compile(r"[0-9a-f]+")
_JA4_RE = re.compile(r"[tqd]\d{2}[di]\d{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}")
_EMAIL_RE = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+")
_LABEL_RE = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
_TLD_RE = re.compile(r"[a-z]{2,63}|xn--[a-z0-9-]{1,59}")
_SCHEME_RE = re.compile(r"[a-z][a-z0-9+.-]*://", re.I)
_IPV4_PORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})")
_IPV6_PORT_RE = re.compile(r"\[([0-9a-fA-F:.]+)\]:(\d{1,5})")

_REFANG = [
    (re.compile(r"^hxxp", re.I), "http"), (re.compile(r"^fxp", re.I), "ftp"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]"), ":"), (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[@\]|\[at\]|\(at\)", re.I), "@"),
]


class IocValueError(ValueError):
    """A value that can't be an indicator. str() says why, for test results and import reports."""


class NotPublicError(IocValueError):
    """An IP address that is well formed but private, loopback, reserved..., so never an indicator."""


def refang(raw: str) -> str:
    value = (raw or "").strip().strip("\"'<>")
    for pattern, replacement in _REFANG:
        value = pattern.sub(replacement, value)
    return value


def detect(raw: str) -> str | None:
    """The type a value looks like, or None. Never 'ja3' or 'x509' (see the module docstring)."""
    value = refang(raw)
    lower = value.lower()
    if _SCHEME_RE.match(value):
        return "url"
    if "@" in value and _EMAIL_RE.fullmatch(lower):
        return "email"
    if _IPV4_PORT_RE.fullmatch(value) or _is_ip(value, 4):
        return "ipv4"
    if _IPV6_PORT_RE.fullmatch(value) or _is_ip(value, 6):
        return "ipv6"
    if _HEX_RE.fullmatch(lower) and len(lower) in _HEX:
        return _HEX[len(lower)]
    if _JA4_RE.fullmatch(lower):
        return "ja4"
    if "." in value and "/" not in value:
        try:
            _domain(value)
            return "domain"
        except IocValueError:
            return None
    return None


def candidates(raw: str) -> list[tuple[str, str]]:
    """Every (type, value) a looked-up value could be stored as: a 32-character hex string may be an MD5 or a JA3."""
    detected = detect(raw)
    if not detected:
        return []
    types = [detected]
    if detected == "md5":
        types.append("ja3")
    elif detected in ("sha1", "sha256"):
        types.append("x509")
    out = []
    for t in types:
        try:
            value, _ = normalize(t, raw)
        except IocValueError:
            continue
        out.append((t, value))
    return out


def normalize(type_: str | None, raw: str) -> tuple[str, dict]:
    """
    (type, canonical value, extra context such as a port) for one value.
    `type_` None or '' detects the type; a fixed type rejects anything
    that doesn't fit it.
    """
    value = refang(raw)
    if not value:
        raise IocValueError("empty")
    if len(value) > MAX_VALUE_LENGTH:
        raise IocValueError("longer than 2,048 characters")
    if not type_:
        type_ = detect(value)
        if not type_:
            raise IocValueError("not a recognised indicator")
    elif type_ not in TYPES:
        raise IocValueError(f"unknown type '{type_}'")
    return _NORMALIZERS[type_](value)


def normalize_typed(type_: str | None, raw: str) -> tuple[str, str, dict]:
    """Like `normalize`, but also returns the type that was detected."""
    if not type_:
        type_ = detect(refang(raw))
        if not type_:
            raise IocValueError("not a recognised indicator")
    value, context = normalize(type_, raw)
    return type_, value, context


def _is_ip(value: str, version: int) -> bool:
    try:
        return ipaddress.ip_address(value).version == version
    except ValueError:
        return False


def _check_global(ip) -> None:
    if ip.is_multicast or not ip.is_global:
        kind = ("private" if ip.is_private else "loopback" if ip.is_loopback else "link-local" if ip.is_link_local
                else "multicast" if ip.is_multicast else "reserved")
        raise NotPublicError(f"{kind} address, not a public one")


def _ipv4(value: str) -> tuple[str, dict]:
    context = {}
    match = _IPV4_PORT_RE.fullmatch(value)
    if match:
        value, context["port"] = match.group(1), int(match.group(2))
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        raise IocValueError("not an IPv4 address") from None
    _check_global(ip)
    return str(ip), context


def _ipv6(value: str) -> tuple[str, dict]:
    context = {}
    match = _IPV6_PORT_RE.fullmatch(value)
    if match:
        value, context["port"] = match.group(1), int(match.group(2))
    try:
        ip = ipaddress.IPv6Address(value.strip("[]"))
    except ValueError:
        raise IocValueError("not an IPv6 address") from None
    _check_global(ip)
    return str(ip), context


def _punycode(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        raise IocValueError("not a valid domain name") from None


def _domain(value: str) -> tuple[str, dict]:
    host = value.strip().rstrip(".").lower()
    if host.startswith("*."):
        host = host[2:]
    if not host.isascii():
        host = _punycode(host)
    labels = host.split(".")
    if len(labels) < 2 or len(host) > 253 or not all(_LABEL_RE.fullmatch(label) for label in labels):
        raise IocValueError("not a valid domain name")
    if not _TLD_RE.fullmatch(labels[-1]):
        raise IocValueError("not a valid domain name")
    return host, {}


def _url(value: str) -> tuple[str, dict]:
    if not _SCHEME_RE.match(value):
        value = "http://" + value
    try:
        parts = urllib.parse.urlsplit(value)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        raise IocValueError("not a valid URL") from None
    if not host or any(c.isspace() for c in value):
        raise IocValueError("not a valid URL")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        host = _domain(host)[0]
    if ":" in host:
        host = f"[{host}]"
    netloc = host + (f":{port}" if port else "")
    if parts.username or parts.password:
        netloc = parts.netloc.rsplit("@", 1)[0] + "@" + netloc
    return urllib.parse.urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment)), {}


def _email(value: str) -> tuple[str, dict]:
    lower = value.lower()
    if not _EMAIL_RE.fullmatch(lower):
        raise IocValueError("not an email address")
    local, domain = lower.rsplit("@", 1)
    return f"{local}@{_domain(domain)[0]}", {}


def _hex(length: int, name: str):
    def check(value: str) -> tuple[str, dict]:
        lower = value.lower()
        if len(lower) != length or not _HEX_RE.fullmatch(lower):
            raise IocValueError(f"not {name} ({length} hexadecimal characters)")
        return lower, {}
    return check


def _x509(value: str) -> tuple[str, dict]:
    lower = value.lower().replace(":", "")
    if len(lower) not in (40, 64) or not _HEX_RE.fullmatch(lower):
        raise IocValueError("not a certificate fingerprint (SHA-1 or SHA-256 in hexadecimal)")
    return lower, {}


def _ja4(value: str) -> tuple[str, dict]:
    lower = value.lower()
    if not _JA4_RE.fullmatch(lower):
        raise IocValueError("not a JA4 fingerprint")
    return lower, {}


_NORMALIZERS = {
    "ipv4": _ipv4, "ipv6": _ipv6, "domain": _domain, "url": _url, "email": _email,
    "md5": _hex(32, "an MD5 hash"), "sha1": _hex(40, "a SHA-1 hash"), "sha256": _hex(64, "a SHA-256 hash"),
    "ja3": _hex(32, "a JA3 fingerprint"), "ja4": _ja4, "x509": _x509,
}


# ------------------------------------------------------------------ allowlist

def normalize_allow_entry(raw: str) -> tuple[str, str]:
    """(entry type, canonical value) for an allowlist entry typed into Settings."""
    value = refang(raw)
    if not value:
        raise IocValueError("empty")
    try:
        return "cidr", str(ipaddress.ip_network(value.strip("[]"), strict=False))
    except ValueError:
        pass
    type_ = detect(value)
    if type_ == "domain":
        return "domain", _domain(value)[0]
    if type_:
        return "exact", normalize(type_, value)[0]
    raise IocValueError("not an IP, range, domain or indicator")
