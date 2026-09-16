"""Extract normalized malicious indicators from Joe Sandbox IRJSON."""

from __future__ import annotations

from ipaddress import ip_address
import re
from urllib.parse import urlsplit

from .models import Indicator


HASH_TYPES = {
    "md5": ("FileMd5", 32),
    "sha1": ("FileSha1", 40),
    "sha256": ("FileSha256", 64),
}


def _is_true(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return False


def _items(value: object, singular_key: str = "") -> list[dict]:
    if isinstance(value, dict) and singular_key:
        value = value.get(singular_key, value)
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _normalize_domain(value: object) -> str:
    if not isinstance(value, str):
        return ""
    candidate = value.strip().rstrip(".").lower()
    if not candidate or "://" in candidate or "/" in candidate:
        return ""
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    labels = candidate.split(".")
    if (
        len(candidate) > 253
        or len(labels) < 2
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or re.fullmatch(r"[a-z0-9-]+", label) is None
            for label in labels
        )
    ):
        return ""
    return candidate


def _normalize_ip(value: object) -> str:
    if not isinstance(value, str):
        return ""
    try:
        return str(ip_address(value.strip()))
    except ValueError:
        return ""


def _normalize_url(value: object) -> str:
    if not isinstance(value, str):
        return ""
    candidate = value.strip()
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return ""
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    return candidate


def _normalize_hash(value: object, length: int) -> str:
    if not isinstance(value, str):
        return ""
    candidate = value.strip().lower()
    if len(candidate) != length or re.fullmatch(r"[0-9a-f]+", candidate) is None:
        return ""
    return candidate


def parse_irjson_indicators(report: dict) -> list[Indicator]:
    """Return unique Defender-compatible IOCs explicitly marked malicious."""
    if not isinstance(report, dict):
        return []
    analysis = report.get("analysis", {})
    if not isinstance(analysis, dict):
        return []
    contacted = analysis.get("contacted", {})
    dropped = analysis.get("dropped", {})

    indicators: list[Indicator] = []

    if isinstance(contacted, dict):
        for entry in _items(contacted.get("domains", []), "domain"):
            if _is_true(entry.get("malicious")):
                value = _normalize_domain(entry.get("name"))
                if value:
                    indicators.append(Indicator("DomainName", value))

        for entry in _items(contacted.get("ips", []), "ip"):
            if _is_true(entry.get("@malicious", entry.get("malicious"))):
                value = _normalize_ip(entry.get("$", entry.get("name")))
                if value:
                    indicators.append(Indicator("IpAddress", value))

        for entry in _items(contacted.get("urls", []), "url"):
            if _is_true(entry.get("malicious")):
                value = _normalize_url(entry.get("name"))
                if value:
                    indicators.append(Indicator("Url", value))

    file_entries = []
    if isinstance(dropped, dict):
        file_entries = _items(dropped.get("file", []), "file")
    for entry in file_entries:
        if not _is_true(entry.get("malicious")):
            continue
        for field, (indicator_type, length) in HASH_TYPES.items():
            value = _normalize_hash(entry.get(field), length)
            if value:
                indicators.append(Indicator(indicator_type, value))

    unique: dict[tuple[str, str], Indicator] = {}
    for indicator in indicators:
        unique[(indicator.indicator_type, indicator.value)] = indicator
    return list(unique.values())
