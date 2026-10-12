"""Pure formatting of Joe Sandbox results for Defender comments and tags."""

from __future__ import annotations

import re

from .lib.models import (
    ANALYSIS_COMMENT_HEADER,
    RESUBMISSION_COMMENT_HEADER,
    SHA_FIELD,
    SUBMISSION_COMMENT_HEADER,
    UNAVAILABLE_COMMENT_HEADER,
)


VERDICT_TAG_PREFIX = "#Joe Sandbox "
# Joe Sandbox analysis "detection" values, highest priority first. An incident
# keeps the most severe verdict seen across all of its emails.
VERDICT_PRIORITY = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0}


def _format_value(value: object, fallback: str = "Unknown") -> str:
    if value is None or value == "":
        return fallback
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item) for item in value) or fallback
    return str(value)


def analysis_comment(analysis: dict, sha256: str, base_url: str) -> str:
    """Build a deterministic Defender comment for one Joe Sandbox result."""
    web_id = _format_value(analysis.get("webid"), "")
    report_url = (
        f"{base_url.rstrip('/')}/analysis/{web_id}"
        if web_id
        else "Unavailable"
    )
    return "\n".join(
        (
            ANALYSIS_COMMENT_HEADER,
            "",
            f"{SHA_FIELD}: {sha256}",
            f"Detection: {_format_value(analysis.get('detection')).upper()}",
            f"Score: {_format_value(analysis.get('score'))}",
            f"Classification: {_format_value(analysis.get('classification'))}",
            f"Threat name: {_format_value(analysis.get('threatname'))}",
            f"Analysis URL: {report_url}",
        )
    )


def submission_comment(
    submission_id: str, sha256: str, analysis_tag: str = ""
) -> str:
    """Build the immediate acknowledgement placed on related alerts."""
    lines = [
        SUBMISSION_COMMENT_HEADER,
        f"{SHA_FIELD}: {sha256}",
        f"Submission ID: {submission_id}",
    ]
    if analysis_tag:
        lines.append(f"Joe Sandbox tag: {analysis_tag}")
    return "\n".join(lines)


def resubmission_comment(submission_id: str, sha256: str, reason: str) -> str:
    """Explain why an earlier submission is abandoned and the EML resubmitted."""
    return "\n".join(
        (
            RESUBMISSION_COMMENT_HEADER,
            f"{SHA_FIELD}: {sha256}",
            f"Previous submission ID: {submission_id}",
            f"Reason: {reason}",
        )
    )


def unavailable_comment(reason: str) -> str:
    """Explain on an alert why its email could not be analyzed."""
    return "\n".join((UNAVAILABLE_COMMENT_HEADER, f"Reason: {reason}"))


def _verdict(analysis: dict) -> str:
    detection = str(analysis.get("detection") or "").strip().lower()
    return detection if detection in VERDICT_PRIORITY else "unknown"


def verdict_tag(analysis: dict) -> str:
    """Return the single Joe Sandbox verdict tag for one analysis."""
    return f"{VERDICT_TAG_PREFIX}{_verdict(analysis).title()}"


def _tag_priority(tag: str) -> int:
    verdict = tag[len(VERDICT_TAG_PREFIX):].strip().lower()
    return VERDICT_PRIORITY.get(verdict, -1)


def _is_verdict_tag(tag: object) -> bool:
    return isinstance(tag, str) and tag.lower().startswith(
        VERDICT_TAG_PREFIX.lower()
    )


def threat_name_tag(analysis: dict) -> str:
    """Return a bounded tag for the Joe Sandbox threat name, if any."""
    threat_name = re.sub(
        r"[^A-Za-z0-9 _.-]", "", _format_value(analysis.get("threatname"), "")
    ).strip()
    return threat_name[:60]


def merge_incident_tags(existing: list, analysis: dict) -> list[str]:
    """Merge one analysis into an incident's tags.

    Non-Joe tags are kept unchanged. The incident carries exactly one
    ``#Joe Sandbox <Verdict>`` tag: the highest-priority verdict among the
    current tag and this analysis (malicious > suspicious > clean > unknown),
    so a clean email never downgrades an incident already tagged malicious.
    """
    existing = [tag for tag in existing or [] if isinstance(tag, str)]
    current = [tag for tag in existing if _is_verdict_tag(tag)]
    candidate = verdict_tag(analysis)
    best = max([*current, candidate], key=_tag_priority)
    if _tag_priority(best) == _tag_priority(candidate):
        # Normalize spelling/case to the canonical tag for that verdict.
        best = candidate

    # Keep the existing order: the verdict tag replaces the first old verdict
    # tag in place, or is appended when there was none.
    merged = []
    for tag in existing:
        if not _is_verdict_tag(tag):
            merged.append(tag)
        elif best not in merged:
            merged.append(best)
    if best not in merged:
        merged.append(best)
    threat_tag = threat_name_tag(analysis)
    if threat_tag:
        merged.append(threat_tag)
    return list(dict.fromkeys(merged))


def incident_tags(analysis: dict) -> list[str]:
    """Create bounded incident tags from Joe Sandbox summary fields."""
    tags = [verdict_tag(analysis)]
    threat_tag = threat_name_tag(analysis)
    if threat_tag:
        tags.append(threat_tag)
    return tags

