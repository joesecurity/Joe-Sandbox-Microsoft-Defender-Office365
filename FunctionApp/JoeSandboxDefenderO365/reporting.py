"""Pure formatting of Joe Sandbox results for Defender comments and tags."""

import re


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
            "Joe Sandbox analysis for raw EML:",
            "",
            f"EML SHA256: {sha256}",
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
        "Raw EML submitted to Joe Sandbox.",
        f"EML SHA256: {sha256}",
        f"Submission ID: {submission_id}",
    ]
    if analysis_tag:
        lines.append(f"Joe Sandbox tag: {analysis_tag}")
    return "\n".join(lines)


def incident_tags(analysis: dict) -> list[str]:
    """Create bounded incident tags from Joe Sandbox summary fields."""
    detection = re.sub(
        r"[^A-Za-z0-9 _.-]", "", _format_value(analysis.get("detection"))
    ).strip()
    tags = [f"#Joe Sandbox {detection.title()}"] if detection else []
    threat_name = re.sub(
        r"[^A-Za-z0-9 _.-]", "", _format_value(analysis.get("threatname"), "")
    ).strip()
    if threat_name:
        tags.append(threat_name[:60])
    return tags
