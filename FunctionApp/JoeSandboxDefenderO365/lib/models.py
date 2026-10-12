"""Data models used by the Defender for Office 365 connector.

Connector comments double as durable state, so this module also owns how
they are recognized: each comment kind starts with a fixed header line and
carries ``Name: value`` lines. Comments identify an email by its SHA-256.
(Some comments written on 2026-10-10 also carry an ``Internet Message-ID``
line; it is still recognized but no longer written. Message-IDs of handled
emails are kept in the connector state instead, see ConnectorState.)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re


SUBMISSION_COMMENT_HEADER = "Raw EML submitted to Joe Sandbox."
ANALYSIS_COMMENT_HEADER = "Joe Sandbox analysis for raw EML:"
RESUBMISSION_COMMENT_HEADER = (
    "Previous Joe Sandbox submission is unavailable; resubmitting."
)
UNAVAILABLE_COMMENT_HEADER = "Joe Sandbox: raw email not available for analysis."
SHA_FIELD = "EML SHA256"
MESSAGE_ID_FIELD = "Internet Message-ID"


def parse_graph_datetime(value: object) -> datetime | None:
    """Parse a Graph ISO-8601 timestamp (variable fractional digits, Z suffix)."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    if "." in text:
        # Python < 3.11 accepts only 3 or 6 fractional digits; normalize to 6.
        head, _, rest = text.partition(".")
        digits = "".join(ch for ch in rest if ch.isdigit())
        suffix = rest[len(digits):]
        text = f"{head}.{digits[:6].ljust(6, '0')}{suffix}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def normalize_message_id(value: object) -> str:
    """Return a Message-ID without whitespace and angle brackets ("" if none)."""
    if not isinstance(value, str):
        return ""
    return value.strip().strip("<>").strip()


def comment_header(text: str) -> str:
    return text.split("\n", 1)[0].strip()


def comment_field(text: str, name: str) -> str:
    """Return the value of a ``Name: value`` line of a connector comment."""
    prefix = f"{name}: "
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return ""


def comment_key(text: str) -> tuple:
    """Identify a connector comment by meaning rather than exact wording, so
    format changes never re-post a comment that already exists."""
    header = comment_header(text)
    if header == ANALYSIS_COMMENT_HEADER:
        return (
            "analysis",
            comment_field(text, "Analysis URL"),
            comment_field(text, SHA_FIELD),
        )
    if header == SUBMISSION_COMMENT_HEADER:
        return ("submission", comment_field(text, "Submission ID"))
    if header == RESUBMISSION_COMMENT_HEADER:
        return (
            "resubmission",
            comment_field(text, "Previous submission ID"),
            comment_field(text, SHA_FIELD),
        )
    if header == UNAVAILABLE_COMMENT_HEADER:
        return ("unavailable", comment_field(text, "Reason"))
    return ("text", text)


def comment_matches(text: str, sha256: str, message_ids: set[str]) -> bool:
    """Return whether a connector comment refers to the given email."""
    sha = comment_field(text, SHA_FIELD)
    if sha and sha256 and sha == sha256:
        return True
    message_id = normalize_message_id(comment_field(text, MESSAGE_ID_FIELD))
    return bool(message_id) and message_id in message_ids


def parse_analysis_comment(text: str) -> dict:
    """Rebuild the analysis summary from a connector analysis comment."""
    if comment_header(text) != ANALYSIS_COMMENT_HEADER:
        return {}

    def value(name: str) -> str | None:
        found = comment_field(text, name)
        return None if found in ("", "Unknown", "Unavailable") else found

    url = comment_field(text, "Analysis URL")
    match = re.search(r"/analysis/([^/?#\s]+)", url)
    return {
        "webid": match.group(1) if match else None,
        "detection": (value("Detection") or "unknown").lower(),
        "score": value("Score"),
        "classification": value("Classification"),
        "threatname": value("Threat name"),
    }


def alert_comments(alert: dict) -> list[dict]:
    return [
        item
        for item in alert.get("comments") or []
        if isinstance(item, dict) and item.get("comment")
    ]


def alert_is_final_for(alert: dict, message_id: str) -> bool:
    """Return whether an alert already has a final connector result (analysis
    or "not available") for a Message-ID, so the email need not be
    downloaded again."""
    if not message_id:
        return False
    for item in alert_comments(alert):
        text = item["comment"]
        if comment_header(text) in (
            ANALYSIS_COMMENT_HEADER,
            UNAVAILABLE_COMMENT_HEADER,
        ) and comment_matches(text, "", {message_id}):
            return True
    return False


@dataclass
class PriorSubmission:
    """A submission recovered from a connector comment on a Defender alert."""

    submission_id: str
    analysis_tag: str
    created: datetime | None


@dataclass
class MessageGroup:
    """All alerts and recipients that reference one Internet Message-ID.

    The same phish delivered to many recipients produces one group, so it is
    downloaded and submitted once (each mailbox copy has different transport
    headers and therefore a different hash).
    """

    message_id: str
    raw_message_id: str
    alerts: dict[str, dict] = field(default_factory=dict)
    # (mailbox, deliveryLocation, deliveryAction), unique by mailbox
    recipients: dict[str, tuple[str, str, str]] = field(default_factory=dict)

    def ordered_recipients(self) -> list[tuple[str, str, str]]:
        # Deterministic, so every cycle downloads the same copy (same hash).
        return [self.recipients[key] for key in sorted(self.recipients)]

    def is_final(self) -> bool:
        return bool(self.alerts) and all(
            alert_is_final_for(alert, self.message_id)
            for alert in self.alerts.values()
        )


@dataclass
class EmailEvidence:
    """One byte-exact MIME message associated with one or more MDO alerts."""

    raw_eml: bytes
    sha256: str
    filename: str
    mailbox_user: str
    internet_message_id: str
    graph_message_id: str
    alert_ids: set[str] = field(default_factory=set)
    incident_ids: set[str] = field(default_factory=set)
    comments_by_alert: dict[str, set[str]] = field(default_factory=dict)
    comment_times: dict[str, datetime] = field(default_factory=dict)
    message_ids: set[str] = field(default_factory=set)
    # Hashes of other copies of the same message seen in earlier cycles.
    alias_sha256s: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        message_id = normalize_message_id(self.internet_message_id)
        if message_id:
            self.message_ids.add(message_id)

    def add_alert(self, alert: dict) -> None:
        """Associate another Defender alert with this same MIME message."""
        alert_id = alert.get("id")
        if not alert_id:
            return

        self.alert_ids.add(alert_id)
        incident_id = alert.get("incidentId")
        if incident_id:
            self.incident_ids.add(str(incident_id))

        comments = self.comments_by_alert.setdefault(alert_id, set())
        for item in alert_comments(alert):
            text = item["comment"]
            comments.add(text)
            created = parse_graph_datetime(item.get("createdDateTime"))
            if created and (
                text not in self.comment_times or created > self.comment_times[text]
            ):
                self.comment_times[text] = created

    def record_comment(self, alert_id: str, comment: str) -> None:
        """Remember a comment the connector just wrote to an alert."""
        self.comments_by_alert.setdefault(alert_id, set()).add(comment)
        self.comment_times[comment] = datetime.now(timezone.utc)

    def has_comment(self, alert_id: str, comment: str) -> bool:
        """Return whether an alert already has a comment with the same meaning."""
        key = comment_key(comment)
        return any(
            comment_key(existing) == key
            for existing in self.comments_by_alert.get(alert_id, set())
        )

    def matches(self, comment: str) -> bool:
        if comment_matches(comment, self.sha256, self.message_ids):
            return True
        return comment_field(comment, SHA_FIELD) in self.alias_sha256s

    def _matching(self, header: str) -> list[str]:
        texts = set().union(*self.comments_by_alert.values()) if self.comments_by_alert else set()
        return [
            text
            for text in texts
            if comment_header(text) == header and self.matches(text)
        ]

    def _newest(self, texts: list[str]) -> str | None:
        if not texts:
            return None
        oldest = datetime.min.replace(tzinfo=timezone.utc)
        return max(texts, key=lambda text: self.comment_times.get(text) or oldest)

    def previous_submission(self) -> PriorSubmission | None:
        """Recover the newest prior submission for this email."""
        candidates = [
            text
            for text in self._matching(SUBMISSION_COMMENT_HEADER)
            if comment_field(text, "Submission ID")
        ]
        newest = self._newest(candidates)
        if newest is None:
            return None
        return PriorSubmission(
            comment_field(newest, "Submission ID"),
            comment_field(newest, "Joe Sandbox tag"),
            self.comment_times.get(newest),
        )

    def previous_submission_id(self) -> str:
        """Recover a prior connector submission ID for this email."""
        prior = self.previous_submission()
        return prior.submission_id if prior else ""

    def resubmission_count(self) -> int:
        return len(
            {
                comment_key(text)
                for text in self._matching(RESUBMISSION_COMMENT_HEADER)
            }
        )

    def latest_analysis_comment(self) -> str | None:
        return self._newest(self._matching(ANALYSIS_COMMENT_HEADER))

    def is_enriched(self) -> bool:
        """Return whether every related alert already has this email's result."""
        if not self.alert_ids:
            return False
        return all(
            any(
                comment_header(comment) == ANALYSIS_COMMENT_HEADER
                and self.matches(comment)
                for comment in self.comments_by_alert.get(alert_id, set())
            )
            for alert_id in self.alert_ids
        )


@dataclass
class Submission:
    """A Joe Sandbox submission tied back to its raw email evidence."""

    submission_id: str
    evidence: EmailEvidence
    analysis_tag: str


@dataclass
class WaitItem:
    """Something to poll in Joe Sandbox until it finishes.

    ``kind`` is ``"submission"`` (polled with submission_info) or
    ``"analysis"`` (an already running analysis found by hash, polled with
    analysis_info). ``evidence`` is None for items restored from state; the
    workflow rebuilds it from the stored alert IDs once the item finishes.
    """

    kind: str
    joe_id: str
    sha256: str
    alert_ids: set[str]
    incident_ids: set[str]
    analysis_tag: str = ""
    created: str = ""
    evidence: EmailEvidence | None = None
    message_ids: set[str] = field(default_factory=set)

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.joe_id}"

    def refers_to(self, evidence: EmailEvidence) -> bool:
        return (bool(self.sha256) and self.sha256 == evidence.sha256) or bool(
            self.message_ids & evidence.message_ids
        )


@dataclass(frozen=True)
class Indicator:
    """A normalized IOC accepted by the Defender indicator API."""

    indicator_type: str
    value: str
