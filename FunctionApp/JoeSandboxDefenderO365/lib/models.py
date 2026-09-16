"""Data models used by the Defender for Office 365 connector."""

from dataclasses import dataclass, field


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

    def add_alert(self, alert: dict) -> None:
        """Associate another Defender alert with this same MIME message."""
        alert_id = alert.get("id")
        if not alert_id:
            return

        self.alert_ids.add(alert_id)
        incident_id = alert.get("incidentId")
        if incident_id:
            self.incident_ids.add(incident_id)

        comments = {
            item.get("comment")
            for item in alert.get("comments", [])
            if isinstance(item, dict) and item.get("comment")
        }
        self.comments_by_alert.setdefault(alert_id, set()).update(comments)

    def previous_submission(self) -> tuple[str, str]:
        """Recover a prior submission ID and its Joe Sandbox correlation tag."""
        hash_line = f"EML SHA256: {self.sha256}"
        for comments in self.comments_by_alert.values():
            for comment in comments:
                if not comment.startswith("Raw EML submitted to Joe Sandbox.\n"):
                    continue
                lines = comment.splitlines()
                if hash_line not in lines:
                    continue
                submission_id = ""
                analysis_tag = ""
                for line in lines:
                    if line.startswith("Submission ID: "):
                        submission_id = line.removeprefix("Submission ID: ").strip()
                    elif line.startswith("Joe Sandbox tag: "):
                        analysis_tag = line.removeprefix(
                            "Joe Sandbox tag: "
                        ).strip()
                if submission_id:
                    return submission_id, analysis_tag
        return "", ""

    def previous_submission_id(self) -> str:
        """Recover a prior connector submission ID for this exact EML hash."""
        return self.previous_submission()[0]


@dataclass
class Submission:
    """A Joe Sandbox submission tied back to its raw email evidence."""

    submission_id: str
    evidence: EmailEvidence
    analysis_tag: str


@dataclass(frozen=True)
class Indicator:
    """A normalized IOC accepted by the Defender indicator API."""

    indicator_type: str
    value: str
