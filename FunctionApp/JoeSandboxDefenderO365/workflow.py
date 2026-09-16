"""Raw-email processing, submission recovery, and Defender enrichment.

Clients are supplied by the host so the workflow can be exercised without
Azure Functions, Blob Storage, credentials, or network calls.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .lib.models import EmailEvidence
from .reporting import analysis_comment, incident_tags, submission_comment

if TYPE_CHECKING:
    from .lib.joesandbox import JoeSandbox
    from .lib.microsoft_defender import MicrosoftDefender


def enrich(
    defender: MicrosoftDefender,
    joe: JoeSandbox,
    evidence: EmailEvidence,
    analysis: dict,
) -> tuple[int, int]:
    """Write Joe Sandbox results to every related alert and incident."""
    indicators_succeeded = 0
    indicators_failed = 0
    if defender.indicators_enabled_for(analysis):
        indicators = []
        try:
            indicators = joe.get_indicators(str(analysis.get("webid", "")))
            indicators_succeeded, indicators_failed = defender.create_indicators(
                indicators, analysis, evidence
            )
        except Exception:
            indicators_failed += max(1, len(indicators))
            logging.exception(
                "Joe Sandbox IOC enrichment failed for analysis %s",
                analysis.get("webid", "unknown"),
            )
    comment = analysis_comment(analysis, evidence.sha256, joe.config.base_url)
    defender.add_alert_comment(evidence, comment)
    defender.add_incident_comments(evidence.incident_ids, comment)
    defender.add_incident_tags(evidence.incident_ids, incident_tags(analysis))
    return indicators_succeeded, indicators_failed


def process_alerts(
    since_iso8601: str,
    defender: MicrosoftDefender,
    joe: JoeSandbox,
) -> dict[str, int]:
    """Process raw emails using the supplied Microsoft and Joe API clients."""
    alerts = defender.get_alerts(since_iso8601)
    evidences = defender.get_email_evidences(alerts)
    submissions = []
    existing_count = 0
    previous_count = 0
    indicators_succeeded = 0
    indicators_failed = 0

    for evidence in evidences:
        prior_submission_id, prior_analysis_tag = evidence.previous_submission()
        if prior_submission_id:
            defender.add_alert_comment(
                evidence,
                submission_comment(
                    prior_submission_id,
                    evidence.sha256,
                    prior_analysis_tag,
                ),
            )
            submission_info = joe.get_submission_info(prior_submission_id)
            if str(submission_info.get("status", "")).lower() == "finished":
                analysis = joe.get_most_relevant_analysis(submission_info)
                if not analysis:
                    logging.warning(
                        "Joe Sandbox submission %s has no most relevant analysis",
                        prior_submission_id,
                    )
                else:
                    succeeded, failed = enrich(
                        defender, joe, evidence, analysis
                    )
                    indicators_succeeded += succeeded
                    indicators_failed += failed
                    existing_count += 1
            previous_count += 1
            continue

        if not joe.config.resubmit:
            existing = joe.parse_analysis(joe.get_analysis(evidence.sha256))
            if existing and existing.get("webid"):
                succeeded, failed = enrich(defender, joe, evidence, existing)
                indicators_succeeded += succeeded
                indicators_failed += failed
                existing_count += 1
                continue

        submission = joe.submit_raw_email(evidence)
        submissions.append(submission)
        defender.add_alert_comment(
            evidence,
            submission_comment(
                submission.submission_id,
                evidence.sha256,
                submission.analysis_tag,
            ),
        )

    finished_count = 0
    for submission, submission_info in joe.wait_submissions(submissions):
        analysis = joe.get_most_relevant_analysis(submission_info)
        if not analysis:
            logging.warning(
                "Joe Sandbox submission %s finished without a most relevant "
                "analysis web ID",
                submission.submission_id,
            )
            continue
        succeeded, failed = enrich(
            defender, joe, submission.evidence, analysis
        )
        indicators_succeeded += succeeded
        indicators_failed += failed
        finished_count += 1

    return {
        "alerts": len(alerts),
        "raw_emails": len(evidences),
        "existing_analyses": existing_count,
        "previous_submissions": previous_count,
        "submitted": len(submissions),
        "finished": finished_count,
        "indicators_succeeded": indicators_succeeded,
        "indicators_failed": indicators_failed,
    }
