"""Raw-email processing, submission recovery, and Defender enrichment.

Clients and state are supplied by the host so the workflow can be exercised
without Azure Functions, Blob Storage, credentials, or network calls.

One polling cycle runs in three phases:

1. Pending submissions saved by earlier cycles are checked first and
   enriched if Joe Sandbox has finished them, independent of the alert
   window.
2. Alerts updated since the watermark (plus alerts that failed or were
   deferred in earlier cycles) are grouped by Internet Message-ID, so a
   message delivered to many recipients is downloaded and submitted once.
   Each message is downloaded, handled and released before the next one:
   skipped (already enriched; its incidents are re-synced), recovered from
   an earlier submission, enriched from an existing analysis, submitted, or
   marked as not available (quarantined, blocked, no mailbox access). A
   failure only affects the alerts of that one message; they are retried up
   to FailedAlertMaxAttempts times. When the function time budget or the
   Joe Sandbox quota runs out, the remaining alerts are deferred to the next
   cycle without being charged an attempt.
3. The connector waits (bounded by the analysis timeout and the function
   time budget) for submissions to finish and enriches them. Anything still
   running stays in the saved state for the next cycle.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from time import monotonic
from typing import TYPE_CHECKING, Callable

from jbxapi import InvalidParameterError, JoeException

from .const import FINAL_MESSAGE_RETENTION_HOURS, STATE_CONFIG
from .lib.joesandbox import FAILED_STATUSES, JoeQuotaExhausted
from .lib.models import (
    EmailEvidence,
    MessageGroup,
    WaitItem,
    parse_analysis_comment,
    parse_graph_datetime,
)
from .lib.network import ServiceUnavailable
from .reporting import (
    analysis_comment,
    resubmission_comment,
    submission_comment,
    unavailable_comment,
)
from .state_manager import ConnectorState

if TYPE_CHECKING:
    from .lib.joesandbox import JoeSandbox
    from .lib.microsoft_defender import MicrosoftDefender

MAX_RESUBMISSIONS = 2

COUNT_KEYS = (
    "alerts",
    "raw_emails",
    "already_enriched",
    "existing_analyses",
    "existing_running",
    "previous_submissions",
    "pending_resolved",
    "pending_expired",
    "submitted",
    "resubmitted",
    "finished",
    "still_pending",
    "unavailable_emails",
    "deferred_alerts",
    "failed_alerts",
    "dropped_alerts",
    "indicators_succeeded",
    "indicators_failed",
    "ioc_report_failures",
)


def _isoformat(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def enrich(
    defender: MicrosoftDefender,
    joe: JoeSandbox,
    evidence: EmailEvidence,
    analysis: dict,
    counts: dict[str, int] | None = None,
) -> tuple[int, int]:
    """Write Joe Sandbox results to every related alert and incident.

    The alert comment is written last: it is the marker that the email is
    fully enriched (see EmailEvidence.is_enriched), so a failure in an
    earlier step leaves the email to be retried.
    """
    counts = counts if counts is not None else dict.fromkeys(COUNT_KEYS, 0)
    succeeded = 0
    failed = 0
    if defender.indicators_enabled_for(analysis):
        web_id = str(analysis.get("webid", ""))
        indicators = []
        try:
            indicators = joe.get_indicators(web_id)
        except ServiceUnavailable:
            raise
        except Exception:
            counts["ioc_report_failures"] += 1
            logging.exception(
                "Joe Sandbox IOC report download failed for analysis %s", web_id
            )
        if indicators:
            try:
                succeeded, failed = defender.create_indicators(
                    indicators, analysis, evidence
                )
            except ServiceUnavailable:
                # Defender API unreachable: let the whole email be retried
                # instead of marking it enriched without its indicators.
                raise
            except Exception:
                # Raised only before any import (existing-indicator lookup or
                # authentication), so none of these indicators were created.
                failed = len(indicators)
                logging.exception(
                    "Microsoft Defender indicator import failed for analysis %s",
                    web_id,
                )
    counts["indicators_succeeded"] += succeeded
    counts["indicators_failed"] += failed

    comment = analysis_comment(analysis, evidence.sha256, joe.config.base_url)
    defender.add_incident_tags(evidence.incident_ids, analysis)
    defender.add_incident_comments(evidence.incident_ids, comment)
    defender.add_alert_comment(evidence, comment)
    return succeeded, failed


class _Cycle:
    """State and helpers for one polling cycle."""

    def __init__(
        self,
        defender: MicrosoftDefender,
        joe: JoeSandbox,
        state: ConnectorState,
        run_deadline: float | None = None,
    ) -> None:
        self.defender = defender
        self.joe = joe
        self.state = state
        self.run_deadline = run_deadline
        self.now = datetime.now(timezone.utc)
        self.ttl = timedelta(hours=STATE_CONFIG.pending_submission_ttl_hours)
        self.counts = dict.fromkeys(COUNT_KEYS, 0)
        self.waiting: dict[str, WaitItem] = {}
        self.refetch_alert_ids: set[str] = set()
        self.alert_errors: dict[str, str] = {}
        self.not_found: dict[str, tuple[str, str]] = {}
        self.deferred: set[str] = set()
        self.alerts_by_id: dict[str, dict] = {}

    # Helpers -------------------------------------------------------------

    def _out_of_time(self) -> bool:
        return self.run_deadline is not None and monotonic() >= self.run_deadline

    def _track(self, item: WaitItem) -> None:
        self.waiting[item.key] = item
        self.state.add_pending(item)

    def _requeue_alerts(self, item: WaitItem, reason: str) -> None:
        """Make the alerts of a dead submission get re-fetched and resubmitted
        next cycle, without consuming one of their failure attempts."""
        for alert_id in item.alert_ids:
            record = self.state.failed_alerts.get(alert_id, {})
            self.state.failed_alerts[alert_id] = {
                "attempts": record.get("attempts", 0),
                "last_error": reason,
                "last_attempt": _isoformat(self.now),
            }

    def _defer(self, alert_ids: set[str], reason: str) -> None:
        """Postpone alerts to the next cycle without charging an attempt.
        Alerts deferred for longer than PendingSubmissionTTLHours are given up."""
        for alert_id in alert_ids:
            if alert_id in self.alert_errors:
                continue
            record = dict(self.state.failed_alerts.get(alert_id, {}))
            since = record.get("deferred_since") or _isoformat(self.now)
            started = parse_graph_datetime(since)
            if started and self.now - started > self.ttl:
                logging.error(
                    "Giving up on alert %s: deferred for more than %d hours (%s)",
                    alert_id,
                    STATE_CONFIG.pending_submission_ttl_hours,
                    reason,
                )
                self.state.failed_alerts.pop(alert_id, None)
                self.counts["dropped_alerts"] += 1
                self.deferred.add(alert_id)
                continue
            record.update(
                {
                    "attempts": record.get("attempts", 0),
                    "last_error": reason,
                    "last_attempt": _isoformat(self.now),
                    "deferred_since": since,
                }
            )
            self.state.failed_alerts[alert_id] = record
            self.deferred.add(alert_id)
            self.counts["deferred_alerts"] += 1

    def _evidence_for(self, item: WaitItem) -> EmailEvidence:
        """Return the evidence for a finished item, re-fetching alerts that
        are not loaded in this cycle so comment deduplication stays exact."""
        evidence = item.evidence or EmailEvidence(
            raw_eml=b"",
            sha256=item.sha256,
            filename="",
            mailbox_user="",
            internet_message_id="",
            graph_message_id="",
        )
        evidence.message_ids |= item.message_ids
        for alert_id in sorted(item.alert_ids - evidence.alert_ids):
            alert = self.alerts_by_id.get(alert_id) or self.defender.get_alert(alert_id)
            if alert is None:
                logging.warning("Alert %s no longer exists; skipping it", alert_id)
                continue
            evidence.add_alert(alert)
        evidence.incident_ids |= item.incident_ids
        return evidence

    def _finish(self, item: WaitItem, info: dict) -> bool:
        """Enrich Defender from a finished Joe item. Returns False if Joe has
        no analysis to report."""
        if item.kind == "analysis":
            analysis = self.joe.parse_analysis(info)
        else:
            analysis = self.joe.get_most_relevant_analysis(info)
        if not analysis or not analysis.get("webid"):
            logging.warning(
                "Joe Sandbox %s %s finished without a most relevant analysis",
                item.kind,
                item.joe_id,
            )
            return False
        evidence = self._evidence_for(item)
        enrich(self.defender, self.joe, evidence, analysis, self.counts)
        self._record_enriched(evidence)
        return True

    def _enrich_failed(self, item: WaitItem, error: Exception) -> None:
        record = self.state.pending.get(item.key)
        if record is None:
            return
        attempts = int(record.get("enrich_attempts", 0)) + 1
        if attempts >= STATE_CONFIG.failed_alert_max_attempts:
            logging.error(
                "Giving up enriching Defender from Joe Sandbox %s %s after %d "
                "attempts: %s",
                item.kind,
                item.joe_id,
                attempts,
                error,
            )
            self.state.remove_pending(item.key)
        else:
            record["enrich_attempts"] = attempts

    def _record_enriched(self, evidence: EmailEvidence) -> None:
        """Remember that every alert of this email has its result, so later
        re-fetches skip it without downloading (see ConnectorState)."""
        self.state.record_final(
            evidence.message_ids,
            evidence.alert_ids,
            evidence.sha256,
            "enriched",
            self.now,
        )

    def _sync_incidents(self, evidence: EmailEvidence) -> None:
        """Bring the incidents of an already enriched email up to date.

        An alert can be correlated into an incident (or moved to another
        one) after it was enriched; the alert is then "done" but the new
        incident has no tag or comment. The result is rebuilt from the
        connector's own analysis comment, so no Joe Sandbox call is needed.
        """
        if not evidence.incident_ids:
            return
        text = evidence.latest_analysis_comment()
        if not text:
            return
        self.defender.add_incident_tags(
            evidence.incident_ids, parse_analysis_comment(text)
        )
        self.defender.add_incident_comments(evidence.incident_ids, text)

    # Phase 1 ---------------------------------------------------------------

    def resolve_stored_pending(self) -> None:
        for item in self.state.pending_items():
            created = parse_graph_datetime(item.created)
            if created and self.now - created > self.ttl:
                logging.warning(
                    "Dropping Joe Sandbox %s %s: still pending after %d hours",
                    item.kind,
                    item.joe_id,
                    STATE_CONFIG.pending_submission_ttl_hours,
                )
                self.state.remove_pending(item.key)
                self.counts["pending_expired"] += 1
                continue
            try:
                if item.kind == "analysis":
                    info = self.joe.get_analysis_info(item.joe_id)
                else:
                    info = self.joe.get_submission_info(item.joe_id)
            except ServiceUnavailable:
                raise
            except InvalidParameterError as error:
                self.state.remove_pending(item.key)
                self._requeue_alerts(item, f"Joe Sandbox {item.kind} not found: {error}")
                self.refetch_alert_ids |= item.alert_ids
                continue
            except JoeException as error:
                logging.warning(
                    "Temporary Joe Sandbox error for pending %s %s: %s",
                    item.kind,
                    item.joe_id,
                    error,
                )
                self.waiting[item.key] = item
                continue

            status = self.joe.status_of(info)
            if status == "finished":
                try:
                    self._finish(item, info)
                    self.state.remove_pending(item.key)
                    self.counts["pending_resolved"] += 1
                except ServiceUnavailable:
                    raise
                except Exception as error:
                    logging.exception(
                        "Enrichment from pending Joe Sandbox %s %s failed",
                        item.kind,
                        item.joe_id,
                    )
                    self._enrich_failed(item, error)
            elif status in FAILED_STATUSES:
                self.state.remove_pending(item.key)
                self._requeue_alerts(item, f"Joe Sandbox {item.kind} status {status}")
                self.refetch_alert_ids |= item.alert_ids
            else:
                self.waiting[item.key] = item

    # Phase 2 ---------------------------------------------------------------

    def load_alerts(self, since_iso8601: str) -> list[dict]:
        alerts = self.defender.get_alerts(since_iso8601)
        fetched = {alert["id"] for alert in alerts}
        retry_ids = (set(self.state.failed_alerts) | self.refetch_alert_ids) - fetched
        extra = []
        for alert_id in sorted(retry_ids):
            try:
                alert = self.defender.get_alert(alert_id)
            except ServiceUnavailable:
                raise
            except Exception as error:
                self.alert_errors[alert_id] = f"{type(error).__name__}: {error}"
                continue
            if alert is None:
                logging.warning(
                    "Previously failed alert %s no longer exists; forgetting it",
                    alert_id,
                )
                self.state.failed_alerts.pop(alert_id, None)
                continue
            extra.append(alert)
        if extra:
            logging.info("Retrying %d previously failed or deferred alerts", len(extra))
            alerts = self.defender.filter_and_sort_alerts(alerts + extra)
        return alerts

    def _recover_prior(self, evidence: EmailEvidence) -> str | None:
        """Handle an earlier submission recorded in an alert comment.

        Returns None when the email is fully handled, "" when there is no
        earlier submission, or the reason why the earlier submission is
        unusable and the email must be resubmitted.
        """
        prior = evidence.previous_submission()
        if prior is None:
            return ""
        # Fan the acknowledgement out to alerts that joined later (deduplicated
        # by submission ID, whatever the comment wording).
        self.defender.add_alert_comment(
            evidence,
            submission_comment(
                prior.submission_id, evidence.sha256, prior.analysis_tag
            ),
        )
        try:
            info = self.joe.get_submission_info(prior.submission_id)
        except InvalidParameterError:
            return "submission not found in Joe Sandbox (deleted or invalid ID)"

        status = self.joe.status_of(info)
        if status == "finished":
            analysis = self.joe.get_most_relevant_analysis(info)
            if not analysis:
                logging.warning(
                    "Joe Sandbox submission %s has no most relevant analysis",
                    prior.submission_id,
                )
            else:
                enrich(self.defender, self.joe, evidence, analysis, self.counts)
                self._record_enriched(evidence)
            self.counts["previous_submissions"] += 1
            return None
        if status in FAILED_STATUSES:
            return f"submission ended with status {status}"
        if prior.created and self.now - prior.created > self.ttl:
            return (
                f"submission still {status or 'running'} after "
                f"{STATE_CONFIG.pending_submission_ttl_hours} hours"
            )
        self._track(
            WaitItem(
                kind="submission",
                joe_id=prior.submission_id,
                sha256=evidence.sha256,
                alert_ids=set(evidence.alert_ids),
                incident_ids=set(evidence.incident_ids),
                analysis_tag=prior.analysis_tag,
                created=_isoformat(prior.created or self.now),
                evidence=evidence,
                message_ids=set(evidence.message_ids),
            )
        )
        self.counts["previous_submissions"] += 1
        return None

    def process_evidence(self, evidence: EmailEvidence) -> None:
        if evidence.is_enriched():
            self.counts["already_enriched"] += 1
            self._sync_incidents(evidence)
            self._record_enriched(evidence)
            return

        for item in self.waiting.values():
            if item.refers_to(evidence):
                # Already tracked (pending from an earlier cycle): attach this
                # cycle's alerts so all of them are enriched when it finishes.
                item.alert_ids |= evidence.alert_ids
                item.incident_ids |= evidence.incident_ids
                item.message_ids |= evidence.message_ids
                if item.evidence is None:
                    item.evidence = evidence
                elif item.evidence is not evidence:
                    for alert_id in evidence.alert_ids - item.evidence.alert_ids:
                        item.evidence.alert_ids.add(alert_id)
                        item.evidence.comments_by_alert[alert_id] = set(
                            evidence.comments_by_alert.get(alert_id, set())
                        )
                    item.evidence.incident_ids |= evidence.incident_ids
                    item.evidence.message_ids |= evidence.message_ids
                    item.evidence.comment_times.update(evidence.comment_times)
                self.state.add_pending(item)
                self.counts["previous_submissions"] += 1
                return

        reason = self._recover_prior(evidence)
        if reason is None:
            return
        resubmitting = bool(reason)
        if resubmitting:
            if evidence.resubmission_count() >= MAX_RESUBMISSIONS:
                logging.error(
                    "Not resubmitting EML %s again: %s, and it was already "
                    "resubmitted %d times",
                    evidence.sha256,
                    reason,
                    MAX_RESUBMISSIONS,
                )
                return
            prior = evidence.previous_submission()
            logging.warning(
                "Resubmitting EML %s: previous submission %s unusable (%s)",
                evidence.sha256,
                prior.submission_id if prior else "unknown",
                reason,
            )

        if not self.joe.config.resubmit and not resubmitting:
            finished, running = self.joe.select_existing_analysis(
                self.joe.get_analysis(evidence.sha256)
            )
            if finished.get("webid"):
                enrich(self.defender, self.joe, evidence, finished, self.counts)
                self._record_enriched(evidence)
                self.counts["existing_analyses"] += 1
                return
            if running:
                web_id = str(running[0]["webid"])
                logging.info(
                    "Joe Sandbox analysis %s for EML %s is still running; "
                    "waiting for it instead of resubmitting",
                    web_id,
                    evidence.sha256,
                )
                self._track(
                    WaitItem(
                        kind="analysis",
                        joe_id=web_id,
                        sha256=evidence.sha256,
                        alert_ids=set(evidence.alert_ids),
                        incident_ids=set(evidence.incident_ids),
                        created=_isoformat(self.now),
                        evidence=evidence,
                        message_ids=set(evidence.message_ids),
                    )
                )
                self.counts["existing_running"] += 1
                return

        # Raises JoeQuotaExhausted before submitting if the quota is used up.
        submission = self.joe.submit_raw_email(evidence)
        if resubmitting:
            prior = evidence.previous_submission()
            self.defender.add_alert_comment(
                evidence,
                resubmission_comment(
                    prior.submission_id if prior else "unknown",
                    evidence.sha256,
                    reason,
                ),
            )
        self.counts["resubmitted" if resubmitting else "submitted"] += 1
        # Save to state before commenting so a failed comment cannot orphan it.
        self._track(
            WaitItem(
                kind="submission",
                joe_id=submission.submission_id,
                sha256=evidence.sha256,
                alert_ids=set(evidence.alert_ids),
                incident_ids=set(evidence.incident_ids),
                analysis_tag=submission.analysis_tag,
                created=_isoformat(self.now),
                evidence=evidence,
                message_ids=set(evidence.message_ids),
            )
        )
        self.defender.add_alert_comment(
            evidence,
            submission_comment(
                submission.submission_id,
                evidence.sha256,
                submission.analysis_tag,
            ),
        )

    def _mark_unavailable(self, group: MessageGroup, reason: str) -> None:
        """Tell the SOC on each alert why its email cannot be analyzed."""
        logging.warning(
            "Email <%s> cannot be analyzed: %s", group.message_id, reason
        )
        self.counts["unavailable_emails"] += 1
        comment = unavailable_comment(reason)
        done = set()
        for alert_id, alert in group.alerts.items():
            try:
                self.defender.add_comment_to_alert(alert, comment)
                done.add(alert_id)
            except ServiceUnavailable:
                raise
            except Exception as error:
                self.alert_errors[alert_id] = f"{type(error).__name__}: {error}"
        self.state.record_final({group.message_id}, done, "", "unavailable", self.now)

    def _process_group(self, group: MessageGroup) -> None:
        known_sha256 = self.state.final_sha256(group.message_id)
        if group.is_final() or self.state.is_final(
            group.message_id, set(group.alerts)
        ):
            # Every alert already has the result (or a "not available" note)
            # for this Message-ID: no download needed.
            self.counts["already_enriched"] += 1
            evidence = EmailEvidence(
                raw_eml=b"",
                sha256=known_sha256,
                filename="",
                mailbox_user="",
                internet_message_id=group.raw_message_id,
                graph_message_id="",
            )
            for alert in group.alerts.values():
                evidence.add_alert(alert)
            self._sync_incidents(evidence)
            return

        resolution = self.defender.resolve_group(group)
        if resolution.error:
            for alert_id in group.alerts:
                self.alert_errors[alert_id] = resolution.error
            return
        if resolution.not_found:
            # Possibly not yet searchable (mailbox index delay): retry as a
            # failed alert; the "not available" note is posted on give-up.
            for alert_id in group.alerts:
                self.alert_errors[alert_id] = resolution.not_found
                self.not_found[alert_id] = (group.message_id, resolution.not_found)
            return
        if resolution.unavailable:
            self._mark_unavailable(group, resolution.unavailable)
            return

        evidence = resolution.evidence
        if known_sha256 and known_sha256 != evidence.sha256:
            # A different recipient's copy than last time: comments written
            # for the earlier copy still belong to this email.
            evidence.alias_sha256s.add(known_sha256)
        self.counts["raw_emails"] += 1
        try:
            self.process_evidence(evidence)
        finally:
            # Release the MIME bytes; tracked items only need the metadata.
            evidence.raw_eml = b""

    def process_alerts(self, since_iso8601: str) -> None:
        self.state.prune_final(
            self.now, timedelta(hours=FINAL_MESSAGE_RETENTION_HOURS)
        )
        alerts = self.load_alerts(since_iso8601)
        self.alerts_by_id = {alert["id"]: alert for alert in alerts}
        self.counts["alerts"] = len(alerts)
        groups = self.defender.group_messages(alerts)
        quota_exhausted = False

        for index, group in enumerate(groups):
            if self._out_of_time():
                remaining = {
                    alert_id for later in groups[index:] for alert_id in later.alerts
                }
                logging.warning(
                    "Function time budget reached; deferring %d emails (%d alerts) "
                    "to the next cycle",
                    len(groups) - index,
                    len(remaining),
                )
                self._defer(remaining, "deferred: function time budget reached")
                break
            try:
                self._process_group(group)
            except ServiceUnavailable:
                raise
            except JoeQuotaExhausted as error:
                if not quota_exhausted:
                    logging.error(
                        "%s; new emails are deferred until quota is available "
                        "(enrichment from existing analyses continues)",
                        error,
                    )
                quota_exhausted = True
                self._defer(set(group.alerts), f"deferred: {error}")
            except Exception as error:
                logging.exception(
                    "Processing email <%s> (alerts %s) failed",
                    group.message_id,
                    ", ".join(sorted(group.alerts)),
                )
                for alert_id in group.alerts:
                    self.alert_errors[alert_id] = f"{type(error).__name__}: {error}"

        logging.info("Processed %d unique emails", len(groups))
        self._update_failed_alerts(set(self.alerts_by_id))

    def _update_failed_alerts(self, processed_ids: set[str]) -> None:
        for alert_id in processed_ids - set(self.alert_errors) - self.deferred:
            self.state.failed_alerts.pop(alert_id, None)
        for alert_id, error in self.alert_errors.items():
            record = self.state.failed_alerts.get(alert_id, {})
            attempts = int(record.get("attempts", 0)) + 1
            if attempts >= STATE_CONFIG.failed_alert_max_attempts:
                logging.error(
                    "Giving up on alert %s after %d failed attempts: %s",
                    alert_id,
                    attempts,
                    error,
                )
                self.state.failed_alerts.pop(alert_id, None)
                self.counts["dropped_alerts"] += 1
                self._note_given_up(alert_id, attempts)
            else:
                logging.warning(
                    "Alert %s failed (attempt %d of %d); it will be retried next "
                    "cycle: %s",
                    alert_id,
                    attempts,
                    STATE_CONFIG.failed_alert_max_attempts,
                    error,
                )
                self.state.failed_alerts[alert_id] = {
                    "attempts": attempts,
                    "last_error": error[:500],
                    "last_attempt": _isoformat(self.now),
                }
                self.counts["failed_alerts"] += 1

    def _note_given_up(self, alert_id: str, attempts: int) -> None:
        """For an email that was never found, leave a note on the alert."""
        if alert_id not in self.not_found or alert_id not in self.alerts_by_id:
            return
        message_id, reason = self.not_found[alert_id]
        try:
            self.defender.add_comment_to_alert(
                self.alerts_by_id[alert_id],
                unavailable_comment(f"not found after {attempts} attempts ({reason})"),
            )
            self.state.record_final(
                {message_id}, {alert_id}, "", "unavailable", self.now
            )
        except ServiceUnavailable:
            raise
        except Exception:
            logging.exception("Could not comment on alert %s", alert_id)

    # Phase 3 ---------------------------------------------------------------

    def wait(self, deadline: float) -> None:
        try:
            for event, item, payload in self.joe.wait(
                list(self.waiting.values()), deadline
            ):
                if event == "failed":
                    self.state.remove_pending(item.key)
                    self._requeue_alerts(
                        item, f"Joe Sandbox {item.kind} {item.joe_id}: {payload}"
                    )
                    continue
                try:
                    if self._finish(item, payload):
                        self.counts["finished"] += 1
                    self.state.remove_pending(item.key)
                except ServiceUnavailable:
                    raise
                except Exception as error:
                    logging.exception(
                        "Enrichment from Joe Sandbox %s %s failed",
                        item.kind,
                        item.joe_id,
                    )
                    self._enrich_failed(item, error)
        except ServiceUnavailable as error:
            # Stop waiting; nothing is charged to the pending items.
            logging.error(
                "%s; unfinished submissions stay pending for the next cycle", error
            )
        self.counts["still_pending"] = len(self.state.pending)


def process_alerts(
    since_iso8601: str,
    defender: MicrosoftDefender,
    joe: JoeSandbox,
    state: ConnectorState | None = None,
    *,
    run_deadline: float | None = None,
    checkpoint: Callable[[], None] | None = None,
) -> dict[str, int]:
    """Run one polling cycle with the supplied Microsoft and Joe API clients.

    ``state`` is updated in place (pending submissions, failed alerts).
    ``checkpoint`` is called once all alerts are handled and before the wait,
    so pending submissions survive a host timeout during the wait.
    ``run_deadline`` (a time.monotonic() value) bounds alert processing (the
    rest is deferred) and the wait.

    Raises ServiceUnavailable (JoeSandboxUnavailable / MicrosoftUnavailable)
    when a service cannot be reached; the caller must then not advance the
    watermark. Such outages never count as a failed attempt for an alert or
    a pending submission.
    """
    state = state if state is not None else ConnectorState()
    cycle = _Cycle(defender, joe, state, run_deadline)
    cycle.resolve_stored_pending()
    cycle.process_alerts(since_iso8601)
    if checkpoint:
        checkpoint()

    deadline = monotonic() + joe.config.analysis_job_timeout_seconds
    if run_deadline is not None:
        deadline = min(deadline, run_deadline)
    cycle.wait(deadline)
    return cycle.counts
