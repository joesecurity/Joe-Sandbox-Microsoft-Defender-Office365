"""Narrow Joe Sandbox API wrapper for raw EML submissions."""

from __future__ import annotations

from io import BytesIO
import json
import logging
import re
from time import monotonic, sleep
from typing import Generator
from uuid import uuid4

from jbxapi import ConnectionError, InvalidApiKeyError, InvalidParameterError
from jbxapi import JoeException
from jbxapi import JoeSandbox as JoeAPI
from jbxapi import PermissionError, ServerOfflineError

from ..const import JOE_CONFIG, JoeSandboxConfig
from .iocs import parse_irjson_indicators
from .models import EmailEvidence, Indicator, Submission, WaitItem
from .network import (
    NETWORK_ERRORS,
    JoeSandboxUnavailable,
    describe,
    is_connect_failure,
    is_network_error,
)

FAILED_STATUSES = {"failed", "error", "cancelled", "canceled"}
RUNNING_STATUSES = {"submitted", "running", "queued", "accepted"}


# jbxapi reports non-JSON responses (e.g. a load balancer error page) as
# "The server responded with an unexpected format (502). ..."
_GATEWAY_STATUS = re.compile(r"\((502|503|504)\)")


def as_joe_error(error: BaseException) -> BaseException:
    """Wrap a raw network error that escaped jbxapi's own wrapping (rare:
    urllib3/socket errors while reading a body) like jbxapi would."""
    if isinstance(error, JoeException) or not is_network_error(error):
        return error
    wrapped = ConnectionError(error)
    wrapped.__cause__ = error
    return wrapped


def unavailability(error: BaseException) -> str | None:
    """Return why Joe Sandbox is unreachable, or None if ``error`` only
    concerns the one request (read timeout, API error for this item).

    jbxapi wraps every requests exception (after its own timeout retries) in
    jbxapi.ConnectionError; only connection-level failures mean that Joe
    Sandbox as a whole cannot be reached.
    """
    if isinstance(error, ServerOfflineError):
        return f"Joe Sandbox is in maintenance: {error}"
    if isinstance(error, ConnectionError) and is_connect_failure(error):
        return f"cannot connect to Joe Sandbox: {describe(error)}"
    if (
        isinstance(error, JoeException)
        and not isinstance(error, ConnectionError)
        and _GATEWAY_STATUS.search(str(error))
    ):
        return f"Joe Sandbox gateway error: {error}"
    return None


class JoeQuotaExhausted(Exception):
    """The Joe Sandbox submission quota (daily or monthly) is used up.

    Only submissions stop; enrichment from finished analyses continues. The
    affected alerts are deferred, not charged a failed attempt.
    """


class JoeSandbox:
    """Submit complete email messages and retrieve their analysis metadata.

    The client is created without network calls; the API is verified lazily
    on first use so that a cycle with nothing to submit never depends on Joe
    Sandbox being reachable.
    """

    def __init__(
        self,
        log: logging.Logger,
        config: JoeSandboxConfig = JOE_CONFIG,
    ) -> None:
        self.log = log
        self.config = config
        self.api = JoeAPI(
            apiurl=self.config.api_url,
            apikey=self.config.api_key,
            verify_ssl=True,
            user_agent=self.config.connector_name,
            accept_tac=self.config.accept_terms,
            retries=self.config.api_retries,
            timeout=self.config.api_timeout_seconds,
        )
        self._verified = False
        self._quota_checked = False
        self._quota_remaining: int | None = None

    def _ensure_online(self) -> None:
        if self._verified:
            return
        try:
            try:
                status = self.api.server_online() or {}
            except NETWORK_ERRORS as error:
                raise as_joe_error(error)
        except InvalidApiKeyError as error:
            self.log.error("Invalid Joe Sandbox API key: %s", error)
            raise
        except PermissionError as error:
            self.log.error("Joe Sandbox API permission denied: %s", error)
            raise
        except JoeException as error:
            # Any failure of the lightweight online check means Joe Sandbox
            # cannot be used this cycle.
            raise JoeSandboxUnavailable(
                unavailability(error) or f"Joe Sandbox online check failed: {describe(error)}"
            ) from error
        if not isinstance(status, dict) or not status.get("online"):
            raise JoeSandboxUnavailable(
                "Joe Sandbox reports that it is offline (maintenance)"
            )
        self._verified = True
        self.log.info("Authenticated and verified the Joe Sandbox API (online)")

    def _call(self, description: str, func, *args, **kwargs):
        """Run one jbxapi call, mapping outages to JoeSandboxUnavailable.

        Other jbxapi errors (including a read timeout on this one request)
        are re-raised as JoeException for the per-item error handling.
        """
        self._ensure_online()
        try:
            try:
                return func(*args, **kwargs)
            except NETWORK_ERRORS as error:
                raise as_joe_error(error)
        except JoeException as error:
            reason = unavailability(error)
            if reason:
                raise JoeSandboxUnavailable(f"{description}: {reason}") from error
            self.log.error("%s failed: %s", description, describe(error))
            raise

    def get_analysis(self, query: str) -> list[dict]:
        """Search Joe Sandbox by the raw EML SHA-256."""
        return self._call(
            "Joe Sandbox analysis search", self.api.analysis_search, query
        ) or []

    def get_analysis_info(self, web_id: str) -> dict:
        """Return the current state and summary for one analysis."""
        return self._call(
            "Joe Sandbox analysis lookup", self.api.analysis_info, web_id
        ) or {}

    def get_submission_info(self, submission_id: str) -> dict:
        """Return Joe Sandbox metadata for one raw-EML submission.

        Raises InvalidParameterError when the submission does not exist
        (deleted by retention, or an invalid ID).
        """
        return self._call(
            "Joe Sandbox submission lookup", self.api.submission_info, submission_id
        ) or {}

    def get_indicators(self, web_id: str) -> list[Indicator]:
        """Download IRJSON and return its malicious Defender-compatible IOCs."""
        response = self._call(
            "Joe Sandbox IOC report download",
            self.api.analysis_download,
            web_id,
            type="irjsonfixed",
        )

        if not response or len(response) < 2:
            self.log.warning("Joe Sandbox returned no IOC report for %s", web_id)
            return []

        report_data = response[1]
        if hasattr(report_data, "read"):
            report_data = report_data.read()
        try:
            if isinstance(report_data, bytes):
                report_data = report_data.decode("utf-8")
            report = json.loads(report_data)
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
            self.log.error(
                "Joe Sandbox returned invalid IRJSON for %s: %s", web_id, error
            )
            return []

        indicators = parse_irjson_indicators(report)
        self.log.info(
            "Extracted %d malicious indicators from Joe Sandbox analysis %s",
            len(indicators),
            web_id,
        )
        return indicators

    @staticmethod
    def status_of(item: dict) -> str:
        return str(item.get("status") or "").strip().lower()

    @staticmethod
    def parse_analysis(analysis: list[dict] | dict | None) -> dict:
        """Select the highest-scoring analysis and retain enrichment fields."""
        if isinstance(analysis, dict):
            selected = analysis
        elif isinstance(analysis, list):
            candidates = [item for item in analysis if isinstance(item, dict)]
            if not candidates:
                return {}
            selected = max(candidates, key=lambda item: item.get("score", 0) or 0)
        else:
            return {}

        fields = (
            "webid",
            "analysisid",
            "status",
            "detection",
            "score",
            "classification",
            "threatname",
            "filename",
            "sha256",
        )
        return {field: selected[field] for field in fields if field in selected}

    def select_existing_analysis(
        self, analyses: list[dict]
    ) -> tuple[dict, list[dict]]:
        """Split hash-search results into the best finished analysis and the
        analyses still running.

        A running analysis has no final verdict yet; enriching from it would
        write a permanent "UNKNOWN" result.
        """
        candidates = [item for item in analyses or [] if isinstance(item, dict)]
        finished = [item for item in candidates if self.status_of(item) == "finished"]
        running = [
            item
            for item in candidates
            if self.status_of(item) in RUNNING_STATUSES and item.get("webid")
        ]
        best = self.parse_analysis(finished) if finished else {}
        return best, running

    def submission_quota_remaining(self) -> int | None:
        """Return the remaining Joe Sandbox Cloud submission quota (the lower
        of daily and monthly), checked once per cycle and counted down
        locally. None when unknown (on-premise appliances have no quota API).
        """
        if self._quota_checked:
            return self._quota_remaining
        self._quota_checked = True
        try:
            info = self._call(
                "Joe Sandbox account info", self.api.account_info
            ) or {}
        except JoeException as error:
            self.log.info("Joe Sandbox quota is not available (%s)", describe(error))
            return None
        quota = info.get("quota") if isinstance(info, dict) else None
        remaining = [
            period.get("remaining")
            for period in ((quota or {}).get("daily"), (quota or {}).get("monthly"))
            if isinstance(period, dict) and isinstance(period.get("remaining"), int)
        ]
        self._quota_remaining = min(remaining) if remaining else None
        self.log.info(
            "Joe Sandbox submission quota remaining: %s",
            "unlimited/unknown" if self._quota_remaining is None else self._quota_remaining,
        )
        return self._quota_remaining

    def submit_raw_email(self, evidence: EmailEvidence) -> Submission:
        """Submit exactly one complete MIME message via jbxapi.submit_sample.

        Raises JoeQuotaExhausted instead of submitting once the quota is used
        up, or when Joe Sandbox rejects the submission for quota reasons.
        """
        remaining = self.submission_quota_remaining()
        if remaining is not None and remaining <= 0:
            raise JoeQuotaExhausted("Joe Sandbox submission quota is exhausted")
        stream = BytesIO(evidence.raw_eml)
        stream.name = evidence.filename
        analysis_tag = f"MDO-{uuid4().hex}"
        params = {
            "tags": ["Defender-O365-Raw-EML", analysis_tag],
            "comments": (
                "Raw EML from Microsoft Defender for Office 365 alert(s): "
                + ", ".join(sorted(evidence.alert_ids))
                + f"; correlation tag: {analysis_tag}"
            ),
        }
        try:
            response = self._call(
                "Joe Sandbox raw EML submission",
                self.api.submit_sample,
                sample=stream,
                params=params,
            )
        except JoeException as error:
            if "quota" in str(error).lower():
                self._quota_checked = True
                self._quota_remaining = 0
                raise JoeQuotaExhausted(str(error)) from error
            raise
        if self._quota_remaining is not None:
            self._quota_remaining -= 1

        submission_id = str((response or {}).get("submission_id") or "")
        if not submission_id:
            raise ValueError("Joe Sandbox returned no submission_id")
        self.log.info(
            "Submitted raw EML %s to Joe Sandbox as submission %s",
            evidence.sha256,
            submission_id,
        )
        return Submission(
            submission_id=submission_id,
            evidence=evidence,
            analysis_tag=analysis_tag,
        )

    def wait(
        self, items: list[WaitItem], deadline: float
    ) -> Generator[tuple[str, WaitItem, dict | str], None, None]:
        """Poll submissions/analyses until they finish or the deadline passes.

        Yields ``("finished", item, info)`` or ``("failed", item, reason)``.
        Items still running at the deadline are not yielded; the caller keeps
        them as pending for the next cycle. Temporary errors for one request
        (API internal error, read timeout) only skip one poll; if Joe Sandbox
        becomes unreachable, JoeSandboxUnavailable is raised.
        """
        pending = {item.key: item for item in items}
        if pending:
            self._ensure_online()

        while pending and monotonic() < deadline:
            for key, item in list(pending.items()):
                if monotonic() >= deadline:
                    break
                try:
                    try:
                        if item.kind == "analysis":
                            info = self.api.analysis_info(item.joe_id) or {}
                        else:
                            info = self.api.submission_info(item.joe_id) or {}
                    except NETWORK_ERRORS as error:
                        raise as_joe_error(error)
                except InvalidParameterError as error:
                    pending.pop(key)
                    self.log.error(
                        "Joe Sandbox %s %s no longer exists: %s",
                        item.kind,
                        item.joe_id,
                        error,
                    )
                    yield "failed", item, f"not found ({error})"
                    continue
                except JoeException as error:
                    reason = unavailability(error)
                    if reason:
                        # Stop waiting instead of spending the time budget on
                        # calls that cannot succeed; items stay pending.
                        raise JoeSandboxUnavailable(
                            f"Joe Sandbox became unreachable while waiting: {reason}"
                        ) from error
                    self.log.warning(
                        "Temporary Joe Sandbox error while polling %s %s: %s",
                        item.kind,
                        item.joe_id,
                        describe(error),
                    )
                    continue

                status = self.status_of(info)
                if status == "finished":
                    pending.pop(key)
                    yield "finished", item, info
                elif status in FAILED_STATUSES:
                    pending.pop(key)
                    self.log.error(
                        "Joe Sandbox %s %s ended with status %s",
                        item.kind,
                        item.joe_id,
                        status,
                    )
                    yield "failed", item, f"status {status}"

            remaining = deadline - monotonic()
            if pending and remaining > 0:
                sleep(min(self.config.poll_interval_seconds, remaining))

        for item in pending.values():
            self.log.warning(
                "Joe Sandbox %s %s is still running at the end of this cycle's "
                "wait; it will be checked again next cycle",
                item.kind,
                item.joe_id,
            )

    @staticmethod
    def most_relevant_web_id(submission_info: dict) -> str:
        """Extract Joe Sandbox server's most relevant analysis web ID."""
        most_relevant = submission_info.get("most_relevant_analysis") or {}
        web_id = most_relevant.get("webid")
        return str(web_id) if web_id else ""

    def get_most_relevant_analysis(self, submission_info: dict) -> dict:
        """Return metadata for the analysis Joe selected for this submission."""
        web_id = self.most_relevant_web_id(submission_info)
        if not web_id:
            return {}
        return self.parse_analysis(self.get_analysis_info(web_id))
