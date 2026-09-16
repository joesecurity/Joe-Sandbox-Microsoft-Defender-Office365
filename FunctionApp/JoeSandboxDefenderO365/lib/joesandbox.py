"""Narrow Joe Sandbox API wrapper for raw EML submissions."""

from __future__ import annotations

from io import BytesIO
import json
import logging
from time import monotonic, sleep
from typing import Generator
from uuid import uuid4

from jbxapi import ConnectionError, InvalidApiKeyError, InvalidParameterError
from jbxapi import JoeSandbox as JoeAPI
from jbxapi import PermissionError, ServerOfflineError

from ..const import JOE_CONFIG, JoeSandboxConfig
from .iocs import parse_irjson_indicators
from .models import EmailEvidence, Indicator, Submission


class JoeSandbox:
    """Submit complete email messages and retrieve their analysis metadata."""

    def __init__(
        self,
        log: logging.Logger,
        config: JoeSandboxConfig = JOE_CONFIG,
    ) -> None:
        self.log = log
        self.config = config
        self.api = self._authenticate()

    def _authenticate(self) -> JoeAPI:
        try:
            api = JoeAPI(
                apiurl=self.config.api_url,
                apikey=self.config.api_key,
                verify_ssl=True,
                user_agent=self.config.connector_name,
                accept_tac=self.config.accept_terms,
                retries=self.config.api_retries,
                timeout=self.config.api_timeout_seconds,
            )
            api.server_online()
            self.log.info("Authenticated and verified the Joe Sandbox API")
            return api
        except InvalidApiKeyError as error:
            self.log.error("Invalid Joe Sandbox API key: %s", error)
            raise
        except PermissionError as error:
            self.log.error("Joe Sandbox API permission denied: %s", error)
            raise
        except (ConnectionError, ServerOfflineError) as error:
            self.log.error("Joe Sandbox is unavailable: %s", error)
            raise

    def get_analysis(self, query: str) -> list[dict]:
        """Search Joe Sandbox by the raw EML SHA-256."""
        try:
            return self.api.analysis_search(query) or []
        except (InvalidParameterError, ConnectionError) as error:
            self.log.error("Joe Sandbox analysis search failed: %s", error)
            raise

    def get_analysis_info(self, web_id: str) -> dict:
        """Return the current state and summary for one analysis."""
        try:
            return self.api.analysis_info(web_id) or {}
        except (InvalidParameterError, ConnectionError) as error:
            self.log.error("Joe Sandbox analysis lookup failed: %s", error)
            raise

    def get_submission_info(self, submission_id: str) -> dict:
        """Return Joe Sandbox metadata for one raw-EML submission."""
        try:
            return self.api.submission_info(submission_id) or {}
        except (InvalidParameterError, ConnectionError) as error:
            self.log.error("Joe Sandbox submission lookup failed: %s", error)
            raise

    def get_indicators(self, web_id: str) -> list[Indicator]:
        """Download IRJSON and return its malicious Defender-compatible IOCs."""
        try:
            response = self.api.analysis_download(web_id, type="irjsonfixed")
        except (InvalidParameterError, ConnectionError) as error:
            self.log.error("Joe Sandbox IOC report download failed: %s", error)
            raise

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

    def submit_raw_email(self, evidence: EmailEvidence) -> Submission:
        """Submit exactly one complete MIME message via jbxapi.submit_sample."""
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
            response = self.api.submit_sample(sample=stream, params=params)
        except PermissionError as error:
            self.log.error("Joe Sandbox submission permission denied: %s", error)
            raise
        except (InvalidParameterError, ConnectionError) as error:
            self.log.error("Joe Sandbox raw EML submission failed: %s", error)
            raise

        submission_id = str(response.get("submission_id", ""))
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

    def wait_submissions(
        self, submissions: list[Submission]
    ) -> Generator[tuple[Submission, dict], None, None]:
        """Yield submission-info objects that finish within the configured deadline."""
        pending = {item.submission_id: item for item in submissions}
        deadline = monotonic() + self.config.analysis_job_timeout_seconds

        while pending and monotonic() < deadline:
            for submission_id, submission in list(pending.items()):
                try:
                    info = self.api.submission_info(submission_id)
                except (InvalidParameterError, ConnectionError) as error:
                    self.log.warning(
                        "Joe Sandbox submission %s is not ready: %s",
                        submission_id,
                        error,
                    )
                    continue

                status = str(info.get("status", "")).lower()
                if status == "finished":
                    pending.pop(submission_id)
                    yield submission, info
                elif status in {"failed", "error", "cancelled", "canceled"}:
                    pending.pop(submission_id)
                    self.log.error(
                        "Joe Sandbox submission %s ended with status %s",
                        submission_id,
                        status,
                    )

            if pending and monotonic() < deadline:
                sleep(self.config.poll_interval_seconds)

        for submission_id in pending:
            self.log.warning(
                "Joe Sandbox submission %s is still pending after the configured "
                "timeout",
                submission_id,
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
