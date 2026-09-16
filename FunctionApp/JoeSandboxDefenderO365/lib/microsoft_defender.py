"""Microsoft Graph client for Defender for Office 365 alerts and raw MIME."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import logging
from time import sleep
from urllib.parse import quote

import requests

from ..const import (
    ANALYZED_MESSAGE_EVIDENCE,
    DEFENDER_CONFIG,
    RETRY_STATUS_CODES,
    SEVERITY_ORDER,
    DefenderConfig,
)
from .models import EmailEvidence, Indicator


class MicrosoftDefender:
    """Retrieve MDO alerts and their complete RFC 822/MIME representation."""

    def __init__(
        self,
        log: logging.Logger,
        config: DefenderConfig = DEFENDER_CONFIG,
    ) -> None:
        self.log = log
        self.config = config
        self.graph_headers: dict[str, str] = {}
        self.defender_headers: dict[str, str] = {}
        self._existing_indicator_keys: set[tuple[str, str]] | None = None
        self._incident_comment_cache: dict[str, set[str]] = {}
        self.authenticate()

    def _access_token(self, scope: str) -> str:
        response = self.retry_request(
            "POST",
            self.config.auth_url,
            data={
                "client_id": self.config.application_id,
                "scope": scope,
                "client_secret": self.config.application_secret,
                "grant_type": "client_credentials",
            },
        )
        return response.json()["access_token"]

    def authenticate(self) -> None:
        """Acquire an application token for Microsoft Graph."""
        access_token = self._access_token("https://graph.microsoft.com/.default")
        self.graph_headers = {
            "Authorization": f"Bearer {access_token}",
            "User-Agent": self.config.user_agent,
            "Content-Type": "application/json",
        }
        self.log.info("Authenticated to Microsoft Graph")

    def authenticate_defender_api(self) -> None:
        """Acquire the separate Defender for Endpoint API token on demand."""
        access_token = self._access_token(self.config.defender_api_scope)
        self.defender_headers = {
            "Authorization": f"Bearer {access_token}",
            "User-Agent": self.config.user_agent,
            "Content-Type": "application/json",
        }
        self.log.info("Authenticated to Microsoft Defender for Endpoint")

    def retry_request(
        self,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        params: dict | None = None,
        data: dict | str | None = None,
        json: dict | None = None,
    ) -> requests.Response:
        """Issue a Microsoft API request with bounded transient-failure retries."""
        for attempt in range(self.config.retry_count + 1):
            try:
                response = requests.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json,
                    timeout=self.config.http_timeout_seconds,
                )
                if response.status_code not in RETRY_STATUS_CODES:
                    response.raise_for_status()
                    return response

                if attempt >= self.config.retry_count:
                    response.raise_for_status()

                retry_after = response.headers.get("Retry-After", "")
                delay = (
                    int(retry_after)
                    if retry_after.isdigit()
                    else self.config.retry_delay_seconds
                )
                self.log.warning(
                    "Microsoft API returned HTTP %d; retrying in %d seconds",
                    response.status_code,
                    delay,
                )
                sleep(delay)
            except (requests.ConnectionError, requests.Timeout):
                if attempt >= self.config.retry_count:
                    raise
                self.log.warning(
                    "Microsoft API request failed; retrying in %d seconds",
                    self.config.retry_delay_seconds,
                )
                sleep(self.config.retry_delay_seconds)

        raise RuntimeError("Microsoft API request exhausted all retries")

    def indicators_enabled_for(self, analysis: dict) -> bool:
        """Return whether this analysis verdict is configured for IOC creation."""
        detection = str(analysis.get("detection", "")).strip().lower()
        return (
            self.config.create_indicators
            and detection in self.config.indicator_verdicts
        )

    def _indicator_action(self, indicator: Indicator, detection: str) -> str:
        is_file = indicator.indicator_type.startswith("File")
        if detection == "malicious":
            return (
                self.config.malicious_file_action
                if is_file
                else self.config.malicious_network_action
            )
        return (
            self.config.suspicious_file_action
            if is_file
            else self.config.suspicious_network_action
        )

    @staticmethod
    def _indicator_key(indicator_type: str, value: str) -> tuple[str, str]:
        normalized = value
        if indicator_type.startswith("File") or indicator_type == "DomainName":
            normalized = value.lower()
        return indicator_type, normalized

    def get_existing_indicator_keys(self) -> set[tuple[str, str]]:
        """Return active Defender indicators, cached for this polling cycle."""
        cached = getattr(self, "_existing_indicator_keys", None)
        if cached is not None:
            return cached
        if not self.defender_headers:
            self.authenticate_defender_api()

        keys: set[tuple[str, str]] = set()
        url = f"{self.config.defender_api_url.rstrip('/')}/indicators"
        params: dict[str, str] | None = {"$top": "10000"}
        while url:
            response = self.retry_request(
                "GET", url, headers=self.defender_headers, params=params
            )
            payload = response.json()
            for item in payload.get("value", []):
                indicator_type = str(item.get("indicatorType", ""))
                value = str(item.get("indicatorValue", ""))
                if indicator_type and value:
                    keys.add(self._indicator_key(indicator_type, value))
            url = payload.get("@odata.nextLink")
            params = None

        self._existing_indicator_keys = keys
        self.log.info("Retrieved %d active Microsoft Defender indicators", len(keys))
        return keys

    def create_indicators(
        self,
        indicators: list[Indicator],
        analysis: dict,
        evidence: EmailEvidence,
    ) -> tuple[int, int]:
        """Submit new Joe Sandbox IOCs in batches of 500."""
        if not indicators or not self.indicators_enabled_for(analysis):
            return 0, 0

        existing = self.get_existing_indicator_keys()
        new_indicators = [
            indicator
            for indicator in indicators
            if self._indicator_key(indicator.indicator_type, indicator.value)
            not in existing
        ]
        skipped = len(indicators) - len(new_indicators)
        if skipped:
            self.log.info(
                "Skipped %d IOCs already present in Microsoft Defender", skipped
            )
        if not new_indicators:
            return 0, 0

        detection = str(analysis.get("detection", "")).strip().lower()
        expiration = (
            datetime.now(timezone.utc)
            + timedelta(days=self.config.indicator_expiration_days)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        web_id = str(analysis.get("webid", "")).strip() or "unknown"
        alert_ids = ", ".join(sorted(evidence.alert_ids)) or "unknown"
        description = (
            f"Joe Sandbox {detection} indicator from raw EML analysis {web_id}.\n"
            f"EML SHA256: {evidence.sha256}\n"
            f"Microsoft Defender alert IDs: {alert_ids}"
        )
        severity = "High" if detection == "malicious" else "Medium"

        payloads = []
        for indicator in new_indicators:
            action = self._indicator_action(indicator, detection)
            payloads.append(
                {
                    "indicatorValue": indicator.value,
                    "indicatorType": indicator.indicator_type,
                    "action": action,
                    "application": "Joe Sandbox for Microsoft Defender for Office 365",
                    "title": f"Joe Sandbox {detection} indicator",
                    "description": description,
                    "expirationTime": expiration,
                    "severity": severity,
                    "recommendedActions": (
                        f"Review Joe Sandbox analysis {web_id} and the related alerts."
                    ),
                    "generateAlert": (
                        True
                        if action == "Audit"
                        else self.config.indicator_generate_alert
                    ),
                }
            )

        succeeded = 0
        failed = 0
        url = f"{self.config.defender_api_url.rstrip('/')}/indicators/import"
        for offset in range(0, len(payloads), 500):
            batch = payloads[offset : offset + 500]
            response = self.retry_request(
                "POST",
                url,
                headers=self.defender_headers,
                json={"Indicators": batch},
            )
            results = response.json().get("value", [])
            if not isinstance(results, list) or not results:
                failed += len(batch)
                self.log.error(
                    "Microsoft Defender returned no per-indicator import results"
                )
                continue
            for result in results:
                if result.get("isFailed"):
                    failed += 1
                    self.log.error(
                        "Microsoft Defender rejected indicator %s: %s",
                        result.get("indicator", "unknown"),
                        result.get("failureReason", "unknown reason"),
                    )
                else:
                    succeeded += 1
            if len(results) == len(batch):
                for item, result in zip(batch, results):
                    if not result.get("isFailed"):
                        existing.add(
                            self._indicator_key(
                                item["indicatorType"], item["indicatorValue"]
                            )
                        )
            if len(results) < len(batch):
                failed += len(batch) - len(results)

        self.log.info(
            "Microsoft Defender indicator import completed: %d succeeded, %d failed",
            succeeded,
            failed,
        )
        return succeeded, failed

    def get_alerts(self, since_iso8601: str) -> list[dict]:
        """Return all new MDO alerts, following Microsoft Graph pagination."""
        url = f"{self.config.graph_url}/security/alerts_v2"
        params = {
            "$filter": (
                "serviceSource eq 'microsoftDefenderForOffice365' "
                f"and createdDateTime ge {since_iso8601}"
            ),
            "$top": "100",
        }
        alerts: list[dict] = []

        while url:
            response = self.retry_request(
                "GET", url, headers=self.graph_headers, params=params
            )
            payload = response.json()
            alerts.extend(payload.get("value", []))
            url = payload.get("@odata.nextLink")
            params = None

        if self.config.severities:
            alerts = [
                alert
                for alert in alerts
                if alert.get("severity", "").lower() in self.config.severities
            ]
        alerts.sort(
            key=lambda alert: SEVERITY_ORDER.get(
                alert.get("severity", "").lower(), 99
            )
        )
        self.log.info(
            "Fetched %d Microsoft Defender for Office 365 alerts", len(alerts)
        )
        return alerts

    @staticmethod
    def _message_id_candidates(internet_message_id: str) -> list[str]:
        value = internet_message_id.strip()
        candidates = [value]
        if value and not (value.startswith("<") and value.endswith(">")):
            candidates.append(f"<{value}>")
        return candidates

    def find_message(
        self, mailbox_user: str, internet_message_id: str
    ) -> dict | None:
        """Resolve an Internet Message-ID to a mailbox-scoped Graph message ID."""
        mailbox_path = quote(mailbox_user, safe="")
        url = f"{self.config.graph_url}/users/{mailbox_path}/messages"

        for candidate in self._message_id_candidates(internet_message_id):
            escaped = candidate.replace("'", "''")
            response = self.retry_request(
                "GET",
                url,
                headers=self.graph_headers,
                params={
                    "$filter": f"internetMessageId eq '{escaped}'",
                    "$select": "id,internetMessageId,subject,receivedDateTime",
                    "$top": "2",
                },
            )
            messages = response.json().get("value", [])
            if messages:
                if len(messages) > 1:
                    self.log.warning(
                        "Multiple mailbox messages matched one Internet Message-ID; "
                        "using the first result"
                    )
                return messages[0]
        return None

    def download_raw_email(
        self, mailbox_user: str, internet_message_id: str
    ) -> tuple[bytes, str] | None:
        """Download Graph's byte-for-byte MIME response for one mailbox message."""
        message = self.find_message(mailbox_user, internet_message_id)
        if not message or not message.get("id"):
            return None

        mailbox_path = quote(mailbox_user, safe="")
        message_path = quote(message["id"], safe="")
        url = (
            f"{self.config.graph_url}/users/{mailbox_path}/messages/"
            f"{message_path}/$value"
        )
        headers = {
            **self.graph_headers,
            "Accept": "application/octet-stream",
        }
        response = self.retry_request("GET", url, headers=headers)
        if not response.content:
            raise ValueError("Microsoft Graph returned an empty MIME message")
        return response.content, message["id"]

    def get_email_evidences(self, alerts: list[dict]) -> list[EmailEvidence]:
        """Resolve and deduplicate raw MIME messages from analyzed-message evidence."""
        by_hash: dict[str, EmailEvidence] = {}
        mailbox_cache: dict[tuple[str, str], tuple[bytes, str] | None] = {}

        for alert in alerts:
            alert_id = alert.get("id", "")
            message_evidences = [
                evidence
                for evidence in alert.get("evidence", [])
                if evidence.get("@odata.type") == ANALYZED_MESSAGE_EVIDENCE
            ]
            if not message_evidences:
                self.log.info(
                    "Alert %s has no analyzed-message evidence; skipping", alert_id
                )
                continue

            for message_evidence in message_evidences:
                mailbox_user = message_evidence.get("recipientEmailAddress", "")
                internet_message_id = message_evidence.get("internetMessageId", "")
                if not mailbox_user or not internet_message_id:
                    self.log.warning(
                        "Alert %s has message evidence without mailbox or Message-ID",
                        alert_id,
                    )
                    continue

                cache_key = (mailbox_user.lower(), internet_message_id)
                if cache_key not in mailbox_cache:
                    mailbox_cache[cache_key] = self.download_raw_email(
                        mailbox_user, internet_message_id
                    )
                raw_result = mailbox_cache[cache_key]
                if raw_result is None:
                    self.log.warning(
                        "Raw email for alert %s was not found in mailbox", alert_id
                    )
                    continue

                raw_eml, graph_message_id = raw_result
                sha256 = hashlib.sha256(raw_eml).hexdigest()
                evidence = by_hash.get(sha256)
                if evidence is None:
                    evidence = EmailEvidence(
                        raw_eml=raw_eml,
                        sha256=sha256,
                        filename=f"mdo-{sha256[:20]}.eml",
                        mailbox_user=mailbox_user,
                        internet_message_id=internet_message_id,
                        graph_message_id=graph_message_id,
                    )
                    by_hash[sha256] = evidence
                evidence.add_alert(alert)

        self.log.info("Resolved %d unique raw EML messages", len(by_hash))
        return list(by_hash.values())

    def add_alert_comment(
        self, evidence: EmailEvidence, comment: str
    ) -> None:
        """Add a comment once to every Defender alert associated with an email."""
        for alert_id in evidence.alert_ids:
            if comment in evidence.comments_by_alert.get(alert_id, set()):
                continue
            alert_path = quote(alert_id, safe="")
            url = f"{self.config.graph_url}/security/alerts_v2/{alert_path}/comments"
            self.retry_request(
                "POST",
                url,
                headers=self.graph_headers,
                json={
                    "@odata.type": "microsoft.graph.security.alertComment",
                    "comment": comment,
                },
            )
            evidence.comments_by_alert.setdefault(alert_id, set()).add(comment)
            self.log.info("Added Joe Sandbox comment to alert %s", alert_id)

    def _get_incident_comments(self, incident_id: str) -> set[str]:
        cache = getattr(self, "_incident_comment_cache", None)
        if cache is None:
            cache = {}
            self._incident_comment_cache = cache
        if incident_id in cache:
            return cache[incident_id]

        incident_path = quote(incident_id, safe="")
        url = f"{self.config.graph_url}/security/incidents/{incident_path}"
        response = self.retry_request("GET", url, headers=self.graph_headers)
        comments = {
            item.get("comment")
            for item in response.json().get("comments", [])
            if isinstance(item, dict) and item.get("comment")
        }
        cache[incident_id] = comments
        return comments

    def add_incident_comments(
        self, incident_ids: set[str], comment: str
    ) -> None:
        """Add a result comment once to every related Defender incident."""
        if not self.config.add_comments_to_incident or not comment:
            return

        for incident_id in incident_ids:
            existing = self._get_incident_comments(incident_id)
            if comment in existing:
                continue
            incident_path = quote(incident_id, safe="")
            url = (
                f"{self.config.graph_url}/security/incidents/"
                f"{incident_path}/comments"
            )
            self.retry_request(
                "POST",
                url,
                headers=self.graph_headers,
                json={
                    "@odata.type": "microsoft.graph.security.alertComment",
                    "comment": comment,
                },
            )
            existing.add(comment)
            self.log.info("Added Joe Sandbox comment to incident %s", incident_id)

    def add_incident_tags(self, incident_ids: set[str], tags: list[str]) -> None:
        """Merge Joe Sandbox verdict tags into the related incidents."""
        if not self.config.add_tags_to_incident or not tags:
            return

        for incident_id in incident_ids:
            incident_path = quote(incident_id, safe="")
            url = f"{self.config.graph_url}/security/incidents/{incident_path}"
            response = self.retry_request("GET", url, headers=self.graph_headers)
            existing = response.json().get("customTags", [])
            merged = list(dict.fromkeys([*existing, *tags]))
            if merged == existing:
                continue
            self.retry_request(
                "PATCH",
                url,
                headers=self.graph_headers,
                json={"customTags": merged},
            )
            self.log.info("Updated Joe Sandbox tags on incident %s", incident_id)
