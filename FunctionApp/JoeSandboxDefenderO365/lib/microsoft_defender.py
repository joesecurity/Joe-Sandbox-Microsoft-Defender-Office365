"""Microsoft Graph client for Defender for Office 365 alerts and raw MIME."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import logging
from time import monotonic, sleep
from urllib.parse import quote

import requests

from ..const import (
    ALERT_PAGE_SIZE,
    ANALYZED_MESSAGE_EVIDENCE,
    DEFENDER_CONFIG,
    INCIDENT_PATCH_SPACING_SECONDS,
    INDICATOR_PAGE_SIZE,
    MAX_RETRY_AFTER_SECONDS,
    RETRY_STATUS_CODES,
    SAFE_POST_RETRY_STATUS_CODES,
    SEVERITY_ORDER,
    TOKEN_REFRESH_MARGIN_SECONDS,
    DefenderConfig,
)
from ..reporting import merge_incident_tags
from .models import (
    EmailEvidence,
    Indicator,
    MessageGroup,
    alert_comments,
    comment_key,
    normalize_message_id,
)
from .network import (
    NETWORK_ERRORS,
    MicrosoftUnavailable,
    describe,
    is_connect_failure,
    is_network_error,
)

GRAPH = "graph"
# Messages with these delivery results are not in the recipient's mailbox.
UNRETRIEVABLE_DELIVERY_LOCATIONS = {"quarantine", "failed", "dropped"}
UNRETRIEVABLE_DELIVERY_ACTIONS = {"blocked"}
PERMANENT_MAILBOX_ERROR_CODES = {
    "ErrorInvalidUser",
    "ErrorNonExistentMailbox",
    "MailboxNotEnabledForRESTAPI",
    "MailboxNotHostedInExchangeOnline",
    "ResourceNotFound",
}
# For a message sent to many recipients, stop after this many mailbox lookups.
MAX_RECIPIENTS_PER_MESSAGE = 5
DEFENDER = "defender"
IDEMPOTENT_METHODS = {"GET", "HEAD", "OPTIONS", "PUT", "DELETE"}


class MicrosoftAPIError(requests.HTTPError):
    """An HTTP error from a Microsoft API, including the response body."""


@dataclass
class GroupResolution:
    """Outcome of downloading one grouped message.

    Exactly one field is set: ``evidence`` (downloaded), ``unavailable``
    (can never be downloaded), ``not_found`` (not found yet; may appear once
    the mailbox search index catches up) or ``error`` (temporary failure).
    """

    evidence: EmailEvidence | None = None
    unavailable: str = ""
    not_found: str = ""
    error: str = ""


class MicrosoftRequestError(requests.RequestException):
    """A connected request failed at the transport level after all retries
    (read timeout, connection dropped mid-response). Affects one item only."""


def _response_json(response: requests.Response, context: str) -> dict:
    try:
        payload = response.json()
    except ValueError:
        raise MicrosoftAPIError(
            f"{context}: expected JSON but got HTTP {response.status_code} "
            f"({response.headers.get('Content-Type', 'no content type')}): "
            f"{response.text[:500]!r}",
            response=response,
        ) from None
    if not isinstance(payload, dict):
        raise MicrosoftAPIError(
            f"{context}: unexpected JSON payload type {type(payload).__name__}",
            response=response,
        )
    return payload


class MicrosoftDefender:
    """Retrieve MDO alerts and their complete RFC 822/MIME representation."""

    def __init__(
        self,
        log: logging.Logger,
        config: DefenderConfig = DEFENDER_CONFIG,
    ) -> None:
        self.log = log
        self.config = config
        self._tokens: dict[str, tuple[str, float]] = {}
        self._existing_indicator_keys: set[tuple[str, str]] | None = None
        self._indicator_listing_error: MicrosoftAPIError | None = None
        self._incident_cache: dict[str, dict] = {}
        self._incident_comment_cache: dict[str, set[str]] = {}
        self._incident_patched_at: dict[str, float] = {}
        self.authenticate()

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def _scope(self, audience: str) -> str:
        if audience == DEFENDER:
            return self.config.defender_api_scope
        return "https://graph.microsoft.com/.default"

    def _refresh_token(self, audience: str) -> str:
        response = self.retry_request(
            "POST",
            self.config.auth_url,
            data={
                "client_id": self.config.application_id,
                "scope": self._scope(audience),
                "client_secret": self.config.application_secret,
                "grant_type": "client_credentials",
            },
            idempotent=True,
        )
        payload = _response_json(response, "Microsoft token request")
        token = payload.get("access_token")
        if not token:
            raise MicrosoftAPIError(
                "Microsoft token response has no access_token", response=response
            )
        try:
            expires_in = int(payload.get("expires_in", 3599))
        except (TypeError, ValueError):
            expires_in = 3599
        self._tokens[audience] = (token, monotonic() + expires_in)
        self.log.info(
            "Authenticated to %s (token valid for %d seconds)",
            "Microsoft Defender for Endpoint" if audience == DEFENDER
            else "Microsoft Graph",
            expires_in,
        )
        return token

    def _token(self, audience: str, force_refresh: bool = False) -> str:
        cached = self._tokens.get(audience)
        if (
            force_refresh
            or cached is None
            or monotonic() >= cached[1] - TOKEN_REFRESH_MARGIN_SECONDS
        ):
            return self._refresh_token(audience)
        return cached[0]

    def _auth_headers(self, audience: str, force_refresh: bool = False) -> dict:
        return {
            "Authorization": f"Bearer {self._token(audience, force_refresh)}",
            "User-Agent": self.config.user_agent,
            "Content-Type": "application/json",
        }

    def authenticate(self) -> None:
        """Acquire an application token for Microsoft Graph."""
        self._token(GRAPH, force_refresh=True)

    def authenticate_defender_api(self) -> None:
        """Acquire the separate Defender for Endpoint API token on demand."""
        self._token(DEFENDER, force_refresh=True)

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _retry_delay(self, response: requests.Response | None) -> float:
        delay: float = self.config.retry_delay_seconds
        if response is not None:
            retry_after = response.headers.get("Retry-After", "").strip()
            try:
                delay = float(retry_after)
            except ValueError:
                pass
        return max(0.0, min(delay, MAX_RETRY_AFTER_SECONDS))

    def retry_request(
        self,
        method: str,
        url: str,
        *,
        auth: str | None = None,
        headers: dict | None = None,
        params: dict | None = None,
        data: dict | str | None = None,
        json: dict | None = None,
        idempotent: bool | None = None,
    ) -> requests.Response:
        """Issue a Microsoft API request with bounded transient-failure retries.

        ``auth`` selects the token audience (Graph or Defender). Tokens are
        refreshed before they expire, and a single 401 forces one refresh and
        retry. Non-idempotent requests (POST) are only retried when the
        server cannot have processed them (connection not established,
        429/503), so a lost response never creates duplicate comments or
        indicators; the next polling cycle's deduplication covers that case.

        Raises:
            MicrosoftUnavailable: the service could not be connected to after
                all retries (DNS, refused, connect timeout, TLS/proxy).
            MicrosoftRequestError: a connected request failed at the
                transport level (read timeout, dropped connection).
            MicrosoftAPIError: an HTTP error status.
        """
        method = method.upper()
        if idempotent is None:
            idempotent = method in IDEMPOTENT_METHODS
        retry_codes = RETRY_STATUS_CODES if idempotent else SAFE_POST_RETRY_STATUS_CODES
        reauthenticated = False
        attempt = 0

        while True:
            request_headers = dict(headers or {})
            if auth:
                request_headers = {
                    **self._auth_headers(auth),
                    **request_headers,
                }
            try:
                response = requests.request(
                    method,
                    url,
                    headers=request_headers,
                    params=params,
                    data=data,
                    json=json,
                    timeout=self.config.http_timeout_seconds,
                )
            except NETWORK_ERRORS as error:
                if not is_network_error(error):
                    raise  # configuration/programming error, e.g. invalid URL
                not_sent = is_connect_failure(error)
                if (idempotent or not_sent) and attempt < self.config.retry_count:
                    attempt += 1
                    delay = self._retry_delay(None)
                    self.log.warning(
                        "Microsoft API %s %s failed (%s); retrying in %.0f seconds",
                        method,
                        url,
                        describe(error),
                        delay,
                    )
                    sleep(delay)
                    continue
                if not_sent:
                    raise MicrosoftUnavailable(
                        f"Cannot connect to Microsoft API ({method} {url}): "
                        f"{describe(error)}"
                    ) from error
                raise MicrosoftRequestError(
                    f"Microsoft API {method} {url} failed: {describe(error)}"
                ) from error

            if response.status_code == 401 and auth and not reauthenticated:
                self.log.warning(
                    "Microsoft API returned HTTP 401; refreshing the access token"
                )
                self._token(auth, force_refresh=True)
                reauthenticated = True
                continue

            if response.ok:
                return response

            if response.status_code in retry_codes and attempt < self.config.retry_count:
                attempt += 1
                delay = self._retry_delay(response)
                self.log.warning(
                    "Microsoft API returned HTTP %d; retrying in %.0f seconds",
                    response.status_code,
                    delay,
                )
                sleep(delay)
                continue

            raise MicrosoftAPIError(
                f"Microsoft API {method} {url} failed with HTTP "
                f"{response.status_code}: {response.text[:500]}",
                response=response,
            )

    def _get_json(self, url: str, auth: str, params: dict | None = None) -> dict:
        response = self.retry_request("GET", url, auth=auth, params=params)
        return _response_json(response, f"GET {url}")

    def _get_paged(
        self, url: str, auth: str, params: dict, page_size: int
    ) -> list[dict]:
        """Page with $top/$skip; these APIs treat $top as a total limit and
        return no @odata.nextLink, so nextLink-only paging silently truncates.
        """
        items: list[dict] = []
        skip = 0
        while True:
            payload = self._get_json(
                url,
                auth,
                {**params, "$top": str(page_size), "$skip": str(skip)},
            )
            page = [item for item in payload.get("value") or [] if isinstance(item, dict)]
            items.extend(page)
            if len(page) < page_size:
                return items
            skip += len(page)

    # ------------------------------------------------------------------
    # Indicators
    # ------------------------------------------------------------------

    def indicators_enabled_for(self, analysis: dict) -> bool:
        """Return whether this analysis verdict is configured for IOC creation."""
        detection = str(analysis.get("detection") or "").strip().lower()
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
        if self._existing_indicator_keys is not None:
            return self._existing_indicator_keys
        if self._indicator_listing_error is not None:
            # Failed earlier in this cycle (e.g. HTTP 403, missing
            # Ti.ReadWrite.All); do not repeat the call for every email.
            raise self._indicator_listing_error

        keys: set[tuple[str, str]] = set()
        url = f"{self.config.defender_api_url.rstrip('/')}/indicators"
        try:
            items = self._get_paged(url, DEFENDER, {}, INDICATOR_PAGE_SIZE)
        except MicrosoftAPIError as error:
            self._indicator_listing_error = error
            self.log.error(
                "Cannot list Microsoft Defender indicators; indicator import is "
                "skipped for this cycle: %s",
                error,
            )
            raise
        for item in items:
            indicator_type = str(item.get("indicatorType") or "")
            value = str(item.get("indicatorValue") or "")
            if indicator_type and value:
                keys.add(self._indicator_key(indicator_type, value))

        self._existing_indicator_keys = keys
        self.log.info("Retrieved %d active Microsoft Defender indicators", len(keys))
        return keys

    def create_indicators(
        self,
        indicators: list[Indicator],
        analysis: dict,
        evidence: EmailEvidence,
    ) -> tuple[int, int]:
        """Submit new Joe Sandbox IOCs in batches of 500.

        Returns (succeeded, failed). A failing batch is counted and logged
        without discarding the results of batches that already succeeded.
        """
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

        detection = str(analysis.get("detection") or "").strip().lower()
        expiration = (
            datetime.now(timezone.utc)
            + timedelta(days=self.config.indicator_expiration_days)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        web_id = str(analysis.get("webid") or "").strip() or "unknown"
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
            try:
                response = self.retry_request(
                    "POST", url, auth=DEFENDER, json={"Indicators": batch}
                )
                results = _response_json(response, "Defender indicator import").get(
                    "value"
                )
            except (requests.RequestException, ValueError) as error:
                failed += len(batch)
                self.log.error(
                    "Microsoft Defender indicator import batch of %d failed: %s",
                    len(batch),
                    error,
                )
                continue
            if not isinstance(results, list) or not results:
                failed += len(batch)
                self.log.error(
                    "Microsoft Defender returned no per-indicator import results"
                )
                continue

            # The API does not return results in input order: pair them with
            # the submitted payloads by indicator value, never by position.
            result_by_value = {
                str(result.get("indicator") or "").lower(): result
                for result in results
                if isinstance(result, dict)
            }
            for item in batch:
                result = result_by_value.get(item["indicatorValue"].lower())
                if result is None:
                    failed += 1
                    self.log.error(
                        "Microsoft Defender returned no import result for "
                        "indicator %s",
                        item["indicatorValue"],
                    )
                elif result.get("isFailed"):
                    failed += 1
                    self.log.error(
                        "Microsoft Defender rejected indicator %s: %s",
                        item["indicatorValue"],
                        result.get("failureReason") or "unknown reason",
                    )
                else:
                    succeeded += 1
                    existing.add(
                        self._indicator_key(
                            item["indicatorType"], item["indicatorValue"]
                        )
                    )

        self.log.info(
            "Microsoft Defender indicator import completed: %d succeeded, %d failed",
            succeeded,
            failed,
        )
        return succeeded, failed

    # ------------------------------------------------------------------
    # Alerts and raw email
    # ------------------------------------------------------------------

    def get_alerts(self, since_iso8601: str) -> list[dict]:
        """Return MDO alerts created or updated since the given time.

        Filtering on lastUpdateDateTime (not createdDateTime) picks up alerts
        that appear late or receive message evidence after creation.
        """
        url = f"{self.config.graph_url}/security/alerts_v2"
        params = {
            "$filter": (
                "serviceSource eq 'microsoftDefenderForOffice365' "
                f"and lastUpdateDateTime ge {since_iso8601}"
            ),
        }
        alerts = self._dedupe_alerts(
            self._get_paged(url, GRAPH, params, ALERT_PAGE_SIZE)
        )
        alerts = self.filter_and_sort_alerts(alerts)
        self.log.info(
            "Fetched %d Microsoft Defender for Office 365 alerts", len(alerts)
        )
        return alerts

    @staticmethod
    def _dedupe_alerts(alerts: list[dict]) -> list[dict]:
        # $skip offsets shift when alerts change during paging; duplicates are
        # harmless but must not be processed twice.
        unique: dict[str, dict] = {}
        for alert in alerts:
            alert_id = alert.get("id")
            if alert_id:
                unique[alert_id] = alert
        return list(unique.values())

    def filter_and_sort_alerts(self, alerts: list[dict]) -> list[dict]:
        """Apply the AlertSeverities filter and order high to informational."""
        if self.config.severities:
            alerts = [
                alert
                for alert in alerts
                if (alert.get("severity") or "").lower() in self.config.severities
            ]
        return sorted(
            alerts,
            key=lambda alert: SEVERITY_ORDER.get(
                (alert.get("severity") or "").lower(), 99
            ),
        )

    def get_alert(self, alert_id: str) -> dict | None:
        """Return one alert by ID, or None if it no longer exists."""
        url = (
            f"{self.config.graph_url}/security/alerts_v2/"
            f"{quote(alert_id, safe='')}"
        )
        try:
            return self._get_json(url, GRAPH)
        except MicrosoftAPIError as error:
            if error.response is not None and error.response.status_code == 404:
                return None
            raise

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
            payload = self._get_json(
                url,
                GRAPH,
                {
                    "$filter": f"internetMessageId eq '{escaped}'",
                    "$select": "id,internetMessageId,subject,receivedDateTime",
                    "$top": "2",
                },
            )
            messages = payload.get("value") or []
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
        try:
            response = self.retry_request(
                "GET", url, auth=GRAPH, headers={"Accept": "application/octet-stream"}
            )
        except MicrosoftAPIError as error:
            if error.response is not None and error.response.status_code == 404:
                return None  # deleted between search and download
            raise
        if not response.content:
            raise ValueError("Microsoft Graph returned an empty MIME message")
        return response.content, message["id"]

    def group_messages(self, alerts: list[dict]) -> list[MessageGroup]:
        """Group analyzed-message evidence of all alerts by Internet Message-ID.

        One phish delivered to many recipients (and reported in many alerts)
        becomes one group, so it is downloaded and submitted only once.
        """
        groups: dict[str, MessageGroup] = {}
        for alert in alerts:
            alert_id = alert.get("id") or ""
            message_evidences = [
                evidence
                for evidence in alert.get("evidence") or []
                if isinstance(evidence, dict)
                and evidence.get("@odata.type") == ANALYZED_MESSAGE_EVIDENCE
            ]
            if not message_evidences:
                self.log.info(
                    "Alert %s has no analyzed-message evidence; skipping", alert_id
                )
                continue
            for message_evidence in message_evidences:
                mailbox = str(message_evidence.get("recipientEmailAddress") or "").strip()
                raw_message_id = str(message_evidence.get("internetMessageId") or "").strip()
                message_id = normalize_message_id(raw_message_id)
                if not mailbox or not message_id:
                    self.log.warning(
                        "Alert %s has message evidence without mailbox or Message-ID",
                        alert_id,
                    )
                    continue
                group = groups.setdefault(
                    message_id, MessageGroup(message_id, raw_message_id)
                )
                group.alerts[alert_id] = alert
                group.recipients.setdefault(
                    mailbox.lower(),
                    (
                        mailbox,
                        str(message_evidence.get("deliveryLocation") or "unknown"),
                        str(message_evidence.get("deliveryAction") or "unknown"),
                    ),
                )
        return list(groups.values())

    @staticmethod
    def _permanent_mailbox_error(error: BaseException) -> str:
        """Return why a mailbox can never be read, or "" if the error may be
        temporary."""
        response = getattr(error, "response", None)
        if not isinstance(error, MicrosoftAPIError) or response is None:
            return ""
        try:
            code = str(response.json().get("error", {}).get("code") or "")
        except (ValueError, AttributeError):
            code = ""
        if response.status_code == 403 or code == "ErrorAccessDenied":
            return (
                f"access to the mailbox was denied ({code or 'HTTP 403'}); check "
                "the Mail.Read permission and any Exchange Application Access "
                "Policy"
            )
        if response.status_code == 404 or code in PERMANENT_MAILBOX_ERROR_CODES:
            return f"mailbox not found or not mail-enabled ({code or 'HTTP 404'})"
        return ""

    def resolve_group(self, group: MessageGroup) -> GroupResolution:
        """Download one copy of a grouped message.

        Recipients are tried in a fixed order so every cycle downloads the
        same copy. Messages that were never delivered (quarantined, blocked,
        dropped) are not searched for.
        """
        permanent: list[str] = []
        not_found: list[str] = []
        errors: list[str] = []
        tried = 0
        for mailbox, location, action in group.ordered_recipients():
            if (
                location.lower() in UNRETRIEVABLE_DELIVERY_LOCATIONS
                or action.lower() in UNRETRIEVABLE_DELIVERY_ACTIONS
            ):
                permanent.append(
                    f"{mailbox}: not delivered to the mailbox (deliveryAction="
                    f"{action}, deliveryLocation={location}); quarantined or "
                    "blocked messages cannot be downloaded through Microsoft Graph"
                )
                continue
            if tried >= MAX_RECIPIENTS_PER_MESSAGE:
                break
            tried += 1
            try:
                raw_result = self.download_raw_email(mailbox, group.raw_message_id)
            except (requests.RequestException, ValueError) as error:
                reason = self._permanent_mailbox_error(error)
                if reason:
                    permanent.append(f"{mailbox}: {reason}")
                else:
                    errors.append(f"{mailbox}: {describe(error)}")
                continue
            if raw_result is None:
                not_found.append(f"{mailbox}: message not found in the mailbox")
                continue

            raw_eml, graph_message_id = raw_result
            sha256 = hashlib.sha256(raw_eml).hexdigest()
            evidence = EmailEvidence(
                raw_eml=raw_eml,
                sha256=sha256,
                filename=f"mdo-{sha256[:20]}.eml",
                mailbox_user=mailbox,
                internet_message_id=group.raw_message_id,
                graph_message_id=graph_message_id,
            )
            for alert in group.alerts.values():
                evidence.add_alert(alert)
            return GroupResolution(evidence=evidence)

        if errors:
            return GroupResolution(error="; ".join(errors))
        if not_found:
            return GroupResolution(not_found="; ".join(not_found + permanent))
        return GroupResolution(
            unavailable="; ".join(permanent) or "no recipient mailbox to read"
        )

    # ------------------------------------------------------------------
    # Comments and tags
    # ------------------------------------------------------------------

    def _post_alert_comment(self, alert_id: str, comment: str) -> None:
        alert_path = quote(alert_id, safe="")
        url = f"{self.config.graph_url}/security/alerts_v2/{alert_path}/comments"
        self.retry_request(
            "POST",
            url,
            auth=GRAPH,
            json={
                "@odata.type": "microsoft.graph.security.alertComment",
                "comment": comment,
            },
        )
        self.log.info("Added Joe Sandbox comment to alert %s", alert_id)

    def add_alert_comment(
        self, evidence: EmailEvidence, comment: str
    ) -> None:
        """Add a comment once to every Defender alert associated with an email.

        Deduplication compares comment meaning (comment_key), not exact text,
        so an alert that already has the same result in an older wording is
        not commented again.
        """
        for alert_id in sorted(evidence.alert_ids):
            if evidence.has_comment(alert_id, comment):
                continue
            self._post_alert_comment(alert_id, comment)
            evidence.record_comment(alert_id, comment)

    def add_comment_to_alert(self, alert: dict, comment: str) -> bool:
        """Add a comment once to one alert (by meaning). Returns True if posted."""
        key = comment_key(comment)
        if any(comment_key(item["comment"]) == key for item in alert_comments(alert)):
            return False
        self._post_alert_comment(alert["id"], comment)
        alert.setdefault("comments", [])
        if alert["comments"] is None:
            alert["comments"] = []
        alert["comments"].append({"comment": comment})
        return True

    def _get_incident(self, incident_id: str) -> dict:
        """Fetch an incident once per polling cycle (comments and tags)."""
        if incident_id not in self._incident_cache:
            url = (
                f"{self.config.graph_url}/security/incidents/"
                f"{quote(incident_id, safe='')}"
            )
            self._incident_cache[incident_id] = self._get_json(url, GRAPH)
        return self._incident_cache[incident_id]

    def _get_incident_comments(self, incident_id: str) -> set[tuple]:
        """Return the meaning keys (comment_key) of an incident's comments."""
        if incident_id not in self._incident_comment_cache:
            self._incident_comment_cache[incident_id] = {
                comment_key(item.get("comment"))
                for item in self._get_incident(incident_id).get("comments") or []
                if isinstance(item, dict) and item.get("comment")
            }
        return self._incident_comment_cache[incident_id]

    def add_incident_comments(
        self, incident_ids: set[str], comment: str
    ) -> None:
        """Add a result comment once to every related Defender incident."""
        if not self.config.add_comments_to_incident or not comment:
            return

        for incident_id in sorted(incident_ids):
            existing = self._get_incident_comments(incident_id)
            if comment_key(comment) in existing:
                continue
            incident_path = quote(incident_id, safe="")
            url = (
                f"{self.config.graph_url}/security/incidents/"
                f"{incident_path}/comments"
            )
            self.retry_request(
                "POST",
                url,
                auth=GRAPH,
                json={
                    "@odata.type": "microsoft.graph.security.alertComment",
                    "comment": comment,
                },
            )
            existing.add(comment_key(comment))
            self.log.info("Added Joe Sandbox comment to incident %s", incident_id)

    def add_incident_tags(self, incident_ids: set[str], analysis: dict) -> None:
        """Set the single, highest-priority Joe Sandbox verdict tag on incidents."""
        if not self.config.add_tags_to_incident:
            return

        for incident_id in sorted(incident_ids):
            incident = self._get_incident(incident_id)
            existing = [
                tag for tag in incident.get("customTags") or [] if isinstance(tag, str)
            ]
            merged = merge_incident_tags(existing, analysis)
            # Graph does not keep tag order; only a different set of tags is
            # a change worth a PATCH.
            if set(merged) == set(existing):
                continue
            url = (
                f"{self.config.graph_url}/security/incidents/"
                f"{quote(incident_id, safe='')}"
            )
            last_patch = self._incident_patched_at.get(incident_id)
            if last_patch is not None:
                wait = INCIDENT_PATCH_SPACING_SECONDS - (monotonic() - last_patch)
                if wait > 0:
                    self.log.info(
                        "Waiting %.0f seconds before updating incident %s again "
                        "so Graph applies the tag updates in order",
                        wait,
                        incident_id,
                    )
                    sleep(wait)
            self.retry_request(
                "PATCH", url, auth=GRAPH, json={"customTags": merged}
            )
            self._incident_patched_at[incident_id] = monotonic()
            incident["customTags"] = merged
            self.log.info(
                "Updated Joe Sandbox tags on incident %s: %s", incident_id, merged
            )

