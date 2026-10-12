"""Environment-backed connector configuration."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from os import environ


DEFENDER_INDICATOR_ACTIONS = {
    "Allowed",
    "Audit",
    "Block",
    "BlockAndRemediate",
    "Warn",
}
ALERT_SEVERITIES = {"unknown", "informational", "low", "medium", "high"}
INDICATOR_VERDICTS = {"malicious", "suspicious"}
REQUIRED_SETTINGS = (
    "JoeSandboxAPIKey",
    "AzureTenantID",
    "AzureClientID",
    "AzureClientSecret",
)


def env_bool(name: str, default: bool) -> bool:
    """Parse a strict boolean environment variable."""
    raw = environ.get(name)
    if raw is None or not raw.strip():
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value, got {raw!r}")


def env_int(
    name: str, default: int, minimum: int, maximum: int | None = None
) -> int:
    """Parse a bounded integer environment variable, naming it on error."""
    raw = environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None
    if value < minimum or (maximum is not None and value > maximum):
        upper = f" and at most {maximum}" if maximum is not None else ""
        raise ValueError(f"{name} must be at least {minimum}{upper}, got {value}")
    return value


def env_list(name: str, default: str, allowed: set[str]) -> tuple[str, ...]:
    """Parse a comma-separated, lower-cased list restricted to known values."""
    values = tuple(
        item.strip().lower()
        for item in environ.get(name, default).split(",")
        if item.strip()
    )
    invalid = sorted(set(values) - allowed)
    if invalid:
        raise ValueError(
            f"{name} contains unsupported value(s) {', '.join(invalid)}; "
            f"allowed: {', '.join(sorted(allowed))}"
        )
    return values


def missing_required_settings() -> list[str]:
    """Return the names of required credentials that are not configured."""
    return [name for name in REQUIRED_SETTINGS if not environ.get(name, "").strip()]


@dataclass(frozen=True)
class JoeSandboxConfig:
    api_key: str
    base_url: str
    accept_terms: bool
    resubmit: bool
    analysis_job_timeout_seconds: int
    poll_interval_seconds: int
    api_retries: int
    api_timeout_seconds: int
    connector_name: str = "JoeSandbox-MS-Defender-Office365"

    @property
    def api_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/api"


@dataclass(frozen=True)
class DefenderConfig:
    tenant_id: str
    application_id: str
    application_secret: str
    severities: tuple[str, ...]
    add_tags_to_incident: bool
    add_comments_to_incident: bool
    retry_count: int
    retry_delay_seconds: int
    http_timeout_seconds: int
    initial_lookback_minutes: int
    overlap_minutes: int
    create_indicators: bool
    indicator_verdicts: tuple[str, ...]
    indicator_expiration_days: int
    malicious_network_action: str
    suspicious_network_action: str
    malicious_file_action: str
    suspicious_file_action: str
    indicator_generate_alert: bool
    graph_url: str = "https://graph.microsoft.com/v1.0"
    defender_api_url: str = "https://api.security.microsoft.com/api"
    defender_api_scope: str = "https://api.securitycenter.microsoft.com/.default"
    user_agent: str = "JoeSandbox-MS-Defender-Office365"

    def __post_init__(self) -> None:
        actions = {
            "MaliciousNetworkAction": self.malicious_network_action,
            "SuspiciousNetworkAction": self.suspicious_network_action,
            "MaliciousFileAction": self.malicious_file_action,
            "SuspiciousFileAction": self.suspicious_file_action,
        }
        invalid = [
            name
            for name, action in actions.items()
            if action not in DEFENDER_INDICATOR_ACTIONS
        ]
        if invalid:
            raise ValueError(
                f"{', '.join(invalid)} must be one of: "
                + ", ".join(sorted(DEFENDER_INDICATOR_ACTIONS))
            )

    @property
    def auth_url(self) -> str:
        return (
            "https://login.microsoftonline.com/"
            f"{self.tenant_id}/oauth2/v2.0/token"
        )


@dataclass(frozen=True)
class StateConfig:
    failed_alert_max_attempts: int
    pending_submission_ttl_hours: int


if environ.get("JoeSandboxAPIRetryTimeout", "").strip():
    logging.getLogger(__name__).warning(
        "JoeSandboxAPIRetryTimeout is deprecated and ignored; use "
        "JoeSandboxAPIRequestTimeoutSeconds (per-request timeout in seconds)"
    )

JOE_CONFIG = JoeSandboxConfig(
    api_key=environ.get("JoeSandboxAPIKey", ""),
    base_url=environ.get(
        "JoeSandboxBaseURL", "https://jbxcloud.joesecurity.org"
    ),
    accept_terms=env_bool("JoeSandboxAcceptTerms", False),
    resubmit=env_bool("JoeSandboxResubmit", False),
    analysis_job_timeout_seconds=(
        env_int("JoeSandboxAnalysisJobTimeout", 30, 1, 1440) * 60
    ),
    poll_interval_seconds=env_int("JoeSandboxPollIntervalSeconds", 30, 5, 3600),
    api_retries=env_int("JoeSandboxAPIMaxRetry", 5, 1, 10),
    api_timeout_seconds=env_int(
        "JoeSandboxAPIRequestTimeoutSeconds", 60, 5, 600
    ),
)

DEFENDER_CONFIG = DefenderConfig(
    tenant_id=environ.get("AzureTenantID", ""),
    application_id=environ.get("AzureClientID", ""),
    application_secret=environ.get("AzureClientSecret", ""),
    severities=env_list(
        "AlertSeverities", "informational,low,medium,high", ALERT_SEVERITIES
    ),
    add_tags_to_incident=env_bool("IncidentTagsEnabled", True),
    add_comments_to_incident=env_bool("IncidentCommentsEnabled", True),
    retry_count=env_int("MicrosoftRetryCount", 3, 0, 10),
    retry_delay_seconds=env_int("MicrosoftRetryDelaySeconds", 60, 1, 600),
    http_timeout_seconds=env_int("MicrosoftHttpTimeoutSeconds", 120, 5, 600),
    initial_lookback_minutes=env_int("InitialLookbackMinutes", 60, 1, 43200),
    overlap_minutes=env_int("AlertOverlapMinutes", 15, 0, 1440),
    create_indicators=env_bool("IndicatorImportEnabled", True),
    indicator_verdicts=env_list(
        "IndicatorVerdicts", "malicious,suspicious", INDICATOR_VERDICTS
    ),
    indicator_expiration_days=env_int("IndicatorLifetimeDays", 30, 1, 3650),
    malicious_network_action=environ.get(
        "MaliciousNetworkAction", "Block"
    ),
    suspicious_network_action=environ.get(
        "SuspiciousNetworkAction", "Audit"
    ),
    malicious_file_action=environ.get(
        "MaliciousFileAction", "Block"
    ),
    suspicious_file_action=environ.get(
        "SuspiciousFileAction", "Audit"
    ),
    indicator_generate_alert=env_bool("IndicatorAlertsEnabled", False),
)

STATE_CONFIG = StateConfig(
    failed_alert_max_attempts=env_int("FailedAlertMaxAttempts", 2, 1, 20),
    pending_submission_ttl_hours=env_int("PendingSubmissionTTLHours", 24, 1, 720),
)

RETRY_STATUS_CODES = {429, 500, 502, 503, 504}
# Statuses that are safe to retry for non-idempotent requests (POST): the
# server rejected the request before processing it.
SAFE_POST_RETRY_STATUS_CODES = {429, 503}
MAX_RETRY_AFTER_SECONDS = 120
TOKEN_REFRESH_MARGIN_SECONDS = 300
# Graph applies incident PATCHes asynchronously; two PATCHes to the same
# incident a second apart were observed to be applied out of order (the
# older tag list won). Space them out within a cycle.
INCIDENT_PATCH_SPACING_SECONDS = 15
# How long handled emails are remembered (state "final_messages") so alerts
# re-fetched by the overlap window or by our own comments are skipped
# without downloading the email again.
FINAL_MESSAGE_RETENTION_HOURS = 72
ALERT_PAGE_SIZE = 100
INDICATOR_PAGE_SIZE = 10000
FUNCTION_TIME_SAFETY_MARGIN_SECONDS = 300
DEFAULT_FUNCTION_TIMEOUT_SECONDS = 30 * 60
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "informational": 3}
ANALYZED_MESSAGE_EVIDENCE = "#microsoft.graph.security.analyzedMessageEvidence"

