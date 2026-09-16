"""Environment-backed connector configuration."""

from dataclasses import dataclass
from os import environ


DEFENDER_INDICATOR_ACTIONS = {
    "Allowed",
    "Audit",
    "Block",
    "BlockAndRemediate",
    "Warn",
}


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
    raise ValueError(f"{name} must be a boolean value")


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
        actions = (
            self.malicious_network_action,
            self.suspicious_network_action,
            self.malicious_file_action,
            self.suspicious_file_action,
        )
        invalid = [
            action for action in actions if action not in DEFENDER_INDICATOR_ACTIONS
        ]
        if invalid:
            raise ValueError(
                "Defender indicator actions must be one of: "
                + ", ".join(sorted(DEFENDER_INDICATOR_ACTIONS))
            )
        if self.indicator_expiration_days < 1:
            raise ValueError("IndicatorLifetimeDays must be at least 1")

    @property
    def auth_url(self) -> str:
        return (
            "https://login.microsoftonline.com/"
            f"{self.tenant_id}/oauth2/v2.0/token"
        )


JOE_CONFIG = JoeSandboxConfig(
    api_key=environ.get("JoeSandboxAPIKey", ""),
    base_url=environ.get(
        "JoeSandboxBaseURL", "https://jbxcloud.joesecurity.org"
    ),
    accept_terms=env_bool("JoeSandboxAcceptTerms", False),
    resubmit=env_bool("JoeSandboxResubmit", False),
    analysis_job_timeout_seconds=(
        int(environ.get("JoeSandboxAnalysisJobTimeout", "30")) * 60
    ),
    poll_interval_seconds=int(environ.get("JoeSandboxPollIntervalSeconds", "30")),
    api_retries=int(environ.get("JoeSandboxAPIMaxRetry", "5")),
    api_timeout_seconds=(
        int(environ.get("JoeSandboxAPIRetryTimeout", "5")) * 60
    ),
)

DEFENDER_CONFIG = DefenderConfig(
    tenant_id=environ.get("AzureTenantID", ""),
    application_id=environ.get("AzureClientID", ""),
    application_secret=environ.get("AzureClientSecret", ""),
    severities=tuple(
        severity.strip().lower()
        for severity in environ.get(
            "AlertSeverities", "informational,low,medium,high"
        ).split(",")
        if severity.strip()
    ),
    add_tags_to_incident=env_bool("IncidentTagsEnabled", True),
    add_comments_to_incident=env_bool("IncidentCommentsEnabled", False),
    retry_count=int(environ.get("MicrosoftRetryCount", "3")),
    retry_delay_seconds=int(
        environ.get("MicrosoftRetryDelaySeconds", "60")
    ),
    http_timeout_seconds=int(environ.get("MicrosoftHttpTimeoutSeconds", "120")),
    initial_lookback_minutes=int(environ.get("InitialLookbackMinutes", "60")),
    overlap_minutes=int(environ.get("AlertOverlapMinutes", "15")),
    create_indicators=env_bool("IndicatorImportEnabled", True),
    indicator_verdicts=tuple(
        verdict.strip().lower()
        for verdict in environ.get(
            "IndicatorVerdicts", "malicious,suspicious"
        ).split(",")
        if verdict.strip()
    ),
    indicator_expiration_days=int(
        environ.get("IndicatorLifetimeDays", "30")
    ),
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

RETRY_STATUS_CODES = {429, 500, 501, 502, 503, 504}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "informational": 3}
ANALYZED_MESSAGE_EVIDENCE = "#microsoft.graph.security.analyzedMessageEvidence"
