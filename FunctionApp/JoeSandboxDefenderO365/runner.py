"""One polling cycle: load state, process alerts, save state.

Shared by the Azure Functions entry point (app.py, blob state) and the local
harness (local_run.py, file state), and free of azure.functions imports.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
from time import monotonic
from typing import Protocol

from .const import (
    DEFAULT_FUNCTION_TIMEOUT_SECONDS,
    DEFENDER_CONFIG,
    FUNCTION_TIME_SAFETY_MARGIN_SECONDS,
    JOE_CONFIG,
    missing_required_settings,
)
from .lib.joesandbox import JoeSandbox
from .lib.network import JoeSandboxUnavailable, ServiceUnavailable, StateStoreError
from .lib.microsoft_defender import MicrosoftDefender
from .lib.models import parse_graph_datetime
from .state_manager import ConnectorState
from .workflow import process_alerts

HOST_JSON = Path(__file__).resolve().parent.parent / "host.json"


class StateStore(Protocol):
    def load(self, log: logging.Logger | None = None) -> ConnectorState: ...

    def save(self, state: ConnectorState) -> None: ...


def isoformat(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timespan(value: str) -> float | None:
    """Parse an Azure Functions timespan ("[d.]hh:mm:ss"); "-1" = unbounded."""
    text = str(value).strip()
    if text == "-1":
        return None
    days = 0
    if "." in text.split(":")[0]:
        day_text, _, text = text.partition(".")
        days = int(day_text)
    hours, minutes, seconds = (float(part) for part in text.split(":"))
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def function_timeout_seconds(
    host_json: Path = HOST_JSON, log: logging.Logger | None = None
) -> float | None:
    """Read functionTimeout from host.json (None = unbounded)."""
    log = log or logging.getLogger(__name__)
    try:
        value = json.loads(host_json.read_text(encoding="utf-8")).get(
            "functionTimeout"
        )
    except (OSError, ValueError) as error:
        log.warning("Could not read functionTimeout from %s: %s", host_json, error)
        return DEFAULT_FUNCTION_TIMEOUT_SECONDS
    if value is None:
        return DEFAULT_FUNCTION_TIMEOUT_SECONDS
    try:
        return parse_timespan(value)
    except ValueError:
        log.warning("Unparseable functionTimeout %r in host.json", value)
        return DEFAULT_FUNCTION_TIMEOUT_SECONDS


def poll_start_time(
    watermark: str | None, now: datetime, since_override: str | None = None
) -> str:
    """Return the lastUpdateDateTime lower bound for this cycle."""
    if since_override:
        return since_override
    parsed = parse_graph_datetime(watermark) if watermark else None
    if parsed is None:
        return isoformat(
            now - timedelta(minutes=DEFENDER_CONFIG.initial_lookback_minutes)
        )
    return isoformat(parsed - timedelta(minutes=DEFENDER_CONFIG.overlap_minutes))


def run_cycle(
    store: StateStore,
    log: logging.Logger,
    *,
    since_override: str | None = None,
) -> dict[str, int]:
    """Run one polling cycle and persist its state."""
    missing = missing_required_settings()
    if missing:
        raise ValueError(
            "Missing required application settings: " + ", ".join(missing)
        )

    if "jbxcloud.joesecurity.org" in JOE_CONFIG.base_url and not JOE_CONFIG.accept_terms:
        log.error(
            "JoeSandboxAcceptTerms is false, but Joe Sandbox Cloud requires "
            "accepting its Terms and Conditions; submissions will be rejected. "
            "Set JoeSandboxAcceptTerms=true"
        )

    started = monotonic()
    poll_started = datetime.now(timezone.utc)
    timeout = function_timeout_seconds(log=log)
    run_deadline = None
    if timeout is not None:
        budget = timeout - FUNCTION_TIME_SAFETY_MARGIN_SECONDS
        run_deadline = started + budget
        if JOE_CONFIG.analysis_job_timeout_seconds > budget:
            log.warning(
                "JoeSandboxAnalysisJobTimeout (%d min) does not fit in the "
                "function time budget (functionTimeout %d min minus %d min "
                "margin); waits are shortened and unfinished submissions are "
                "picked up by the next cycle",
                JOE_CONFIG.analysis_job_timeout_seconds // 60,
                timeout // 60,
                FUNCTION_TIME_SAFETY_MARGIN_SECONDS // 60,
            )

    try:
        state = store.load(log)
    except StateStoreError as error:
        log.error("%s; skipping this cycle", error)
        return {"skipped_state_unavailable": 1}

    since = poll_start_time(state.watermark, poll_started, since_override)
    log.info(
        "Polling Microsoft Defender alerts updated since %s (%d pending "
        "submissions, %d alerts to retry)",
        since,
        len(state.pending),
        len(state.failed_alerts),
    )

    def save(final: bool) -> None:
        try:
            store.save(state)
        except StateStoreError as error:
            if final:
                # Fail visibly; the old watermark makes the next cycle
                # re-process this window, and alert comments allow recovery.
                log.error("%s; the cycle's progress was not saved", error)
                raise
            log.warning("%s; it is saved again at the end of the cycle", error)

    def checkpoint() -> None:
        state.watermark = isoformat(poll_started)
        save(final=False)

    try:
        defender = MicrosoftDefender(log)
        joe = JoeSandbox(log)
        counts = process_alerts(
            since,
            defender,
            joe,
            state,
            run_deadline=run_deadline,
            checkpoint=checkpoint,
        )
    except ServiceUnavailable as error:
        # Keep the watermark so this window is fetched again next cycle, and
        # save pending submissions recorded before the outage was detected.
        # No alert is charged a failed attempt for an outage.
        log.error(
            "%s is unavailable (%s); skipping this cycle without advancing the "
            "watermark",
            error.service,
            error,
        )
        save(final=True)
        if isinstance(error, JoeSandboxUnavailable):
            return {"skipped_joe_unavailable": 1}
        return {"skipped_microsoft_unavailable": 1}
    except Exception:
        try:
            store.save(state)
        except StateStoreError as save_error:
            log.error("%s", save_error)
        raise

    state.watermark = isoformat(poll_started)
    save(final=True)
    return counts
