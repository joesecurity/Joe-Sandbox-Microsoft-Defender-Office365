"""Timer-triggered Microsoft Defender for Office 365 to Joe Sandbox connector."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from os import environ

import azure.functions as func

from .const import DEFENDER_CONFIG
from .lib.joesandbox import JoeSandbox
from .lib.microsoft_defender import MicrosoftDefender
from .state_manager import StateManager
from .workflow import process_alerts


def run(since_iso8601: str) -> dict[str, int]:
    """Construct production clients and delegate one polling cycle."""
    log = logging.getLogger(__name__)
    return process_alerts(
        since_iso8601, MicrosoftDefender(log), JoeSandbox(log)
    )


def _parse_watermark(value: str | None, now: datetime) -> datetime:
    if not value:
        return now - timedelta(minutes=DEFENDER_CONFIG.initial_lookback_minutes)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed - timedelta(minutes=DEFENDER_CONFIG.overlap_minutes)


def _isoformat(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(mytimer: func.TimerRequest) -> None:
    """Azure Functions timer entry point."""
    if mytimer.past_due:
        logging.warning("The MDO polling timer is past due; processing it now")

    poll_started = datetime.now(timezone.utc)
    state = StateManager(environ.get("AzureWebJobsStorage", ""))
    since = _isoformat(_parse_watermark(state.get(), poll_started))
    logging.info("Polling Microsoft Defender alerts since %s", since)

    counts = run(since)
    state.post(_isoformat(poll_started))
    logging.info("MDO polling cycle completed: %s", counts)
