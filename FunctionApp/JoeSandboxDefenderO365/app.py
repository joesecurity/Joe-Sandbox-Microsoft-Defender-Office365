"""Timer-triggered Microsoft Defender for Office 365 to Joe Sandbox connector."""

from __future__ import annotations

import logging
from os import environ

import azure.functions as func

from .runner import run_cycle
from .state_manager import BlobStateStore

# The Azure SDK logs every blob request/response (and the expected 409
# ContainerAlreadyExists) at INFO; keep only its warnings and errors.
logging.getLogger("azure").setLevel(logging.WARNING)


def main(mytimer: func.TimerRequest) -> None:
    """Azure Functions timer entry point."""
    if mytimer.past_due:
        logging.warning("The MDO polling timer is past due; processing it now")

    store = BlobStateStore(environ.get("AzureWebJobsStorage", ""))
    counts = run_cycle(store, logging.getLogger(__name__))
    logging.info("MDO polling cycle completed: %s", counts)

