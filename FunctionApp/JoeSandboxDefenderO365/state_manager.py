"""Persist the connector state (watermark, pending submissions, failed alerts).

The state is one JSON document::

    {
      "version": 2,
      "watermark": "2026-10-09T10:00:00Z",
      "pending": {
        "submission:6024095": {"kind": "submission", "joe_id": "6024095",
                               "sha256": "...", "alert_ids": [...],
                               "incident_ids": [...], "analysis_tag": "...",
                               "created": "2026-10-09T10:01:00Z",
                               "enrich_attempts": 0}
      },
      "final_messages": {
        "<message id>": {"alert_ids": [...], "sha256": "...",
                         "status": "enriched", "at": "..."}
      },
      "failed_alerts": {
        "<alert id>": {"attempts": 1, "last_error": "...",
                       "last_attempt": "2026-10-09T10:01:00Z",
                       "deferred_since": "...",   # deferred, not failed
                       "not_found": "..."}        # email not found yet
      }
    }

Version 1 stored only the watermark as plain text; it is still accepted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from datetime import datetime, timedelta, timezone
import logging
from pathlib import Path

from .lib.models import WaitItem, parse_graph_datetime
from .lib.network import StateStoreError

STATE_VERSION = 2


@dataclass
class ConnectorState:
    """In-memory connector state shared by one polling cycle."""

    watermark: str | None = None
    pending: dict[str, dict] = field(default_factory=dict)
    failed_alerts: dict[str, dict] = field(default_factory=dict)
    # Internet Message-ID -> {"alert_ids": [...], "sha256": "...",
    #   "status": "enriched" | "unavailable", "at": ISO time}
    # Emails whose alerts already have their final result, so re-fetched
    # alerts (overlap window) are skipped without downloading the email.
    final_messages: dict[str, dict] = field(default_factory=dict)

    @classmethod
    def loads(cls, raw: str | None, log: logging.Logger | None = None) -> ConnectorState:
        """Parse stored state; corrupt content falls back to an empty state."""
        log = log or logging.getLogger(__name__)
        text = (raw or "").strip()
        if not text:
            return cls()
        if not text.startswith("{"):
            # Version 1: a bare ISO-8601 watermark.
            if parse_graph_datetime(text) is None:
                log.warning(
                    "Ignoring unparseable watermark %r; using the initial lookback",
                    text[:100],
                )
                return cls()
            return cls(watermark=text)
        try:
            data = json.loads(text)
        except json.JSONDecodeError as error:
            log.warning("Ignoring corrupt connector state (%s); starting fresh", error)
            return cls()
        if not isinstance(data, dict):
            log.warning("Ignoring connector state of unexpected type; starting fresh")
            return cls()

        watermark = data.get("watermark")
        if not isinstance(watermark, str) or parse_graph_datetime(watermark) is None:
            if watermark:
                log.warning(
                    "Ignoring unparseable watermark %r; using the initial lookback",
                    str(watermark)[:100],
                )
            watermark = None
        pending = data.get("pending")
        failed = data.get("failed_alerts")
        final = data.get("final_messages")
        return cls(
            final_messages={
                str(key): value
                for key, value in (final or {}).items()
                if isinstance(value, dict)
            }
            if isinstance(final, dict)
            else {},
            watermark=watermark,
            pending={
                str(key): value
                for key, value in (pending or {}).items()
                if isinstance(value, dict) and value.get("joe_id")
            }
            if isinstance(pending, dict)
            else {},
            failed_alerts={
                str(key): value
                for key, value in (failed or {}).items()
                if isinstance(value, dict)
            }
            if isinstance(failed, dict)
            else {},
        )

    def dumps(self) -> str:
        return json.dumps(
            {
                "version": STATE_VERSION,
                "watermark": self.watermark,
                "pending": self.pending,
                "failed_alerts": self.failed_alerts,
                "final_messages": self.final_messages,
            },
            indent=2,
            sort_keys=True,
        )

    # Emails already handled ----------------------------------------------

    def record_final(
        self,
        message_ids: set[str],
        alert_ids: set[str],
        sha256: str,
        status: str,
        now: datetime,
    ) -> None:
        for message_id in message_ids:
            if not message_id:
                continue
            previous = self.final_messages.get(message_id, {})
            self.final_messages[message_id] = {
                "alert_ids": sorted(set(previous.get("alert_ids", [])) | alert_ids),
                "sha256": sha256 or previous.get("sha256", ""),
                "status": status,
                "at": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }

    def is_final(self, message_id: str, alert_ids: set[str]) -> bool:
        """Return whether every alert of an email already has its result."""
        record = self.final_messages.get(message_id)
        return bool(record) and alert_ids <= set(record.get("alert_ids") or [])

    def final_sha256(self, message_id: str) -> str:
        return str((self.final_messages.get(message_id) or {}).get("sha256") or "")

    def prune_final(self, now: datetime, retention: timedelta) -> None:
        """Forget handled emails once they can no longer be re-fetched."""
        for message_id, record in list(self.final_messages.items()):
            at = parse_graph_datetime(record.get("at"))
            if at is None or now - at > retention:
                del self.final_messages[message_id]

    # Pending submissions -------------------------------------------------

    def add_pending(self, item: WaitItem) -> None:
        previous = self.pending.get(item.key, {})
        self.pending[item.key] = {
            "kind": item.kind,
            "joe_id": item.joe_id,
            "sha256": item.sha256,
            "alert_ids": sorted(set(previous.get("alert_ids", [])) | item.alert_ids),
            "incident_ids": sorted(
                set(previous.get("incident_ids", [])) | item.incident_ids
            ),
            "message_ids": sorted(
                set(previous.get("message_ids", [])) | set(item.message_ids)
            ),
            "analysis_tag": item.analysis_tag or previous.get("analysis_tag", ""),
            "created": previous.get("created") or item.created,
            "enrich_attempts": previous.get("enrich_attempts", 0),
        }

    def remove_pending(self, key: str) -> None:
        self.pending.pop(key, None)

    def pending_items(self) -> list[WaitItem]:
        items = []
        for record in self.pending.values():
            items.append(
                WaitItem(
                    kind=str(record.get("kind") or "submission"),
                    joe_id=str(record["joe_id"]),
                    sha256=str(record.get("sha256") or ""),
                    alert_ids=set(record.get("alert_ids") or []),
                    incident_ids=set(record.get("incident_ids") or []),
                    analysis_tag=str(record.get("analysis_tag") or ""),
                    created=str(record.get("created") or ""),
                    message_ids=set(record.get("message_ids") or []),
                )
            )
        return items


class BlobStateStore:
    """Read and write the connector state in Azure Blob Storage."""

    def __init__(
        self,
        connection_string: str,
        container_name: str = "joesandbox-defender-o365-state",
        blob_name: str = "alert-watermark.txt",
    ) -> None:
        if not connection_string:
            raise ValueError("AzureWebJobsStorage is required")
        from azure.storage.blob import BlobServiceClient

        service = BlobServiceClient.from_connection_string(connection_string)
        self.container = service.get_container_client(container_name)
        self.blob = self.container.get_blob_client(blob_name)

    def get(self) -> str | None:
        """Return the raw saved state, or None before the first run.

        Raises StateStoreError if Blob Storage cannot be read (network,
        authentication, throttling after the SDK's own retries).
        """
        from azure.core.exceptions import AzureError, ResourceNotFoundError

        try:
            return self.blob.download_blob().readall().decode("utf-8", "replace")
        except ResourceNotFoundError:
            return None
        except (AzureError, OSError) as error:
            raise StateStoreError(
                f"Cannot read connector state from Blob Storage: "
                f"{type(error).__name__}: {error}"
            ) from error

    def post(self, content: str) -> None:
        """Save the raw state; raises StateStoreError on failure."""
        from azure.core.exceptions import AzureError, ResourceExistsError

        try:
            try:
                self.container.create_container()
            except ResourceExistsError:
                pass
            self.blob.upload_blob(content.encode("utf-8"), overwrite=True)
        except (AzureError, OSError) as error:
            raise StateStoreError(
                f"Cannot write connector state to Blob Storage: "
                f"{type(error).__name__}: {error}"
            ) from error

    def load(self, log: logging.Logger | None = None) -> ConnectorState:
        return ConnectorState.loads(self.get(), log)

    def save(self, state: ConnectorState) -> None:
        self.post(state.dumps())


# Backwards-compatible name used by earlier versions of app.py.
StateManager = BlobStateStore


class FileStateStore:
    """Keep the connector state in a local JSON file (local testing)."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def load(self, log: logging.Logger | None = None) -> ConnectorState:
        try:
            raw = self.path.read_text(encoding="utf-8") if self.path.exists() else None
        except OSError as error:
            raise StateStoreError(f"Cannot read {self.path}: {error}") from error
        return ConnectorState.loads(raw, log)

    def save(self, state: ConnectorState) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        try:
            tmp.write_text(state.dumps(), encoding="utf-8")
            tmp.replace(self.path)
        except OSError as error:
            raise StateStoreError(f"Cannot write {self.path}: {error}") from error


class MemoryStateStore:
    """Non-persistent state (local runs with --no-state)."""

    def __init__(self) -> None:
        self.state = ConnectorState()

    def load(self, log: logging.Logger | None = None) -> ConnectorState:
        return self.state

    def save(self, state: ConnectorState) -> None:
        self.state = state
