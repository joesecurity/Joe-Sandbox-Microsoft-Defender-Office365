"""Persist the connector polling watermark in Azure Blob Storage."""

from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.storage.blob import BlobServiceClient


class StateManager:
    """Read and write one UTF-8 polling watermark."""

    def __init__(
        self,
        connection_string: str,
        container_name: str = "joesandbox-defender-o365-state",
        blob_name: str = "alert-watermark.txt",
    ) -> None:
        if not connection_string:
            raise ValueError("AzureWebJobsStorage is required")
        service = BlobServiceClient.from_connection_string(connection_string)
        self.container = service.get_container_client(container_name)
        self.blob = self.container.get_blob_client(blob_name)

    def get(self) -> str | None:
        """Return the saved watermark, or None before the first successful run."""
        try:
            return self.blob.download_blob().readall().decode("utf-8")
        except ResourceNotFoundError:
            return None

    def post(self, watermark: str) -> None:
        """Save the watermark after a successful polling cycle."""
        try:
            self.container.create_container()
        except ResourceExistsError:
            pass
        self.blob.upload_blob(watermark.encode("utf-8"), overwrite=True)
