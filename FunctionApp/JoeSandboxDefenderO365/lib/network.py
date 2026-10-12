"""Classification of network failures shared by the API clients.

Two kinds of failure are distinguished:

* **Service unavailable** — the service cannot be reached at all (DNS
  failure, connection refused, connect timeout, TLS or proxy failure, Joe
  Sandbox maintenance, gateway 502/503/504). Nothing in the cycle can
  succeed, so the cycle is skipped without advancing the watermark and
  without charging a failure attempt to any alert.
* **Request failure** — the connection was made but one request failed
  (read timeout, connection dropped mid-response, HTTP error). It concerns
  one item only and is handled by the per-item retry logic.
"""

from __future__ import annotations

import socket
import ssl

import requests
import urllib3.exceptions


class ServiceUnavailable(Exception):
    """A remote service is unreachable; skip this polling cycle."""

    service = "remote service"


class JoeSandboxUnavailable(ServiceUnavailable):
    """Joe Sandbox is offline (maintenance) or unreachable."""

    service = "Joe Sandbox"


class MicrosoftUnavailable(ServiceUnavailable):
    """Microsoft Graph, Defender or Entra ID cannot be reached."""

    service = "Microsoft"


class StateStoreError(Exception):
    """The connector state could not be read or written."""


# Every exception type that a network call made through requests/urllib3 can
# raise. requests wraps most low-level errors, but urllib3 and socket errors
# can still escape in edge cases (e.g. while reading a response body).
NETWORK_ERRORS = (
    requests.RequestException,
    urllib3.exceptions.HTTPError,
    OSError,  # socket.timeout, ConnectionResetError, ssl.SSLError, ...
)

# RequestException subclasses that indicate a programming or configuration
# error rather than a network problem.
NON_NETWORK_REQUEST_ERRORS = (
    requests.exceptions.InvalidURL,
    requests.exceptions.MissingSchema,
    requests.exceptions.InvalidSchema,
    requests.exceptions.InvalidHeader,
    requests.exceptions.URLRequired,
    requests.exceptions.InvalidJSONError,
    requests.exceptions.StreamConsumedError,
    requests.exceptions.UnrewindableBodyError,
    requests.exceptions.HTTPError,  # an HTTP status, not a transport error
)

_CONNECT_FAILURE_TYPES = tuple(
    error_type
    for error_type in (
        requests.exceptions.ConnectTimeout,
        requests.exceptions.SSLError,
        requests.exceptions.ProxyError,
        socket.gaierror,
        ConnectionRefusedError,
        ssl.SSLError,
        # urllib3 types differ between 1.26 and 2.x (NameResolutionError is
        # 2.x only); resolve them defensively so either version imports.
        *(
            getattr(urllib3.exceptions, name, None)
            for name in (
                "NewConnectionError",
                "ConnectTimeoutError",
                "NameResolutionError",
                "ProxyError",
                "SSLError",
            )
        ),
    )
    if isinstance(error_type, type)
)

_CONNECT_FAILURE_MARKERS = (
    "NewConnectionError",
    "NameResolutionError",
    "Failed to establish a new connection",
    "Connection refused",
    "Name or service not known",
    "nodename nor servname",
    "getaddrinfo failed",
    "Temporary failure in name resolution",
    "No route to host",
    "Network is unreachable",
    "ConnectTimeoutError",
    "ProxyError",
    "SSLError",
    "CERTIFICATE_VERIFY_FAILED",
)


def _chain(error: BaseException):
    """Yield the error, its causes/contexts, and exceptions held in args."""
    seen: set[int] = set()
    stack = [error]
    while stack:
        current = stack.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        stack.append(current.__cause__)
        stack.append(current.__context__)
        stack.extend(arg for arg in getattr(current, "args", ()) if isinstance(arg, BaseException))
        reason = getattr(current, "reason", None)
        if isinstance(reason, BaseException):
            stack.append(reason)


def is_network_error(error: BaseException) -> bool:
    """Return True for transport-level failures (not HTTP statuses/config)."""
    if isinstance(error, NON_NETWORK_REQUEST_ERRORS):
        return False
    return isinstance(error, NETWORK_ERRORS)


def is_connect_failure(error: BaseException) -> bool:
    """Return True if the request certainly never reached the server, i.e.
    the service could not be connected to at all."""
    for item in _chain(error):
        if isinstance(item, _CONNECT_FAILURE_TYPES):
            return True
        text = str(item)
        if any(marker in text for marker in _CONNECT_FAILURE_MARKERS):
            return True
    return False


def describe(error: BaseException) -> str:
    return f"{type(error).__name__}: {error}"
