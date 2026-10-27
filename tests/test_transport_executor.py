from __future__ import annotations

from typing import ClassVar

import httpx

import php_sentinel.http.client as client_module
from php_sentinel.http.client import fetch_with_transport
from php_sentinel.models.transport import (
    TransportPolicy,
    TransportStopReason,
)


class StreamContext:
    def __init__(self, response: httpx.Response):
        self.response = response

    def __enter__(self) -> httpx.Response:
        return self.response

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class SequenceClient:
    responses: ClassVar[
        list[tuple[int, dict[str, str], bytes]]
    ] = []
    seen_urls: ClassVar[list[str]] = []
    kwargs: ClassVar[dict[str, object]] = {}

    def __init__(self, **kwargs):
        type(self).kwargs = kwargs

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def stream(self, method, url):
        assert method == "GET"

        type(self).seen_urls.append(str(url))

        status, headers, body = type(self).responses.pop(0)

        response = httpx.Response(
            status,
            headers=headers,
            content=body,
            request=httpx.Request(
                method,
                str(url),
            ),
        )

        return StreamContext(response)


def configure(
    monkeypatch,
    responses: list[
        tuple[int, dict[str, str], bytes]
    ],
):
    SequenceClient.responses = list(responses)
    SequenceClient.seen_urls = []
    SequenceClient.kwargs = {}

    monkeypatch.setattr(
        client_module.httpx,
        "Client",
        SequenceClient,
    )


def test_executor_completes_single_request(monkeypatch):
    configure(
        monkeypatch,
        [
            (200, {}, b"ok"),
        ],
    )

    response, evidence = fetch_with_transport(
        "https://example.test/",
    )

    assert response.status_code == 200
    assert response.content == b"ok"
    assert evidence.execution.attempts == 1
    assert evidence.execution.requests_sent == 1
    assert evidence.execution.retries == 0
    assert evidence.execution.redirect_count == 0
    assert (
        evidence.execution.stop_reason
        == TransportStopReason.COMPLETED
    )
    assert SequenceClient.kwargs["follow_redirects"] is False


def test_same_host_redirect_consumes_request_budget(monkeypatch):
    configure(
        monkeypatch,
        [
            (
                302,
                {"Location": "/final"},
                b"redirect",
            ),
            (200, {}, b"done"),
        ],
    )

    response, evidence = fetch_with_transport(
        "https://example.test/start",
    )

    assert response.status_code == 200
    assert str(response.url) == "https://example.test/final"
    assert len(response.history) == 1
    assert evidence.execution.attempts == 1
    assert evidence.execution.requests_sent == 2
    assert evidence.execution.redirect_count == 1


def test_cross_host_redirect_is_denied_by_default(monkeypatch):
    configure(
        monkeypatch,
        [
            (
                302,
                {"Location": "https://other.test/"},
                b"redirect",
            ),
        ],
    )

    response, evidence = fetch_with_transport(
        "https://example.test/",
    )

    assert response.status_code == 302
    assert evidence.execution.requests_sent == 1
    assert evidence.execution.redirect_count == 0
    assert evidence.execution.redirect_target_denied is True
    assert (
        evidence.execution.stop_reason
        == TransportStopReason.REDIRECT_TARGET_DENIED
    )


def test_same_origin_explicit_default_https_port_is_allowed(
    monkeypatch,
):
    configure(
        monkeypatch,
        [
            (
                302,
                {"Location": "https://example.test:443/final"},
                b"redirect",
            ),
            (
                200,
                {},
                b"application",
            ),
        ],
    )

    response, evidence = fetch_with_transport(
        "https://example.test/start",
    )

    assert response.status_code == 200
    assert evidence.execution.requests_sent == 2
    assert evidence.execution.redirect_count == 1
    assert (
        evidence.execution.stop_reason
        == TransportStopReason.COMPLETED
    )


def test_same_host_different_port_redirect_is_denied_by_default(
    monkeypatch,
):
    configure(
        monkeypatch,
        [
            (
                302,
                {"Location": "https://example.test:8443/admin"},
                b"redirect",
            ),
        ],
    )

    response, evidence = fetch_with_transport(
        "https://example.test/",
    )

    assert response.status_code == 302
    assert SequenceClient.seen_urls == [
        "https://example.test/",
    ]
    assert evidence.execution.requests_sent == 1
    assert evidence.execution.redirect_count == 0
    assert evidence.execution.redirect_target_denied is True
    assert (
        evidence.execution.stop_reason
        == TransportStopReason.REDIRECT_TARGET_DENIED
    )


def test_default_http_to_https_upgrade_is_allowed(
    monkeypatch,
):
    configure(
        monkeypatch,
        [
            (
                302,
                {"Location": "https://example.test/final"},
                b"redirect",
            ),
            (
                200,
                {},
                b"application",
            ),
        ],
    )

    response, evidence = fetch_with_transport(
        "http://example.test/start",
    )

    assert response.status_code == 200
    assert SequenceClient.seen_urls == [
        "http://example.test/start",
        "https://example.test/final",
    ]
    assert evidence.execution.requests_sent == 2
    assert evidence.execution.redirect_count == 1
    assert (
        evidence.execution.stop_reason
        == TransportStopReason.COMPLETED
    )


def test_https_to_http_redirect_is_denied(monkeypatch):
    configure(
        monkeypatch,
        [
            (
                302,
                {"Location": "http://example.test/plain"},
                b"redirect",
            ),
        ],
    )

    _response, evidence = fetch_with_transport(
        "https://example.test/",
    )

    assert evidence.execution.redirect_target_denied is True
    assert (
        evidence.execution.stop_reason
        == TransportStopReason.REDIRECT_TARGET_DENIED
    )


def test_429_retries_once_with_backoff(monkeypatch):
    configure(
        monkeypatch,
        [
            (429, {}, b"limited"),
            (200, {}, b"ok"),
        ],
    )

    sleeps: list[float] = []

    monkeypatch.setattr(
        client_module.time,
        "sleep",
        sleeps.append,
    )

    response, evidence = fetch_with_transport(
        "https://example.test/",
    )

    assert response.status_code == 200
    assert evidence.execution.attempts == 2
    assert evidence.execution.requests_sent == 2
    assert evidence.execution.retries == 1
    assert evidence.execution.rate_limit_observed is True
    assert sleeps == [1.0]


def test_redirect_then_429_stops_when_budget_is_exhausted(
    monkeypatch,
):
    configure(
        monkeypatch,
        [
            (
                302,
                {"Location": "/final"},
                b"redirect",
            ),
            (429, {}, b"limited"),
        ],
    )

    response, evidence = fetch_with_transport(
        "https://example.test/start",
    )

    assert response.status_code == 429
    assert evidence.execution.attempts == 1
    assert evidence.execution.requests_sent == 2
    assert evidence.execution.redirect_count == 1
    assert evidence.execution.retries == 0
    assert evidence.execution.budget_exhausted is True
    assert evidence.execution.rate_limit_observed is True
    assert (
        evidence.execution.stop_reason
        == TransportStopReason.REQUEST_BUDGET_EXHAUSTED
    )


def test_retry_after_above_policy_stops_without_sleep(
    monkeypatch,
):
    configure(
        monkeypatch,
        [
            (
                429,
                {"Retry-After": "120"},
                b"limited",
            ),
        ],
    )

    sleeps: list[float] = []

    monkeypatch.setattr(
        client_module.time,
        "sleep",
        sleeps.append,
    )

    _response, evidence = fetch_with_transport(
        "https://example.test/",
        policy=TransportPolicy(
            maximum_retry_after_seconds=30.0,
        ),
    )

    assert sleeps == []
    assert evidence.execution.retry_after_observed is True
    assert (
        evidence.execution.retry_after_exceeded_policy
        is True
    )
    assert (
        evidence.execution.stop_reason
        == TransportStopReason.RETRY_AFTER_EXCEEDS_POLICY
    )


def test_redirect_limit_is_enforced_before_following(
    monkeypatch,
):
    configure(
        monkeypatch,
        [
            (
                302,
                {"Location": "/next"},
                b"redirect",
            ),
        ],
    )

    _response, evidence = fetch_with_transport(
        "https://example.test/",
        policy=TransportPolicy(
            max_attempts=1,
            request_budget=2,
            maximum_redirects=0,
        ),
    )

    assert evidence.execution.requests_sent == 1
    assert evidence.execution.redirect_count == 0
    assert (
        evidence.execution.stop_reason
        == TransportStopReason.REDIRECT_LIMIT_EXHAUSTED
    )
