from __future__ import annotations

import httpx
import pytest

import php_sentinel.http.client as client_module
from php_sentinel.http.client import (
    HTTPResponseTooLargeError,
    fetch,
)


class FakeStreamContext:
    def __init__(self, response):
        self.response = response

    def __enter__(self):
        return self.response

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeClient:
    response = None

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def stream(self, method, url):
        assert method == "GET"
        assert url == "https://example.test/"
        assert self.response is not None
        return FakeStreamContext(self.response)


def make_response(
    *,
    body=b"body",
    headers=None,
    history=None,
):
    request = httpx.Request(
        "GET",
        "https://example.test/",
    )

    return httpx.Response(
        200,
        request=request,
        headers=headers or {},
        content=body,
        history=history or [],
    )


def test_fetch_returns_loaded_response_with_original_semantics(
    monkeypatch,
):
    redirect = httpx.Response(
        302,
        request=httpx.Request(
            "GET",
            "https://example.test/start",
        ),
        headers={"location": "https://example.test/"},
    )

    FakeClient.response = make_response(
        body=b"bounded-body",
        headers={"content-type": "text/plain"},
        history=[redirect],
    )

    monkeypatch.setattr(
        client_module.httpx,
        "Client",
        FakeClient,
    )

    response = fetch(
        "https://example.test/",
        maximum_bytes=1024,
    )

    assert response.status_code == 200
    assert response.content == b"bounded-body"
    assert response.text == "bounded-body"
    assert response.headers["content-type"] == "text/plain"
    assert len(response.history) == 1
    assert response.request.url == httpx.URL("https://example.test/")


def test_fetch_rejects_declared_oversized_response_before_body_use(
    monkeypatch,
):
    FakeClient.response = make_response(
        body=b"x",
        headers={"content-length": "2048"},
    )

    monkeypatch.setattr(
        client_module.httpx,
        "Client",
        FakeClient,
    )

    with pytest.raises(
        HTTPResponseTooLargeError,
        match="maximum allowed body size",
    ):
        fetch(
            "https://example.test/",
            maximum_bytes=1024,
        )


def test_fetch_rejects_chunked_body_that_crosses_limit(
    monkeypatch,
):
    FakeClient.response = make_response(
        body=b"x" * 1025,
    )

    monkeypatch.setattr(
        client_module.httpx,
        "Client",
        FakeClient,
    )

    with pytest.raises(
        HTTPResponseTooLargeError,
        match="maximum allowed body size",
    ):
        fetch(
            "https://example.test/",
            maximum_bytes=1024,
        )


def test_fetch_rejects_nonpositive_limit():
    with pytest.raises(
        ValueError,
        match="maximum_bytes must be positive",
    ):
        fetch(
            "https://example.test/",
            maximum_bytes=0,
        )


def test_default_user_agent_uses_package_version():
    from php_sentinel import __version__

    assert client_module.DEFAULT_HEADERS["User-Agent"] == f"PHP-Sentinel/{__version__}"


def test_default_headers_disable_response_compression():
    assert client_module.DEFAULT_HEADERS["Accept-Encoding"] == "identity"
