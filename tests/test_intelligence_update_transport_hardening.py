from __future__ import annotations

import os
import socket

import httpx
import pytest

from php_sentinel.intelligence.update import (
    IntelligenceUpdateTransportError,
    stage_remote_bundle,
)

POLICY_URL = "https://updates.example.test/policy.json"

MANIFEST_URL = "https://updates.example.test/manifest.json"


def public_test_peer_address(
    response,
):
    return "8.8.8.8"


def public_test_resolver(
    host,
    port,
    *,
    type,
):
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            (
                "8.8.8.8",
                port,
            ),
        )
    ]


def response_for(
    request: httpx.Request,
    *,
    body: bytes = b"{}",
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return httpx.Response(
        status_code,
        content=body,
        headers=headers,
        request=request,
    )


def test_default_client_does_not_inherit_proxy_environment(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(
        "HTTPS_PROXY",
        "http://127.0.0.1:1",
    )
    monkeypatch.setenv(
        "HTTP_PROXY",
        "http://127.0.0.1:1",
    )
    monkeypatch.setenv(
        "ALL_PROXY",
        "http://127.0.0.1:1",
    )

    calls: list[str] = []

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        calls.append(str(request.url))

        return response_for(
            request,
        )

    transport = httpx.MockTransport(handler)

    original_client = httpx.Client

    created: dict[str, object] = {}

    class CapturingClient:
        def __init__(
            self,
            *args,
            **kwargs,
        ):
            created.update(kwargs)

            client_kwargs = dict(kwargs)

            client_kwargs["transport"] = transport

            self._client = original_client(
                *args,
                **client_kwargs,
            )

        def stream(
            self,
            *args,
            **kwargs,
        ):
            return self._client.stream(
                *args,
                **kwargs,
            )

        def close(self):
            self._client.close()

    monkeypatch.setattr(
        "php_sentinel.intelligence.update.httpx.Client",
        CapturingClient,
    )

    stage_remote_bundle(
        policy_url=POLICY_URL,
        manifest_url=MANIFEST_URL,
        staging_directory=(tmp_path / "stage"),
        resolver=public_test_resolver,
        peer_address_getter=public_test_peer_address,
    )

    assert created["trust_env"] is False

    assert created["follow_redirects"] is False

    assert calls == [
        POLICY_URL,
        MANIFEST_URL,
    ]


def test_redirect_is_rejected_even_with_supplied_client(
    tmp_path,
):
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return response_for(
            request,
            status_code=302,
            headers={"Location": ("https://other.example.test/payload.json")},
        )

    with (
        httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
            trust_env=False,
        ) as client,
        pytest.raises(
            IntelligenceUpdateTransportError,
            match="redirects are not followed",
        ),
    ):
        stage_remote_bundle(
            policy_url=POLICY_URL,
            manifest_url=MANIFEST_URL,
            staging_directory=(tmp_path / "stage"),
            client=client,
            resolver=public_test_resolver,
            peer_address_getter=public_test_peer_address,
        )


def test_supplied_client_cannot_turn_redirect_into_success(
    tmp_path,
):
    calls: list[str] = []

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        calls.append(str(request.url))

        if str(request.url) == POLICY_URL:
            return response_for(
                request,
                status_code=302,
                headers={"Location": ("https://other.example.test/policy.json")},
            )

        return response_for(
            request,
        )

    # follow_redirects=True is deliberately hostile here.
    # The update layer must still reject redirect responses
    # at its own transport boundary.
    with (
        httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=True,
            trust_env=False,
        ) as client,
        pytest.raises(
            IntelligenceUpdateTransportError,
            match="redirects are not followed",
        ),
    ):
        stage_remote_bundle(
            policy_url=POLICY_URL,
            manifest_url=MANIFEST_URL,
            staging_directory=(tmp_path / "stage"),
            client=client,
            resolver=public_test_resolver,
            peer_address_getter=public_test_peer_address,
        )

    assert POLICY_URL in calls


def test_empty_response_fails_closed(
    tmp_path,
):
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return response_for(
            request,
            body=b"",
        )

    with (
        httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
            trust_env=False,
        ) as client,
        pytest.raises(
            IntelligenceUpdateTransportError,
            match="was empty",
        ),
    ):
        stage_remote_bundle(
            policy_url=POLICY_URL,
            manifest_url=MANIFEST_URL,
            staging_directory=(tmp_path / "stage"),
            client=client,
            resolver=public_test_resolver,
            peer_address_getter=public_test_peer_address,
        )


def test_size_limit_still_applies_to_streamed_content(
    tmp_path,
):
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return response_for(
            request,
            body=b"x" * 17,
        )

    with (
        httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
            trust_env=False,
        ) as client,
        pytest.raises(
            IntelligenceUpdateTransportError,
            match="maximum download size",
        ),
    ):
        stage_remote_bundle(
            policy_url=POLICY_URL,
            manifest_url=MANIFEST_URL,
            staging_directory=(tmp_path / "stage"),
            maximum_bytes=16,
            client=client,
            resolver=public_test_resolver,
            peer_address_getter=public_test_peer_address,
        )


def test_proxy_environment_is_not_required_for_supplied_client(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(
        "HTTPS_PROXY",
        "http://127.0.0.1:1",
    )

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return response_for(
            request,
        )

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        trust_env=False,
    ) as client:
        metadata = stage_remote_bundle(
            policy_url=POLICY_URL,
            manifest_url=MANIFEST_URL,
            staging_directory=(tmp_path / "stage"),
            client=client,
            resolver=public_test_resolver,
            peer_address_getter=public_test_peer_address,
        )

    assert metadata.policy_url == (POLICY_URL)

    assert metadata.manifest_url == (MANIFEST_URL)


def test_no_proxy_env_cleanup_assumption():
    # Guard against tests accidentally depending on the host's
    # ambient proxy configuration.
    assert isinstance(
        os.environ,
        os._Environ,
    )
