from __future__ import annotations

import socket

import httpx
import pytest

from php_sentinel.intelligence.update import (
    IntelligenceUpdateTransportError,
    _address_is_public_update_destination,
    _resolve_remote_host_addresses,
    _validate_remote_destination,
    _validate_remote_url,
    stage_remote_bundle,
)


def resolver_for(
    *addresses: str,
):
    def resolver(
        host,
        port,
        *,
        type,
    ):
        assert host
        assert port
        assert type == socket.SOCK_STREAM

        results = []

        for address in addresses:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET

            if family == socket.AF_INET6:
                sockaddr = (
                    address,
                    port,
                    0,
                    0,
                )
            else:
                sockaddr = (
                    address,
                    port,
                )

            results.append(
                (
                    family,
                    socket.SOCK_STREAM,
                    6,
                    "",
                    sockaddr,
                )
            )

        return results

    return resolver


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "::",
        "ff02::1",
    ],
)
def test_non_public_addresses_are_rejected(
    address,
):
    assert _address_is_public_update_destination(address) is False


@pytest.mark.parametrize(
    "address",
    [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
    ],
)
def test_public_addresses_are_allowed(
    address,
):
    assert _address_is_public_update_destination(address) is True


def test_public_literal_ipv4_is_allowed():
    assert _validate_remote_destination("https://8.8.8.8/policy.json") == ("8.8.8.8",)


def test_loopback_literal_ipv4_is_rejected():
    with pytest.raises(
        IntelligenceUpdateTransportError,
        match="not a globally routable public address",
    ):
        _validate_remote_destination("https://127.0.0.1/policy.json")


def test_private_literal_ipv4_is_rejected():
    with pytest.raises(
        IntelligenceUpdateTransportError,
        match="not a globally routable public address",
    ):
        _validate_remote_destination("https://10.0.0.10/policy.json")


def test_loopback_literal_ipv6_is_rejected():
    with pytest.raises(
        IntelligenceUpdateTransportError,
        match="not a globally routable public address",
    ):
        _validate_remote_destination("https://[::1]/policy.json")


def test_hostname_with_public_addresses_is_allowed():
    resolved = _validate_remote_destination(
        "https://updates.example.test/policy.json",
        resolver=resolver_for(
            "8.8.8.8",
            "1.1.1.1",
        ),
    )

    assert resolved == (
        "1.1.1.1",
        "8.8.8.8",
    )


def test_hostname_with_private_address_is_rejected():
    with pytest.raises(
        IntelligenceUpdateTransportError,
        match="non-public address",
    ):
        _validate_remote_destination(
            "https://updates.example.test/policy.json",
            resolver=resolver_for(
                "10.1.2.3",
            ),
        )


def test_mixed_public_private_dns_answer_fails_closed():
    with pytest.raises(
        IntelligenceUpdateTransportError,
        match="10.1.2.3",
    ):
        _validate_remote_destination(
            "https://updates.example.test/policy.json",
            resolver=resolver_for(
                "8.8.8.8",
                "10.1.2.3",
            ),
        )


def test_mixed_public_loopback_dns_answer_fails_closed():
    with pytest.raises(
        IntelligenceUpdateTransportError,
        match="127.0.0.1",
    ):
        _validate_remote_destination(
            "https://updates.example.test/policy.json",
            resolver=resolver_for(
                "1.1.1.1",
                "127.0.0.1",
            ),
        )


def test_ipv6_link_local_dns_answer_fails_closed():
    with pytest.raises(
        IntelligenceUpdateTransportError,
        match="fe80::1",
    ):
        _validate_remote_destination(
            "https://updates.example.test/policy.json",
            resolver=resolver_for(
                "2606:4700:4700::1111",
                "fe80::1",
            ),
        )


def test_resolution_failure_fails_closed():
    def resolver(
        host,
        port,
        *,
        type,
    ):
        raise socket.gaierror(
            socket.EAI_NONAME,
            "Name or service not known",
        )

    with pytest.raises(
        IntelligenceUpdateTransportError,
        match="hostname resolution failed",
    ):
        _validate_remote_destination(
            "https://updates.example.test/policy.json",
            resolver=resolver,
        )


def test_empty_resolution_fails_closed():
    with pytest.raises(
        IntelligenceUpdateTransportError,
        match="resolved to no addresses",
    ):
        _validate_remote_destination(
            "https://updates.example.test/policy.json",
            resolver=resolver_for(),
        )


def test_duplicate_dns_addresses_are_normalized():
    resolved = _resolve_remote_host_addresses(
        hostname="updates.example.test",
        port=443,
        resolver=resolver_for(
            "8.8.8.8",
            "8.8.8.8",
            "1.1.1.1",
        ),
    )

    assert resolved == (
        "1.1.1.1",
        "8.8.8.8",
    )


def test_invalid_resolver_address_fails_closed():
    def resolver(
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
                    "not-an-ip",
                    port,
                ),
            )
        ]

    with pytest.raises(
        IntelligenceUpdateTransportError,
        match="invalid IP address",
    ):
        _validate_remote_destination(
            "https://updates.example.test/policy.json",
            resolver=resolver,
        )


def test_stage_remote_bundle_blocks_private_dns_before_fetch(
    tmp_path,
):
    calls: list[str] = []

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(
            200,
            content=b"{}",
            request=request,
        )

    with (
        httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
            trust_env=False,
        ) as client,
        pytest.raises(
            IntelligenceUpdateTransportError,
            match="non-public address",
        ),
    ):
        stage_remote_bundle(
            policy_url=("https://updates.example.test/policy.json"),
            manifest_url=("https://updates.example.test/manifest.json"),
            staging_directory=(tmp_path / "stage"),
            client=client,
            resolver=resolver_for(
                "10.10.10.10",
            ),
        )

    assert calls == []


def test_stage_remote_bundle_accepts_public_preflight_with_mock_transport(
    tmp_path,
):
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"{}",
            request=request,
        )

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        trust_env=False,
    ) as client:
        metadata = stage_remote_bundle(
            policy_url=("https://updates.example.test/policy.json"),
            manifest_url=("https://updates.example.test/manifest.json"),
            staging_directory=(tmp_path / "stage"),
            client=client,
            resolver=resolver_for(
                "8.8.8.8",
            ),
            peer_address_getter=peer_address("8.8.8.8"),
        )

    assert metadata.policy_bytes == 2
    assert metadata.manifest_bytes == 2


def peer_address(
    value: str,
):
    def getter(
        response,
    ):
        return value

    return getter


def test_stage_rejects_connected_peer_outside_prevalidated_set(
    tmp_path,
):
    calls: list[str] = []

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        calls.append(str(request.url))

        return httpx.Response(
            200,
            content=b"{}",
            request=request,
        )

    with (
        httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
            trust_env=False,
        ) as client,
        pytest.raises(
            IntelligenceUpdateTransportError,
            match=("not present in the prevalidated DNS address set"),
        ),
    ):
        stage_remote_bundle(
            policy_url=("https://updates.example.test/policy.json"),
            manifest_url=("https://updates.example.test/manifest.json"),
            staging_directory=(tmp_path / "stage"),
            client=client,
            resolver=resolver_for(
                "8.8.8.8",
            ),
            peer_address_getter=peer_address("1.1.1.1"),
        )

    assert calls == [("https://updates.example.test/policy.json")]


def test_stage_accepts_connected_peer_in_prevalidated_set(
    tmp_path,
):
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"{}",
            request=request,
        )

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        trust_env=False,
    ) as client:
        metadata = stage_remote_bundle(
            policy_url=("https://updates.example.test/policy.json"),
            manifest_url=("https://updates.example.test/manifest.json"),
            staging_directory=(tmp_path / "stage"),
            client=client,
            resolver=resolver_for(
                "8.8.8.8",
                "1.1.1.1",
            ),
            peer_address_getter=peer_address("1.1.1.1"),
        )

    assert metadata.policy_bytes == 2
    assert metadata.manifest_bytes == 2


def test_stage_rejects_private_connected_peer(
    tmp_path,
):
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"{}",
            request=request,
        )

    with (
        httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
            trust_env=False,
        ) as client,
        pytest.raises(
            IntelligenceUpdateTransportError,
        ),
    ):
        stage_remote_bundle(
            policy_url=("https://updates.example.test/policy.json"),
            manifest_url=("https://updates.example.test/manifest.json"),
            staging_directory=(tmp_path / "stage"),
            client=client,
            resolver=resolver_for(
                "8.8.8.8",
            ),
            peer_address_getter=peer_address("10.0.0.1"),
        )


@pytest.mark.parametrize(
    "address",
    [
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:8.8.8.8",
        "::ffff:1.1.1.1",
    ],
)
def test_destination_policy_rejects_ipv4_mapped_ipv6(
    address,
):
    assert not _address_is_public_update_destination(address)


@pytest.mark.parametrize(
    "url",
    [
        "https://[fe80::1%25eth0]/policy.json",
        "https://[fe80::1%eth0]/policy.json",
    ],
)
def test_destination_policy_rejects_scoped_ipv6_host(
    url,
):
    with pytest.raises(
        IntelligenceUpdateTransportError,
        match="Scoped or percent-bearing",
    ):
        _validate_remote_destination(url)


def test_destination_policy_converts_malformed_port_to_transport_error():
    with pytest.raises(
        IntelligenceUpdateTransportError,
        match="invalid port",
    ):
        _validate_remote_destination("https://updates.example.test:99999/policy.json")


def test_remote_url_validation_rejects_malformed_port():
    with pytest.raises(
        IntelligenceUpdateTransportError,
        match="invalid port",
    ):
        _validate_remote_url("https://updates.example.test:99999/policy.json")
