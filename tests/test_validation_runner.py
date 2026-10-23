from unittest.mock import Mock, patch

import httpx

from php_sentinel.validation.runner import run_lab_validation


def test_validation_denied_without_authorization():
    result = run_lab_validation(
        "http://127.0.0.1:8080/",
        explicit_authorization=False,
    )

    assert result.authorized is False
    assert result.observations == []


@patch("php_sentinel.validation.runner.httpx.Client")
def test_authorized_validation_uses_only_head_and_get(client_cls):
    request_head = httpx.Request(
        "HEAD",
        "http://127.0.0.1:8080/",
    )
    request_get = httpx.Request(
        "GET",
        "http://127.0.0.1:8080/",
    )

    head_response = httpx.Response(
        200,
        headers={"Server": "Apache"},
        request=request_head,
    )

    get_response = httpx.Response(
        200,
        headers={
            "Server": "Apache",
            "X-Powered-By": "PHP/8.5.12",
        },
        content=b"safe reference response",
        request=request_get,
    )

    client = Mock()
    client.__enter__ = Mock(return_value=client)
    client.__exit__ = Mock(return_value=False)
    client.head.return_value = head_response
    client.get.return_value = get_response

    client_cls.return_value = client

    result = run_lab_validation(
        "http://127.0.0.1:8080/",
        explicit_authorization=True,
    )

    assert result.authorized is True
    assert len(result.observations) == 2
    client.head.assert_called_once()
    client.get.assert_called_once()
