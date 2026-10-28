from __future__ import annotations

import time

import httpx

from php_sentinel import __version__
from php_sentinel.http.transport import decide_retry
from php_sentinel.models.transport import (
    TransportEvidence,
    TransportExecution,
    TransportPolicy,
    TransportStopReason,
)

DEFAULT_HEADERS = {
    "User-Agent": f"PHP-Sentinel/{__version__}",
    "Accept": "*/*",
    "Accept-Encoding": "identity",
}

DEFAULT_RESPONSE_MAX_BYTES = 2 * 1024 * 1024


class HTTPResponseTooLargeError(ValueError):
    """Raised when a target response exceeds the configured body limit."""

    def __init__(
        self,
        message: str,
        *,
        evidence: TransportEvidence | None = None,
    ) -> None:
        super().__init__(message)
        self.evidence = evidence


class TransportExecutionError(httpx.RequestError):
    def __init__(
        self,
        message: str,
        *,
        evidence: TransportEvidence,
    ) -> None:
        super().__init__(message)
        self.evidence = evidence


def _transport_failure_reason(
    exc: httpx.TransportError,
) -> TransportStopReason:
    if isinstance(exc, httpx.TimeoutException):
        return TransportStopReason.TIMEOUT

    if isinstance(exc, httpx.NetworkError):
        return TransportStopReason.NETWORK_ERROR

    if isinstance(exc, httpx.ProtocolError):
        return TransportStopReason.PROTOCOL_ERROR

    return TransportStopReason.TRANSPORT_ERROR


def _load_bounded_response(
    streamed: httpx.Response,
    *,
    maximum_bytes: int,
    history: list[httpx.Response],
) -> httpx.Response:
    content_length = streamed.headers.get("content-length")

    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError:
            declared_length = None

        if declared_length is not None and declared_length > maximum_bytes:
            raise HTTPResponseTooLargeError(
                "Target HTTP response exceeds the maximum allowed body size."
            )

    chunks: list[bytes] = []
    total = 0

    for chunk in streamed.iter_bytes():
        total += len(chunk)

        if total > maximum_bytes:
            raise HTTPResponseTooLargeError(
                "Target HTTP response exceeds the maximum allowed body size."
            )

        chunks.append(chunk)

    body = b"".join(chunks)

    return httpx.Response(
        status_code=streamed.status_code,
        headers=streamed.headers,
        content=body,
        request=streamed.request,
        history=[
            *history,
            *list(streamed.history),
        ],
        extensions=dict(streamed.extensions),
    )


def _effective_port(url: httpx.URL) -> int | None:
    if url.port is not None:
        return url.port

    if url.scheme == "http":
        return 80

    if url.scheme == "https":
        return 443

    return None


def _redirect_target_allowed(
    source: httpx.URL,
    target: httpx.URL,
    *,
    policy: TransportPolicy,
) -> bool:
    if target.scheme not in {"http", "https"}:
        return False

    if source.scheme == "https" and target.scheme != "https":
        return False

    if policy.allow_cross_host_redirects:
        return True

    if source.host != target.host:
        return False

    source_port = _effective_port(source)
    target_port = _effective_port(target)

    if source.scheme == target.scheme:
        return source_port == target_port

    return (
        source.scheme == "http"
        and target.scheme == "https"
        and source_port == 80
        and target_port == 443
    )


def _build_transport_evidence(
    *,
    policy: TransportPolicy,
    attempts: int,
    requests_sent: int,
    retries: int,
    redirect_count: int,
    stop_reason: TransportStopReason,
    retry_after_observed: bool,
    retry_after_honored: bool,
    retry_after_exceeded_policy: bool,
    rate_limit_observed: bool,
    redirect_target_denied: bool = False,
) -> TransportEvidence:
    return TransportEvidence(
        policy=policy,
        execution=TransportExecution(
            attempts=attempts,
            requests_sent=requests_sent,
            retries=retries,
            budget_exhausted=(
                stop_reason
                == TransportStopReason.REQUEST_BUDGET_EXHAUSTED
            ),
            retry_after_observed=retry_after_observed,
            retry_after_honored=retry_after_honored,
            retry_after_exceeded_policy=(
                retry_after_exceeded_policy
            ),
            rate_limit_observed=rate_limit_observed,
            redirect_target_denied=redirect_target_denied,
            stop_reason=stop_reason,
            redirect_count=redirect_count,
        ),
    )


def fetch_with_transport(
    url: str,
    timeout: float = 10.0,
    maximum_bytes: int = DEFAULT_RESPONSE_MAX_BYTES,
    *,
    policy: TransportPolicy | None = None,
) -> tuple[httpx.Response, TransportEvidence]:
    if maximum_bytes < 1:
        raise ValueError("maximum_bytes must be positive.")

    selected_policy = policy or TransportPolicy()

    attempts = 0
    requests_sent = 0
    retries = 0
    redirect_count = 0

    retry_after_observed = False
    retry_after_honored = False
    retry_after_exceeded_policy = False
    rate_limit_observed = False

    current_url = url

    with httpx.Client(
        headers=DEFAULT_HEADERS,
        timeout=timeout,
        follow_redirects=False,
        verify=True,
    ) as client:
        while True:
            attempts += 1
            attempt_history: list[httpx.Response] = []

            while True:
                requests_sent += 1

                try:
                    with client.stream(
                        "GET",
                        current_url,
                    ) as streamed:
                        response = _load_bounded_response(
                            streamed,
                            maximum_bytes=maximum_bytes,
                            history=attempt_history,
                        )
                except HTTPResponseTooLargeError as exc:
                    evidence = _build_transport_evidence(
                        policy=selected_policy,
                        attempts=attempts,
                        requests_sent=requests_sent,
                        retries=retries,
                        redirect_count=redirect_count,
                        stop_reason=(
                            TransportStopReason.RESPONSE_BODY_LIMIT_EXCEEDED
                        ),
                        retry_after_observed=retry_after_observed,
                        retry_after_honored=retry_after_honored,
                        retry_after_exceeded_policy=(
                            retry_after_exceeded_policy
                        ),
                        rate_limit_observed=rate_limit_observed,
                    )

                    raise HTTPResponseTooLargeError(
                        str(exc),
                        evidence=evidence,
                    ) from exc

                except httpx.TransportError as exc:
                    evidence = _build_transport_evidence(
                        policy=selected_policy,
                        attempts=attempts,
                        requests_sent=requests_sent,
                        retries=retries,
                        redirect_count=redirect_count,
                        stop_reason=_transport_failure_reason(exc),
                        retry_after_observed=retry_after_observed,
                        retry_after_honored=retry_after_honored,
                        retry_after_exceeded_policy=(
                            retry_after_exceeded_policy
                        ),
                        rate_limit_observed=rate_limit_observed,
                    )

                    raise TransportExecutionError(
                        (
                            "Transport execution failed before a permitted "
                            "application response was obtained."
                        ),
                        evidence=evidence,
                    ) from exc

                if not response.is_redirect:
                    break

                location = response.headers.get("location")

                if location is None:
                    break

                if redirect_count >= selected_policy.maximum_redirects:
                    return (
                        response,
                        _build_transport_evidence(
                            policy=selected_policy,
                            attempts=attempts,
                            requests_sent=requests_sent,
                            retries=retries,
                            redirect_count=redirect_count,
                            stop_reason=(
                                TransportStopReason.REDIRECT_LIMIT_EXHAUSTED
                            ),
                            retry_after_observed=retry_after_observed,
                            retry_after_honored=retry_after_honored,
                            retry_after_exceeded_policy=(
                                retry_after_exceeded_policy
                            ),
                            rate_limit_observed=rate_limit_observed,
                        ),
                    )

                next_url = response.url.join(location)

                if not _redirect_target_allowed(
                    response.url,
                    next_url,
                    policy=selected_policy,
                ):
                    return (
                        response,
                        _build_transport_evidence(
                            policy=selected_policy,
                            attempts=attempts,
                            requests_sent=requests_sent,
                            retries=retries,
                            redirect_count=redirect_count,
                            stop_reason=(
                                TransportStopReason.REDIRECT_TARGET_DENIED
                            ),
                            retry_after_observed=retry_after_observed,
                            retry_after_honored=retry_after_honored,
                            retry_after_exceeded_policy=(
                                retry_after_exceeded_policy
                            ),
                            rate_limit_observed=rate_limit_observed,
                            redirect_target_denied=True,
                        ),
                    )

                if requests_sent >= selected_policy.request_budget:
                    return (
                        response,
                        _build_transport_evidence(
                            policy=selected_policy,
                            attempts=attempts,
                            requests_sent=requests_sent,
                            retries=retries,
                            redirect_count=redirect_count,
                            stop_reason=(
                                TransportStopReason.REQUEST_BUDGET_EXHAUSTED
                            ),
                            retry_after_observed=retry_after_observed,
                            retry_after_honored=retry_after_honored,
                            retry_after_exceeded_policy=(
                                retry_after_exceeded_policy
                            ),
                            rate_limit_observed=rate_limit_observed,
                        ),
                    )

                attempt_history.append(response)
                redirect_count += 1
                current_url = str(next_url)

            decision = decide_retry(
                response,
                policy=selected_policy,
                attempts=attempts,
                retries=retries,
                requests_sent=requests_sent,
            )

            retry_after_observed = (
                retry_after_observed
                or decision.retry_after_observed
            )
            retry_after_honored = (
                retry_after_honored
                or decision.retry_after_honored
            )
            retry_after_exceeded_policy = (
                retry_after_exceeded_policy
                or decision.retry_after_exceeded_policy
            )
            rate_limit_observed = (
                rate_limit_observed
                or decision.rate_limit_observed
            )

            if not decision.should_retry:
                return (
                    response,
                    _build_transport_evidence(
                        policy=selected_policy,
                        attempts=attempts,
                        requests_sent=requests_sent,
                        retries=retries,
                        redirect_count=redirect_count,
                        stop_reason=decision.stop_reason,
                        retry_after_observed=retry_after_observed,
                        retry_after_honored=retry_after_honored,
                        retry_after_exceeded_policy=(
                            retry_after_exceeded_policy
                        ),
                        rate_limit_observed=rate_limit_observed,
                    ),
                )

            retries += 1

            if decision.delay_seconds > 0:
                time.sleep(decision.delay_seconds)

            current_url = str(response.url)


def fetch(
    url: str,
    timeout: float = 10.0,
    maximum_bytes: int = DEFAULT_RESPONSE_MAX_BYTES,
) -> httpx.Response:
    response, _transport = fetch_with_transport(
        url,
        timeout=timeout,
        maximum_bytes=maximum_bytes,
    )

    return response
