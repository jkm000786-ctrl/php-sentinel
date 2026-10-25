import httpx

from php_sentinel import __version__

DEFAULT_HEADERS = {
    "User-Agent": f"PHP-Sentinel/{__version__}",
    "Accept": "*/*",
    "Accept-Encoding": "identity",
}

DEFAULT_RESPONSE_MAX_BYTES = 2 * 1024 * 1024


class HTTPResponseTooLargeError(ValueError):
    """Raised when a target response exceeds the configured body limit."""


def fetch(
    url: str,
    timeout: float = 10.0,
    maximum_bytes: int = DEFAULT_RESPONSE_MAX_BYTES,
) -> httpx.Response:
    if maximum_bytes < 1:
        raise ValueError("maximum_bytes must be positive.")

    with (
        httpx.Client(
            headers=DEFAULT_HEADERS,
            timeout=timeout,
            follow_redirects=True,
            verify=True,
        ) as client,
        client.stream(
            "GET",
            url,
        ) as streamed,
    ):
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
            history=list(streamed.history),
            extensions=dict(streamed.extensions),
        )
