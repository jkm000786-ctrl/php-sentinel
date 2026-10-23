import httpx

DEFAULT_HEADERS = {
    "User-Agent": "PHP-Sentinel/0.1.0",
    "Accept": "*/*",
}


def fetch(url: str, timeout: float = 10.0) -> httpx.Response:
    with httpx.Client(
        headers=DEFAULT_HEADERS,
        timeout=timeout,
        follow_redirects=True,
        verify=True,
    ) as client:
        return client.get(url)
