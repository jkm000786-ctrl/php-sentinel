import re
from dataclasses import dataclass

import httpx

PHP_VERSION_RE = re.compile(r"(?:PHP/|PHP\s+)(\d+\.\d+\.\d+)", re.IGNORECASE)


@dataclass(frozen=True)
class PHPDetection:
    detected: bool
    version: str | None
    x_powered_by: str | None
    server: str | None
    reasons: tuple[str, ...]


def detect_php(response: httpx.Response) -> PHPDetection:
    x_powered_by = response.headers.get("x-powered-by")
    server = response.headers.get("server")
    reasons: list[str] = []
    version = None

    for candidate in [x_powered_by or "", server or ""]:
        match = PHP_VERSION_RE.search(candidate)
        if match:
            version = match.group(1)
            reasons.append(f"PHP version marker observed in HTTP header: {candidate}")
            break

    detected = bool(version)

    if x_powered_by and "php" in x_powered_by.lower():
        detected = True
        reasons.append("X-Powered-By indicates PHP")

    body = response.text[:200_000]
    if "php" in body.lower() and any(
        marker in body for marker in ("Fatal error:", "Parse error:", "PHP Version")
    ):
        detected = True
        reasons.append("Response body contains a PHP runtime/error marker")

    return PHPDetection(
        detected=detected,
        version=version,
        x_powered_by=x_powered_by,
        server=server,
        reasons=tuple(reasons),
    )
