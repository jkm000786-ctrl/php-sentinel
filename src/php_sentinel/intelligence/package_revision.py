from __future__ import annotations

import re
from dataclasses import dataclass

from php_sentinel.models.vendor import VendorFamily


@dataclass(frozen=True)
class PackageIdentity:
    raw: str
    upstream_version: str | None
    vendor: VendorFamily
    revision: str | None


PHP_VERSION_RE = re.compile(r"(?P<version>\d+\.\d+\.\d+)")


def identify_package(raw: str | None) -> PackageIdentity | None:
    if not raw:
        return None

    lower = raw.lower()
    match = PHP_VERSION_RE.search(raw)

    upstream = match.group("version") if match else None
    vendor = VendorFamily.UNKNOWN

    if "ubuntu" in lower:
        vendor = VendorFamily.UBUNTU
    elif "debian" in lower:
        vendor = VendorFamily.DEBIAN
    elif "el9" in lower or "el8" in lower or "rhel" in lower:
        vendor = VendorFamily.RHEL
    elif "rocky" in lower:
        vendor = VendorFamily.ROCKY
    elif "alma" in lower:
        vendor = VendorFamily.ALMALINUX
    elif "suse" in lower:
        vendor = VendorFamily.SUSE
    elif "amzn" in lower or "amazon" in lower:
        vendor = VendorFamily.AMAZON
    elif "cloudlinux" in lower:
        vendor = VendorFamily.CLOUDLINUX

    revision = None

    if upstream and raw != upstream:
        pos = raw.find(upstream)
        if pos >= 0:
            suffix = raw[pos + len(upstream) :].strip()
            revision = suffix or None

    return PackageIdentity(
        raw=raw,
        upstream_version=upstream,
        vendor=vendor,
        revision=revision,
    )
