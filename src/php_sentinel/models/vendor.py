from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class VendorFamily(str, Enum):
    UPSTREAM = "upstream"
    UBUNTU = "ubuntu"
    DEBIAN = "debian"
    RHEL = "rhel"
    ROCKY = "rocky"
    ALMALINUX = "almalinux"
    SUSE = "suse"
    AMAZON = "amazon_linux"
    CLOUDLINUX = "cloudlinux"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class BackportStatus(str, Enum):
    CONFIRMED_FIXED = "confirmed_fixed"
    PROBABLY_FIXED = "probably_fixed"
    NO_FIX_EVIDENCE = "no_fix_evidence"
    UNKNOWN = "unknown"


class VendorEvidence(BaseModel):
    vendor: VendorFamily = VendorFamily.UNKNOWN
    package_name: str | None = None
    package_version: str | None = None
    backport_status: BackportStatus = BackportStatus.UNKNOWN
    advisory_reference: str | None = None
    source: str | None = None
    notes: str | None = None
