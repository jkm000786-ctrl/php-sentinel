from php_sentinel.intelligence.package_revision import identify_package
from php_sentinel.models.vendor import VendorFamily


def test_identifies_ubuntu_package():
    result = identify_package("8.4.26-1ubuntu2.3")

    assert result is not None
    assert result.upstream_version == "8.4.26"
    assert result.vendor == VendorFamily.UBUNTU


def test_identifies_debian_package():
    result = identify_package("PHP 8.3.35-2+deb13u1 Debian")

    assert result is not None
    assert result.upstream_version == "8.3.35"
    assert result.vendor == VendorFamily.DEBIAN


def test_unknown_package_does_not_infer_patch():
    result = identify_package("8.5.11-custom")

    assert result is not None
    assert result.vendor == VendorFamily.UNKNOWN
