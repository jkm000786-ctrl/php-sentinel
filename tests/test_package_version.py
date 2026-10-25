from importlib.metadata import version

from php_sentinel import __version__


def test_package_version_matches_installed_metadata():
    assert version("php-sentinel") == __version__
