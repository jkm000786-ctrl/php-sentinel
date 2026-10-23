from php_sentinel.detection.server_detector import detect_server_family
from php_sentinel.models.fingerprint import ServerFamily


def test_apache_detection():
    assert detect_server_family("Apache/2.4.62") == ServerFamily.APACHE


def test_nginx_detection():
    assert detect_server_family("nginx/1.26.0") == ServerFamily.NGINX


def test_litespeed_detection():
    assert detect_server_family("LiteSpeed") == ServerFamily.LITESPEED
