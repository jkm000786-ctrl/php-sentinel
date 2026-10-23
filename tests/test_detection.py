import httpx

from php_sentinel.detection.php_detector import detect_php


def make_response(headers=None, body="ok"):
    request = httpx.Request("GET", "https://example.test/")
    return httpx.Response(200, headers=headers or {}, text=body, request=request)


def test_detects_x_powered_by():
    r = detect_php(make_response({"X-Powered-By": "PHP/8.5.11"}))
    assert r.detected
    assert r.version == "8.5.11"


def test_generic_apache_is_not_php_proof():
    r = detect_php(make_response({"Server": "Apache"}))
    assert not r.detected
