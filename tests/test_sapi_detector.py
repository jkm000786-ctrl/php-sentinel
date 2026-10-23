from php_sentinel.detection.sapi_detector import infer_sapi
from php_sentinel.models.fingerprint import SAPIHypothesis, ServerFamily


def test_litespeed_sapi():
    result = infer_sapi(
        server_family=ServerFamily.LITESPEED,
        server_header="LiteSpeed",
        x_powered_by="PHP/8.4.26",
        body="",
    )
    assert result.sapi == SAPIHypothesis.LITESPEED


def test_nginx_php_suggests_fpm():
    result = infer_sapi(
        server_family=ServerFamily.NGINX,
        server_header="nginx",
        x_powered_by="PHP/8.4.26",
        body="",
    )
    assert result.sapi == SAPIHypothesis.FPM_FASTCGI


def test_apache_php_suggests_mod_php():
    result = infer_sapi(
        server_family=ServerFamily.APACHE,
        server_header="Apache/2.4",
        x_powered_by="PHP/8.4.26",
        body="",
    )
    assert result.sapi == SAPIHypothesis.MOD_PHP
