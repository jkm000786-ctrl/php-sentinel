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


def test_frankenphp_server_header_is_strong_sapi_evidence():
    result = infer_sapi(
        server_family=ServerFamily.UNKNOWN,
        server_header="FrankenPHP",
        x_powered_by=None,
        body="",
    )
    assert result.sapi == SAPIHypothesis.FRANKENPHP
    assert result.confidence == 0.95


def test_frankenphp_body_mention_alone_is_not_sapi_evidence():
    result = infer_sapi(
        server_family=ServerFamily.UNKNOWN,
        server_header="BunnyCDN-PK1-1345",
        x_powered_by=None,
        body="Learn about FrankenPHP and other PHP deployment options.",
    )
    assert result.sapi == SAPIHypothesis.UNKNOWN
    assert result.confidence == 0.0


def test_php_fpm_body_mention_alone_is_not_sapi_evidence():
    result = infer_sapi(
        server_family=ServerFamily.UNKNOWN,
        server_header="BunnyCDN-PK1-1345",
        x_powered_by=None,
        body="PHP-FPM and FPM/FastCGI deployment documentation.",
    )
    assert result.sapi == SAPIHypothesis.UNKNOWN
    assert result.confidence == 0.0


def test_cgi_fastcgi_body_mention_alone_is_not_sapi_evidence():
    result = infer_sapi(
        server_family=ServerFamily.UNKNOWN,
        server_header="cdn",
        x_powered_by=None,
        body="CGI-FCGI CGI/FastCGI SAPI documentation.",
    )
    assert result.sapi == SAPIHypothesis.UNKNOWN
    assert result.confidence == 0.0
