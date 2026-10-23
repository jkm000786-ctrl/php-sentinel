from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class ServerFamily(str, Enum):
    APACHE = "apache"
    NGINX = "nginx"
    LITESPEED = "litespeed"
    CADDY = "caddy"
    IIS = "iis"
    UNKNOWN = "unknown"


class SAPIHypothesis(str, Enum):
    MOD_PHP = "mod_php"
    FPM_FASTCGI = "fpm_fastcgi"
    CGI = "cgi"
    LITESPEED = "litespeed"
    FRANKENPHP = "frankenphp"
    UNKNOWN = "unknown"


class Fingerprint(BaseModel):
    server_family: ServerFamily = ServerFamily.UNKNOWN
    server_raw: str | None = None
    sapi: SAPIHypothesis = SAPIHypothesis.UNKNOWN
    sapi_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    indicators: list[str] = Field(default_factory=list)
