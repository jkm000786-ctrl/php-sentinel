from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class EdgeProvider(str, Enum):
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    IMPERVA = "imperva"
    FASTLY = "fastly"
    BUNNYCDN = "bunnycdn"
    AWS_CLOUDFRONT = "aws_cloudfront"
    SUCURI = "sucuri"
    AZURE_EDGE = "azure_edge"
    MODSECURITY = "modsecurity"
    GENERIC_CDN = "generic_cdn"
    GENERIC_WAF = "generic_waf"
    UNKNOWN = "unknown"
    NONE = "none"


class EdgeResponseClass(str, Enum):
    APPLICATION_RESPONSE = "application_response"
    EDGE_RESPONSE = "edge_response"
    WAF_BLOCK = "waf_block"
    BOT_CHALLENGE = "bot_challenge"
    RATE_LIMIT = "rate_limit"
    ORIGIN_FAILURE = "origin_failure"
    UNKNOWN = "unknown"


class ApplicationReachability(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    UNKNOWN = "unknown"
    NOT_REACHED = "not_reached"


class EdgeSignal(BaseModel):
    signal_type: str
    source: str
    value: str
    weight: float = Field(ge=0.0, le=1.0)
    provider: EdgeProvider | None = None


class EdgeAssessment(BaseModel):
    edge_detected: bool = False
    waf_detected: bool = False
    provider: EdgeProvider = EdgeProvider.NONE
    provider_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    provider_ambiguous: bool = False
    provider_candidates: list[EdgeProvider] = Field(default_factory=list)
    response_class: EdgeResponseClass = EdgeResponseClass.UNKNOWN
    application_reachability: ApplicationReachability = (
        ApplicationReachability.UNKNOWN
    )
    challenge_detected: bool = False
    rate_limited: bool = False
    signals: list[EdgeSignal] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)
