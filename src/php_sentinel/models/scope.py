from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, HttpUrl


class AuthorizationMode(str, Enum):
    PASSIVE = "passive"
    LAB_VALIDATION = "lab_validation"


class ScopeDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class ScopePolicy(BaseModel):
    target: HttpUrl
    mode: AuthorizationMode = AuthorizationMode.PASSIVE
    explicit_authorization: bool = False
    allowed_hosts: list[str] = Field(default_factory=list)


class ScopeEvaluation(BaseModel):
    decision: ScopeDecision
    reasons: list[str] = Field(default_factory=list)
