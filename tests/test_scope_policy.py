from php_sentinel.models.scope import (
    AuthorizationMode,
    ScopeDecision,
    ScopePolicy,
)
from php_sentinel.validation.policy import evaluate_scope


def test_passive_mode_is_allowed():
    result = evaluate_scope(
        ScopePolicy(
            target="https://example.test/",
            mode=AuthorizationMode.PASSIVE,
        )
    )

    assert result.decision == ScopeDecision.ALLOW


def test_lab_validation_requires_explicit_authorization():
    result = evaluate_scope(
        ScopePolicy(
            target="http://127.0.0.1:8080/",
            mode=AuthorizationMode.LAB_VALIDATION,
            explicit_authorization=False,
        )
    )

    assert result.decision == ScopeDecision.DENY


def test_loopback_lab_target_is_allowed_when_authorized():
    result = evaluate_scope(
        ScopePolicy(
            target="http://127.0.0.1:8080/",
            mode=AuthorizationMode.LAB_VALIDATION,
            explicit_authorization=True,
        )
    )

    assert result.decision == ScopeDecision.ALLOW


def test_public_target_is_denied_for_active_validation():
    result = evaluate_scope(
        ScopePolicy(
            target="https://8.8.8.8/",
            mode=AuthorizationMode.LAB_VALIDATION,
            explicit_authorization=True,
        )
    )

    assert result.decision == ScopeDecision.DENY
