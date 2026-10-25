from __future__ import annotations

import hashlib

import httpx

from php_sentinel import __version__
from php_sentinel.models.scope import (
    AuthorizationMode,
    ScopeDecision,
    ScopePolicy,
)
from php_sentinel.models.validation import (
    ValidationKind,
    ValidationObservation,
    ValidationReport,
)
from php_sentinel.validation.policy import evaluate_scope


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_lab_validation(
    target: str,
    *,
    explicit_authorization: bool,
    timeout: float = 10.0,
) -> ValidationReport:
    policy = ScopePolicy(
        target=target,
        mode=AuthorizationMode.LAB_VALIDATION,
        explicit_authorization=explicit_authorization,
    )

    scope = evaluate_scope(policy)

    report = ValidationReport(
        target=target,
        authorized=scope.decision == ScopeDecision.ALLOW,
        notes=list(scope.reasons),
    )

    if scope.decision != ScopeDecision.ALLOW:
        return report

    headers = {
        "User-Agent": f"PHP-Sentinel-LabValidator/{__version__}",
        "Accept": "*/*",
    }

    with httpx.Client(
        timeout=timeout,
        headers=headers,
        follow_redirects=False,
        verify=True,
    ) as client:
        head = client.head(target)

        report.observations.append(
            ValidationObservation(
                kind=ValidationKind.HEAD_CHECK,
                method="HEAD",
                url=str(head.request.url),
                status_code=head.status_code,
                server=head.headers.get("server"),
                x_powered_by=head.headers.get("x-powered-by"),
                content_type=head.headers.get("content-type"),
            )
        )

        get = client.get(target)

        report.observations.append(
            ValidationObservation(
                kind=ValidationKind.BASELINE_GET,
                method="GET",
                url=str(get.request.url),
                status_code=get.status_code,
                server=get.headers.get("server"),
                x_powered_by=get.headers.get("x-powered-by"),
                content_type=get.headers.get("content-type"),
                body_sha256=_sha256(get.content),
                body_length=len(get.content),
            )
        )

    report.notes.append("Validation performed only HEAD and baseline GET requests.")
    report.notes.append(
        "No vulnerability payload, command execution, memory-corruption trigger, "
        "or destructive request was sent."
    )

    return report
