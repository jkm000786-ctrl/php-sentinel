from __future__ import annotations

import re

from php_sentinel.evidence.provenance import build_provenance
from php_sentinel.intelligence.activation import VerifiedIntelligenceSelection
from php_sentinel.intelligence.repository import default_policy, policy_identity
from php_sentinel.intelligence.version_policy import evaluate_version
from php_sentinel.models.differential import (
    DifferentialConclusion,
    DifferentialReport,
    RuntimeSnapshot,
)
from php_sentinel.models.intelligence_policy import IntelligencePolicy
from php_sentinel.models.validation import ValidationKind, ValidationReport
from php_sentinel.validation.runner import run_lab_validation

PHP_VERSION_RE = re.compile(
    r"(?:PHP/|PHP\s+)(\d+\.\d+\.\d+)",
    re.IGNORECASE,
)


def _snapshot(
    report: ValidationReport,
    *,
    policy: IntelligencePolicy | None = None,
) -> RuntimeSnapshot:
    get_observation = next(
        (item for item in report.observations if item.kind == ValidationKind.BASELINE_GET),
        None,
    )

    if get_observation is None:
        return RuntimeSnapshot(
            target=report.target,
        )

    version = None

    if get_observation.x_powered_by:
        match = PHP_VERSION_RE.search(get_observation.x_powered_by)
        if match:
            version = match.group(1)

    version_decision = evaluate_version(version, policy=policy)

    return RuntimeSnapshot(
        target=report.target,
        php_version=version,
        upstream_fixed=version_decision.upstream_fixed,
        status_code=get_observation.status_code,
        healthy=200 <= get_observation.status_code < 500,
        x_powered_by=get_observation.x_powered_by,
        server=get_observation.server,
        body_sha256=get_observation.body_sha256,
        body_length=get_observation.body_length,
    )


def compare_lab_targets(
    candidate_target: str,
    patched_target: str,
    *,
    explicit_authorization: bool,
    timeout: float = 10.0,
    intelligence_selection: VerifiedIntelligenceSelection | None = None,
    policy: IntelligencePolicy | None = None,
) -> DifferentialReport:
    if intelligence_selection is not None and policy is not None:
        raise ValueError(
            "Verified intelligence selection cannot be combined with a direct policy."
        )

    if intelligence_selection is not None:
        selected_policy = intelligence_selection.policy
        provenance_selection = intelligence_selection
    else:
        selected_policy = policy or default_policy()
        provenance_selection = None

    candidate_validation = run_lab_validation(
        candidate_target,
        explicit_authorization=explicit_authorization,
        timeout=timeout,
    )

    patched_validation = run_lab_validation(
        patched_target,
        explicit_authorization=explicit_authorization,
        timeout=timeout,
    )

    candidate = _snapshot(candidate_validation, policy=selected_policy)
    patched = _snapshot(patched_validation, policy=selected_policy)

    authorized = candidate_validation.authorized and patched_validation.authorized

    differences: list[str] = []
    notes: list[str] = []

    if candidate.php_version != patched.php_version:
        differences.append(
            "PHP version differs: "
            f"{candidate.php_version or 'unknown'} vs "
            f"{patched.php_version or 'unknown'}."
        )

    if candidate.body_sha256 != patched.body_sha256:
        differences.append("Baseline response body SHA-256 differs.")

    if candidate.status_code != patched.status_code:
        differences.append(
            f"Baseline HTTP status differs: {candidate.status_code} vs {patched.status_code}."
        )

    if not authorized:
        conclusion = DifferentialConclusion.UNAUTHORIZED

    elif candidate.upstream_fixed is False and patched.upstream_fixed is True:
        conclusion = DifferentialConclusion.PRECONDITION_DIFFERENTIAL_CONFIRMED
        notes.append(
            "Candidate runtime is below the modeled upstream fixed "
            "threshold while the reference runtime meets it."
        )

    elif candidate.upstream_fixed is True and patched.upstream_fixed is True:
        conclusion = DifferentialConclusion.BOTH_PATCHED

    elif candidate.php_version is None:
        conclusion = DifferentialConclusion.CANDIDATE_NOT_ESTABLISHED

    else:
        conclusion = DifferentialConclusion.INCONCLUSIVE

    notes.extend(
        [
            ("This comparison validates version and deployment preconditions only."),
            "It does not establish exploitability.",
            (
                "No CVE trigger, command execution, crash trigger, or "
                "memory-corruption payload was used."
            ),
        ]
    )

    intelligence_identity = policy_identity(selected_policy)

    canonical_payload = {
        "intelligence_policy": intelligence_identity,
        "candidate": candidate.model_dump(mode="json"),
        "patched_reference": patched.model_dump(mode="json"),
        "candidate_validation": candidate_validation.model_dump(mode="json"),
        "patched_validation": patched_validation.model_dump(mode="json"),
        "authorized": authorized,
        "conclusion": conclusion.value,
        "differences": differences,
        "notes": notes,
    }

    target_identity_payload = {
        "candidate_target": candidate.target,
        "patched_target": patched.target,
        "candidate_php_version": candidate.php_version,
        "patched_php_version": patched.php_version,
        "candidate_body_sha256": candidate.body_sha256,
        "patched_body_sha256": patched.body_sha256,
    }

    provenance = build_provenance(
        canonical_payload=canonical_payload,
        target_identity_payload=target_identity_payload,
        intelligence_selection=provenance_selection,
        intelligence_policy=(
            selected_policy if provenance_selection is None else None
        ),
    )

    return DifferentialReport(
        candidate=candidate,
        patched_reference=patched,
        candidate_validation=candidate_validation,
        patched_validation=patched_validation,
        authorized=authorized,
        conclusion=conclusion,
        provenance=provenance,
        differences=differences,
        notes=notes,
    )
