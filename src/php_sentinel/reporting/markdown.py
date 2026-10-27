from __future__ import annotations

from php_sentinel.models.unified import UnifiedAssessmentReport


def render_markdown_report(
    report: UnifiedAssessmentReport,
) -> str:
    assessment = report.assessment

    lines = [
        "# PHP Sentinel Security Assessment",
        "",
        "## Executive Summary",
        "",
        f"- **Target:** `{report.target}`",
        f"- **Final URL:** `{report.http.final_url}`",
        f"- **HTTP status:** {report.http.status_code}",
        (f"- **Edge provider:** `{report.edge.provider.value}`"),
        (f"- **Edge response class:** `{report.edge.response_class.value}`"),
        (
            "- **Application reachability:** "
            f"`{report.edge.application_reachability.value}`"
        ),
        (f"- **PHP detected:** {assessment.php_detected}"),
        (f"- **PHP version:** {assessment.php_version or 'unknown'}"),
        (f"- **Server:** {assessment.server or 'unknown'}"),
        (
            "- **SAPI hypothesis:** "
            f"{assessment.fingerprint.sapi.value} "
            f"({assessment.fingerprint.sapi_confidence:.0%} confidence)"
        ),
        (f"- **Overall assessment:** `{assessment.status.value}`"),
        (f"- **Exposure priority:** `{assessment.exposure_priority}`"),
        "",
        "## Edge Security Context",
        "",
        f"- **Edge detected:** {report.edge.edge_detected}",
        f"- **WAF detected:** {report.edge.waf_detected}",
        f"- **Provider:** `{report.edge.provider.value}`",
        (
            "- **Provider confidence:** "
            f"{report.edge.provider_confidence:.0%}"
        ),
        f"- **Provider ambiguous:** {report.edge.provider_ambiguous}",
        f"- **Response class:** `{report.edge.response_class.value}`",
        (
            "- **Application reachability:** "
            f"`{report.edge.application_reachability.value}`"
        ),
        f"- **Challenge detected:** {report.edge.challenge_detected}",
        f"- **Rate limited:** {report.edge.rate_limited}",
        "",
        "## Transport Execution",
        "",
        (
            "- **Attempts:** "
            f"{report.transport.execution.attempts if report.transport else 'n/a'}"
        ),
        (
            "- **Requests sent:** "
            f"{report.transport.execution.requests_sent if report.transport else 'n/a'}"
        ),
        (
            "- **Retries:** "
            f"{report.transport.execution.retries if report.transport else 'n/a'}"
        ),
        (
            "- **Redirect count:** "
            f"{report.transport.execution.redirect_count if report.transport else 'n/a'}"
        ),
        (
            "- **Budget exhausted:** "
            f"{report.transport.execution.budget_exhausted if report.transport else 'n/a'}"
        ),
        (
            "- **Rate limit observed:** "
            f"{report.transport.execution.rate_limit_observed if report.transport else 'n/a'}"
        ),
        (
            "- **Retry-After observed:** "
            f"{report.transport.execution.retry_after_observed if report.transport else 'n/a'}"
        ),
        (
            "- **Retry-After honored:** "
            f"{report.transport.execution.retry_after_honored if report.transport else 'n/a'}"
        ),
        (
            "- **Redirect target denied:** "
            f"{report.transport.execution.redirect_target_denied if report.transport else 'n/a'}"
        ),
        (
            "- **Stop reason:** "
            f"`{report.transport.execution.stop_reason.value if report.transport else 'n/a'}`"
        ),
        "",
        "## Evidence Provenance",
        "",
        (f"- **Report ID:** `{report.provenance.report_id}`"),
        (f"- **Tool:** {report.provenance.tool_name} {report.provenance.tool_version}"),
        (f"- **Policy version:** `{report.provenance.policy_version}`"),
        (f"- **Intelligence policy:** `{report.provenance.intelligence_policy_id or 'unknown'}`"),
        (f"- **Intelligence SHA-256:** `{report.provenance.intelligence_sha256 or 'unknown'}`"),
        (f"- **Intelligence trust:** `{report.provenance.intelligence_trust_state or 'unknown'}`"),
        (f"- **Intelligence signer:** `{report.provenance.intelligence_signer_id or 'none'}`"),
        (
            "- **Signature algorithm:** "
            f"`{report.provenance.intelligence_signature_algorithm or 'none'}`"
        ),
        (f"- **Lifecycle state:** `{report.provenance.intelligence_lifecycle_state or 'unknown'}`"),
        (
            "- **Policy generation:** "
            f"`{report.provenance.intelligence_generation if report.provenance.intelligence_generation is not None else 'n/a'}`"
        ),
        (f"- **Manifest issued at:** `{report.provenance.intelligence_issued_at or 'n/a'}`"),
        (f"- **Manifest expires at:** `{report.provenance.intelligence_expires_at or 'n/a'}`"),
        (f"- **Canonical evidence SHA-256:** `{report.provenance.canonical_sha256}`"),
        (f"- **Target identity SHA-256:** `{report.provenance.target_identity_sha256}`"),
        (
            "- **Provenance edge provider:** "
            f"`{report.provenance.edge_provider or 'unknown'}`"
        ),
        (
            "- **Provenance response class:** "
            f"`{report.provenance.edge_response_class or 'unknown'}`"
        ),
        (
            "- **Provenance application reachability:** "
            f"`{report.provenance.application_reachability or 'unknown'}`"
        ),
        "",
        (
            "> `bundled_trusted` means package-local PHP Sentinel trust; "
            "it does not mean the intelligence was independently signed "
            "by the PHP upstream project."
        ),
        "",
        "## Evidence Integrity",
        "",
        (f"- **Response body length:** {report.http.body_length} bytes"),
        (f"- **Response SHA-256:** `{report.http.body_sha256}`"),
        ("- PHP Sentinel does not persist the arbitrary HTTP response body in unified evidence."),
        "",
        "## Findings",
        "",
    ]

    for finding in report.findings:
        lines.extend(
            [
                f"### {finding.cve_id} — {finding.title}",
                "",
                f"- **State:** `{finding.state.value}`",
                f"- **Severity:** `{finding.severity.value}`",
                f"- **Confidence:** `{finding.confidence}`",
                (f"- **Detected PHP:** `{finding.detected_version or 'unknown'}`"),
                (f"- **Fixed threshold:** `{finding.fixed_version or 'n/a'}`"),
                (f"- **SAPI:** `{finding.sapi_hypothesis or 'unknown'}`"),
                "",
                "#### Evidence",
                "",
            ]
        )

        for item in finding.evidence:
            lines.append(f"- {item}")

        lines.extend(
            [
                "",
                "#### Rationale",
                "",
            ]
        )

        for item in finding.rationale:
            lines.append(f"- {item}")

        lines.extend(
            [
                "",
                "#### Remediation",
                "",
            ]
        )

        if finding.remediation:
            for item in finding.remediation:
                lines.append(f"- {item}")
        else:
            lines.append("- No additional remediation required.")

        lines.append("")

    lines.extend(
        [
            "## Interpretation Boundary",
            "",
            (
                "A `potential_exposure` finding means the modeled "
                "security preconditions remain present."
            ),
            "",
            (
                "It does **not** mean PHP Sentinel achieved command "
                "execution, compromise, memory corruption, or confirmed "
                "remote-code execution."
            ),
            "",
            (
                "Vendor-maintained packages must be evaluated against "
                "authoritative vendor package and advisory evidence."
            ),
            "",
        ]
    )

    return "\n".join(lines)
