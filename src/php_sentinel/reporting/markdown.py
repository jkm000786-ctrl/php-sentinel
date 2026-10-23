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
