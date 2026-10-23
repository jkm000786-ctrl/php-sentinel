import json
from pathlib import Path
from typing import Annotated

import httpx
import typer
from rich.console import Console
from rich.table import Table

from php_sentinel.assessment.exposure import assess_response
from php_sentinel.assessment.pipeline import run_unified_assessment
from php_sentinel.evidence.writer import write_json_evidence
from php_sentinel.http.client import fetch
from php_sentinel.intelligence.activation import (
    IntelligenceActivationError,
    activate_verified_intelligence,
)
from php_sentinel.intelligence.lifecycle import (
    DEFAULT_LIFECYCLE_STATE_PATH,
)
from php_sentinel.models.vendor import (
    BackportStatus,
    VendorEvidence,
    VendorFamily,
)
from php_sentinel.reporting.markdown import render_markdown_report
from php_sentinel.validation.runner import run_lab_validation

app = typer.Typer(
    help="PHP Sentinel — evidence-driven PHP exposure assessment.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def analyze(
    target: Annotated[
        str,
        typer.Argument(help="Authorized HTTP(S) target URL."),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit JSON."),
    ] = False,
    timeout: Annotated[
        float,
        typer.Option(help="HTTP timeout in seconds."),
    ] = 10.0,
    vendor: Annotated[
        VendorFamily,
        typer.Option(
            "--vendor",
            help="Package/vendor family when independently known.",
        ),
    ] = VendorFamily.UNKNOWN,
    package_name: Annotated[
        str | None,
        typer.Option(
            "--package-name",
            help="Installed PHP package name from trusted evidence.",
        ),
    ] = None,
    package_version: Annotated[
        str | None,
        typer.Option(
            "--package-version",
            help="Full installed package version from trusted evidence.",
        ),
    ] = None,
    backport_status: Annotated[
        BackportStatus,
        typer.Option(
            "--backport-status",
            help="Vendor fix evidence classification.",
        ),
    ] = BackportStatus.UNKNOWN,
    advisory_reference: Annotated[
        str | None,
        typer.Option(
            "--advisory-ref",
            help="Vendor security advisory or package-security reference.",
        ),
    ] = None,
    validate_lab: Annotated[
        bool,
        typer.Option(
            "--validate-lab",
            help="Run safe loopback-only validation.",
        ),
    ] = False,
    authorize_lab: Annotated[
        bool,
        typer.Option(
            "--authorize-lab",
            help="Explicitly authorize this local lab validation.",
        ),
    ] = False,
    evidence_out: Annotated[
        Path | None,
        typer.Option(
            "--evidence-out",
            help="Write validation evidence to JSON.",
        ),
    ] = None,
) -> None:
    if validate_lab:
        validation = run_lab_validation(
            target,
            explicit_authorization=authorize_lab,
            timeout=timeout,
        )

        if evidence_out:
            path = write_json_evidence(
                validation,
                evidence_out,
            )
            console.print(f"[green]Validation evidence written:[/green] {path}")

        if not validation.authorized:
            console.print("[red]Lab validation denied by scope policy.[/red]")
            for reason in validation.notes:
                console.print(f" • {reason}")
            raise typer.Exit(code=3)

        console.print("[green]Safe lab validation completed.[/green]")
        for observation in validation.observations:
            console.print(f" • {observation.method} {observation.status_code} {observation.url}")

    try:
        response = fetch(target, timeout=timeout)
    except httpx.HTTPError as exc:
        console.print(f"[red]HTTP error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    has_vendor_evidence = any(
        (
            vendor != VendorFamily.UNKNOWN,
            package_name,
            package_version,
            backport_status != BackportStatus.UNKNOWN,
            advisory_reference,
        )
    )

    vendor_evidence = None

    if has_vendor_evidence:
        vendor_evidence = VendorEvidence(
            vendor=vendor,
            package_name=package_name,
            package_version=package_version,
            backport_status=backport_status,
            advisory_reference=advisory_reference,
            source="operator-supplied",
        )

    result = assess_response(
        target,
        response,
        vendor_evidence=vendor_evidence,
    )

    if json_output:
        typer.echo(
            json.dumps(
                result.model_dump(mode="json"),
                indent=2,
            )
        )
        return

    table = Table(title="PHP Sentinel Assessment")
    table.add_column("Field")
    table.add_column("Value")

    table.add_row("Target", result.target)
    table.add_row("HTTP status", str(response.status_code))
    table.add_row("PHP detected", str(result.php_detected))
    table.add_row("PHP confidence", f"{result.php_confidence:.0%}")
    table.add_row("PHP version", result.php_version or "unknown")
    table.add_row("Server", result.server or "unknown")
    table.add_row(
        "Server family",
        result.fingerprint.server_family.value,
    )
    table.add_row(
        "SAPI hypothesis",
        result.fingerprint.sapi.value,
    )
    table.add_row(
        "SAPI confidence",
        f"{result.fingerprint.sapi_confidence:.0%}",
    )

    if result.vendor_evidence:
        table.add_row(
            "Vendor",
            result.vendor_evidence.vendor.value,
        )
        table.add_row(
            "Package",
            result.vendor_evidence.package_name or "unknown",
        )
        table.add_row(
            "Package version",
            result.vendor_evidence.package_version or "unknown",
        )
        table.add_row(
            "Backport status",
            result.vendor_evidence.backport_status.value,
        )

    table.add_row(
        "Exposure priority",
        result.exposure_priority,
    )
    table.add_row(
        "Assessment",
        result.status.value,
    )
    table.add_row(
        "Relevant CVEs",
        ", ".join(result.applicable_cves) or "none established",
    )

    console.print(table)

    console.print("\n[bold]Rationale[/bold]")
    for item in result.rationale:
        console.print(f" • {item}")

    console.print("\n[bold]Recommended action[/bold]")
    for item in result.remediation:
        console.print(f" • {item}")


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Argument(
            help="Authorized HTTP(S) target URL.",
        ),
    ],
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Emit unified JSON to stdout.",
        ),
    ] = False,
    timeout: Annotated[
        float,
        typer.Option(
            help="HTTP timeout in seconds.",
        ),
    ] = 10.0,
    vendor: Annotated[
        VendorFamily,
        typer.Option(
            "--vendor",
            help="Package/vendor family when independently known.",
        ),
    ] = VendorFamily.UNKNOWN,
    package_name: Annotated[
        str | None,
        typer.Option(
            "--package-name",
            help="Installed PHP package name from trusted evidence.",
        ),
    ] = None,
    package_version: Annotated[
        str | None,
        typer.Option(
            "--package-version",
            help="Full installed package version from trusted evidence.",
        ),
    ] = None,
    backport_status: Annotated[
        BackportStatus,
        typer.Option(
            "--backport-status",
            help="Vendor fix evidence classification.",
        ),
    ] = BackportStatus.UNKNOWN,
    advisory_reference: Annotated[
        str | None,
        typer.Option(
            "--advisory-ref",
            help="Vendor security advisory or package reference.",
        ),
    ] = None,
    validate_lab: Annotated[
        bool,
        typer.Option(
            "--validate-lab",
            help="Run safe loopback-only validation before scan.",
        ),
    ] = False,
    authorize_lab: Annotated[
        bool,
        typer.Option(
            "--authorize-lab",
            help="Explicitly authorize local laboratory validation.",
        ),
    ] = False,
    evidence_out: Annotated[
        Path | None,
        typer.Option(
            "--evidence-out",
            help="Write unified evidence report to JSON.",
        ),
    ] = None,
    markdown_out: Annotated[
        Path | None,
        typer.Option(
            "--markdown-out",
            help="Write human-readable Markdown report.",
        ),
    ] = None,
    policy_path: Annotated[
        Path | None,
        typer.Option(
            "--policy",
            help=("External intelligence policy JSON. Requires --manifest and --trust-store."),
        ),
    ] = None,
    manifest_path: Annotated[
        Path | None,
        typer.Option(
            "--manifest",
            help=("Detached signed intelligence manifest. Requires --policy and --trust-store."),
        ),
    ] = None,
    trust_store_path: Annotated[
        Path | None,
        typer.Option(
            "--trust-store",
            help=("Trusted signer store for external intelligence activation."),
        ),
    ] = None,
    minimum_policy_generation: Annotated[
        int,
        typer.Option(
            "--minimum-policy-generation",
            help=("Reject external manifests below this generation."),
        ),
    ] = 1,
    max_policy_age_days: Annotated[
        int,
        typer.Option(
            "--max-policy-age-days",
            help=("Maximum accepted age for an external manifest."),
        ),
    ] = 30,
    lifecycle_state_path: Annotated[
        Path,
        typer.Option(
            "--lifecycle-state",
            help=("Persistent rollback/replay protection state for external intelligence."),
        ),
    ] = DEFAULT_LIFECYCLE_STATE_PATH,
) -> None:
    try:
        intelligence_selection = activate_verified_intelligence(
            policy_path=policy_path,
            manifest_path=manifest_path,
            trust_store_path=trust_store_path,
            lifecycle_state_path=(lifecycle_state_path if policy_path is not None else None),
            minimum_generation=(minimum_policy_generation),
            maximum_age_days=(max_policy_age_days),
        )
    except IntelligenceActivationError as exc:
        console.print(f"[red]Intelligence activation denied:[/red] {exc}")
        raise typer.Exit(code=4) from exc

    validation = None

    if validate_lab:
        validation = run_lab_validation(
            target,
            explicit_authorization=authorize_lab,
            timeout=timeout,
        )

        if not validation.authorized:
            if evidence_out:
                denied_path = evidence_out.with_name(
                    f"{evidence_out.stem}-validation-denied{evidence_out.suffix or '.json'}"
                )
                path = write_json_evidence(
                    validation,
                    denied_path,
                )
                console.print(f"[yellow]Validation denial evidence written:[/yellow] {path}")

            console.print("[red]Lab validation denied by scope policy.[/red]")

            for reason in validation.notes:
                console.print(f" • {reason}")

            raise typer.Exit(code=3)

    try:
        report = run_unified_assessment(
            target,
            timeout=timeout,
            vendor=vendor,
            package_name=package_name,
            package_version=package_version,
            backport_status=backport_status,
            advisory_reference=advisory_reference,
            lab_validation=validation,
            intelligence_selection=(intelligence_selection),
        )
    except httpx.HTTPError as exc:
        console.print(f"[red]HTTP error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if evidence_out:
        path = write_json_evidence(
            report,
            evidence_out,
        )
        console.print(f"[green]Unified evidence written:[/green] {path}")

    if markdown_out:
        markdown_out.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        markdown_out.write_text(
            render_markdown_report(report),
            encoding="utf-8",
        )
        console.print(f"[green]Markdown report written:[/green] {markdown_out}")

    if json_output:
        typer.echo(
            json.dumps(
                report.model_dump(mode="json"),
                indent=2,
            )
        )
        return

    assessment = report.assessment

    summary = Table(title="PHP Sentinel Unified Assessment")
    summary.add_column("Field")
    summary.add_column("Value")

    summary.add_row(
        "Requested target",
        report.http.requested_url,
    )
    summary.add_row(
        "Final URL",
        report.http.final_url,
    )
    summary.add_row(
        "HTTP status",
        str(report.http.status_code),
    )
    summary.add_row(
        "Redirects",
        str(report.http.redirect_count),
    )
    summary.add_row(
        "PHP detected",
        str(assessment.php_detected),
    )
    summary.add_row(
        "PHP confidence",
        f"{assessment.php_confidence:.0%}",
    )
    summary.add_row(
        "PHP version",
        assessment.php_version or "unknown",
    )
    summary.add_row(
        "Server",
        assessment.server or "unknown",
    )
    summary.add_row(
        "SAPI hypothesis",
        assessment.fingerprint.sapi.value,
    )
    summary.add_row(
        "SAPI confidence",
        f"{assessment.fingerprint.sapi_confidence:.0%}",
    )
    summary.add_row(
        "Assessment",
        assessment.status.value,
    )
    summary.add_row(
        "Exposure priority",
        assessment.exposure_priority,
    )
    summary.add_row(
        "Body SHA-256",
        report.http.body_sha256,
    )
    summary.add_row(
        "Intelligence policy",
        (report.provenance.intelligence_policy_id or "legacy/unknown"),
    )
    summary.add_row(
        "Intelligence trust",
        (report.provenance.intelligence_trust_state or "legacy/unknown"),
    )
    summary.add_row(
        "Intelligence signer",
        (report.provenance.intelligence_signer_id or "none"),
    )
    summary.add_row(
        "Lifecycle state",
        (report.provenance.intelligence_lifecycle_state or "legacy/unknown"),
    )
    summary.add_row(
        "Policy generation",
        (
            str(report.provenance.intelligence_generation)
            if (report.provenance.intelligence_generation is not None)
            else "n/a"
        ),
    )

    console.print(summary)

    cve_table = Table(title="Per-CVE Decisions")
    cve_table.add_column("CVE")
    cve_table.add_column("Status")
    cve_table.add_column("Confidence")
    cve_table.add_column("Priority")
    cve_table.add_column("Fixed threshold")

    for decision in report.cve_decisions.decisions:
        cve_table.add_row(
            decision.cve_id,
            decision.status.value,
            decision.confidence.value,
            decision.exposure_priority.value,
            decision.fixed_version or "n/a",
        )

    console.print(cve_table)

    console.print("\n[bold]Assessment rationale[/bold]")

    for item in assessment.rationale:
        console.print(f" • {item}")

    console.print("\n[bold]CVE decisions[/bold]")

    for decision in report.cve_decisions.decisions:
        console.print(
            f" • {decision.cve_id}: {decision.status.value} ({decision.confidence.value})"
        )

    console.print("\n[bold]Recommended action[/bold]")

    seen: set[str] = set()

    for item in assessment.remediation:
        if item not in seen:
            console.print(f" • {item}")
            seen.add(item)

    for decision in report.cve_decisions.decisions:
        for item in decision.remediation:
            if item not in seen:
                console.print(f" • {item}")
                seen.add(item)


if __name__ == "__main__":
    app()
