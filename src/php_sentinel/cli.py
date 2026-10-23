import json
from pathlib import Path
from typing import Annotated

import httpx
import typer
from rich.console import Console
from rich.table import Table

from php_sentinel.assessment.exposure import assess_response
from php_sentinel.evidence.writer import write_json_evidence
from php_sentinel.http.client import fetch
from php_sentinel.models.vendor import (
    BackportStatus,
    VendorEvidence,
    VendorFamily,
)
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


if __name__ == "__main__":
    app()
