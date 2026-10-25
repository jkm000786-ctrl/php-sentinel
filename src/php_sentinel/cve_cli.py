from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from php_sentinel.evidence.writer import write_json_evidence
from php_sentinel.intelligence.cve_decision_engine import decide_cves
from php_sentinel.versioning import version_callback

console = Console()


def main(
    php_version: Annotated[
        str | None,
        typer.Option(
            "--php-version",
            help="Observed PHP version.",
        ),
    ] = None,
    php_detected: Annotated[
        bool,
        typer.Option(
            "--php-detected/--no-php-detected",
            help="Whether PHP was established from evidence.",
        ),
    ] = True,
    vendor: Annotated[
        str | None,
        typer.Option(
            "--vendor",
            help="Vendor family, e.g. upstream, ubuntu, debian.",
        ),
    ] = None,
    backport_status: Annotated[
        str | None,
        typer.Option(
            "--backport-status",
            help=("confirmed_fixed, probably_fixed, no_fix_evidence, or unknown."),
        ),
    ] = None,
    sapi: Annotated[
        str | None,
        typer.Option(
            "--sapi",
            help=("SAPI hypothesis: mod_php, fpm_fastcgi, cgi, litespeed, frankenphp, or unknown."),
        ),
    ] = None,
    evidence_out: Annotated[
        Path | None,
        typer.Option(
            "--evidence-out",
            help="Write CVE decision evidence as JSON.",
        ),
    ] = None,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=version_callback,
            is_eager=True,
            help="Show PHP Sentinel version and exit.",
        ),
    ] = False,
) -> None:
    report = decide_cves(
        php_detected=php_detected,
        php_version=php_version,
        vendor_family=vendor,
        backport_status=backport_status,
        sapi_hypothesis=sapi,
    )

    if evidence_out:
        path = write_json_evidence(
            report,
            evidence_out,
        )
        console.print(f"[green]CVE evidence written:[/green] {path}")

    table = Table(title="PHP Sentinel CVE Decision Engine")
    table.add_column("CVE")
    table.add_column("Status")
    table.add_column("Confidence")
    table.add_column("Priority")
    table.add_column("Fixed threshold")

    for decision in report.decisions:
        table.add_row(
            decision.cve_id,
            decision.status.value,
            decision.confidence.value,
            decision.exposure_priority.value,
            decision.fixed_version or "n/a",
        )

    console.print(table)

    for decision in report.decisions:
        console.print(f"\n[bold]{decision.cve_id}[/bold] — {decision.title}")

        console.print("[bold]Rationale[/bold]")
        for item in decision.rationale:
            console.print(f" • {item}")

        if decision.remediation:
            console.print("[bold]Remediation[/bold]")
            for item in decision.remediation:
                console.print(f" • {item}")

    console.print("\n[bold]Decision-engine notes[/bold]")
    for note in report.notes:
        console.print(f" • {note}")


def cli() -> None:
    typer.run(main)


if __name__ == "__main__":
    cli()
