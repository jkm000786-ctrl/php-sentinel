from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from php_sentinel.evidence.writer import write_json_evidence
from php_sentinel.intelligence.activation import (
    IntelligenceActivationError,
    activate_verified_intelligence,
)
from php_sentinel.intelligence.lifecycle import DEFAULT_LIFECYCLE_STATE_PATH
from php_sentinel.validation.differential import compare_lab_targets
from php_sentinel.versioning import version_callback

console = Console()


def main(
    candidate: Annotated[
        str,
        typer.Argument(help="Loopback candidate PHP runtime."),
    ],
    patched_reference: Annotated[
        str,
        typer.Argument(help="Loopback patched PHP reference runtime."),
    ],
    authorize_lab: Annotated[
        bool,
        typer.Option(
            "--authorize-lab",
            help="Explicitly authorize local laboratory comparison.",
        ),
    ] = False,
    evidence_out: Annotated[
        Path | None,
        typer.Option(
            "--evidence-out",
            help="Write differential evidence as JSON.",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            help="HTTP timeout in seconds.",
        ),
    ] = 10.0,
    policy_path: Annotated[
        Path | None,
        typer.Option(
            "--policy",
            help="External intelligence policy JSON. Requires --manifest and --trust-store.",
        ),
    ] = None,
    manifest_path: Annotated[
        Path | None,
        typer.Option(
            "--manifest",
            help="Detached signed intelligence manifest. Requires --policy and --trust-store.",
        ),
    ] = None,
    trust_store_path: Annotated[
        Path | None,
        typer.Option(
            "--trust-store",
            help="Trusted signer store for external intelligence activation.",
        ),
    ] = None,
    minimum_policy_generation: Annotated[
        int,
        typer.Option(
            "--minimum-policy-generation",
            help="Reject external manifests below this generation.",
        ),
    ] = 1,
    max_policy_age_days: Annotated[
        int,
        typer.Option(
            "--max-policy-age-days",
            help="Maximum accepted age for an external manifest.",
        ),
    ] = 30,
    lifecycle_state_path: Annotated[
        Path,
        typer.Option(
            "--lifecycle-state",
            help="Persistent rollback/replay protection state for external intelligence.",
        ),
    ] = DEFAULT_LIFECYCLE_STATE_PATH,
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
    try:
        intelligence_selection = activate_verified_intelligence(
            policy_path=policy_path,
            manifest_path=manifest_path,
            trust_store_path=trust_store_path,
            lifecycle_state_path=(
                lifecycle_state_path if policy_path is not None else None
            ),
            minimum_generation=minimum_policy_generation,
            maximum_age_days=max_policy_age_days,
        )
    except IntelligenceActivationError as exc:
        console.print(f"[red]Intelligence activation denied:[/red] {exc}")
        raise typer.Exit(code=4) from exc

    report = compare_lab_targets(
        candidate,
        patched_reference,
        explicit_authorization=authorize_lab,
        timeout=timeout,
        intelligence_selection=intelligence_selection,
    )

    if evidence_out:
        path = write_json_evidence(
            report,
            evidence_out,
        )
        console.print(f"[green]Matrix evidence written:[/green] {path}")

    table = Table(title="PHP Sentinel Differential Lab Matrix")
    table.add_column("Field")
    table.add_column("Candidate")
    table.add_column("Patched reference")

    table.add_row(
        "Target",
        report.candidate.target,
        report.patched_reference.target,
    )
    table.add_row(
        "PHP version",
        report.candidate.php_version or "unknown",
        report.patched_reference.php_version or "unknown",
    )
    table.add_row(
        "Upstream fixed",
        str(report.candidate.upstream_fixed),
        str(report.patched_reference.upstream_fixed),
    )
    table.add_row(
        "HTTP status",
        str(report.candidate.status_code),
        str(report.patched_reference.status_code),
    )
    table.add_row(
        "Healthy",
        str(report.candidate.healthy),
        str(report.patched_reference.healthy),
    )
    table.add_row(
        "Body SHA-256",
        report.candidate.body_sha256 or "none",
        report.patched_reference.body_sha256 or "none",
    )

    if report.provenance is not None:
        policy_id = report.provenance.intelligence_policy_id or "unknown"
        trust_state = report.provenance.intelligence_trust_state or "unknown"
        table.add_row("Intelligence policy", policy_id, policy_id)
        table.add_row("Intelligence trust", trust_state, trust_state)

    console.print(table)

    console.print(f"\n[bold]Conclusion:[/bold] {report.conclusion.value}")

    if report.differences:
        console.print("\n[bold]Differences[/bold]")
        for difference in report.differences:
            console.print(f" • {difference}")

    console.print("\n[bold]Notes[/bold]")
    for note in report.notes:
        console.print(f" • {note}")

    if not report.authorized:
        raise typer.Exit(code=3)


def cli() -> None:
    typer.run(main)


if __name__ == "__main__":
    cli()
