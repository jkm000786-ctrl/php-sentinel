from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from php_sentinel.evidence.writer import write_json_evidence
from php_sentinel.validation.differential import compare_lab_targets

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
) -> None:
    report = compare_lab_targets(
        candidate,
        patched_reference,
        explicit_authorization=authorize_lab,
        timeout=timeout,
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
