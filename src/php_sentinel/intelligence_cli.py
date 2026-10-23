from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from php_sentinel.intelligence.repository import (
    load_policy,
    policy_identity,
)

console = Console()


def _load_or_exit(
    policy_path: Path | None,
):
    try:
        return load_policy(policy_path)
    except (
        OSError,
        ValueError,
        ValidationError,
        json.JSONDecodeError,
    ) as exc:
        console.print(f"[bold red]Policy validation failed:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc


def main(
    policy_path: Annotated[
        Path | None,
        typer.Option(
            "--policy",
            help=("Optional intelligence policy JSON file. Defaults to the bundled policy."),
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help=("Emit validated policy identity and policy content as JSON."),
        ),
    ] = False,
    validate_only: Annotated[
        bool,
        typer.Option(
            "--validate-only",
            help=("Validate policy schema and integrity without using it for assessment."),
        ),
    ] = False,
) -> None:
    policy = _load_or_exit(policy_path)

    identity = policy_identity(policy)

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "identity": identity,
                    "policy": policy.model_dump(mode="json"),
                },
                indent=2,
            )
        )
        return

    if validate_only:
        console.print("[bold green]Policy valid[/bold green]")
        console.print(f"Policy ID: {policy.policy_id}")
        console.print(f"Schema version: {policy.schema_version}")
        console.print(f"SHA-256: {identity['sha256']}")
        return

    console.print(
        "[bold]PHP Sentinel Intelligence "
        "Policy[/bold]\n"
        f"Policy ID: {policy.policy_id}\n"
        f"Schema version: "
        f"{policy.schema_version}\n"
        f"Published: "
        f"{policy.published_date}\n"
        f"Publisher: "
        f"{policy.source.publisher}\n"
        f"SHA-256: {identity['sha256']}"
    )

    versions = Table(title="Upstream Fixed Versions")
    versions.add_column("Branch")
    versions.add_column("Fixed version")

    for branch, version_value in sorted(
        policy.fixed_versions.items(),
        reverse=True,
    ):
        versions.add_row(
            branch,
            version_value,
        )

    console.print(versions)

    cves = Table(title="Modeled CVEs")
    cves.add_column("CVE")
    cves.add_column("Severity")
    cves.add_column("Title")

    for item in policy.cves:
        cves.add_row(
            item.cve_id,
            item.severity,
            item.title,
        )

    console.print(cves)


def cli() -> None:
    typer.run(main)


if __name__ == "__main__":
    cli()
