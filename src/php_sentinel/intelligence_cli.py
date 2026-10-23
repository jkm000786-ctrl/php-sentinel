from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from php_sentinel.intelligence.repository import (
    load_policy,
)

console = Console()


def main(
    policy_path: Annotated[
        Path | None,
        typer.Option(
            "--policy",
            help=("Optional intelligence policy JSON file. Defaults to the bundled policy."),
        ),
    ] = None,
) -> None:
    policy = load_policy(policy_path)

    console.print(
        "[bold]PHP Sentinel Intelligence Policy[/bold]\n"
        f"Policy ID: {policy.policy_id}\n"
        f"Schema version: {policy.schema_version}\n"
        f"Published: {policy.published_date}\n"
        f"Publisher: {policy.source.publisher}"
    )

    versions = Table(title="Upstream Fixed Versions")
    versions.add_column("Branch")
    versions.add_column("Fixed version")

    for branch, version in sorted(
        policy.fixed_versions.items(),
        reverse=True,
    ):
        versions.add_row(
            branch,
            version,
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
