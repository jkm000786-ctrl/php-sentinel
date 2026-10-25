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
from php_sentinel.intelligence.trust import (
    load_manifest,
    load_trust_store,
    verify_manifest,
)
from php_sentinel.versioning import version_callback

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
            help=("Validate policy schema and integrity without activating it."),
        ),
    ] = False,
    verify_manifest_path: Annotated[
        Path | None,
        typer.Option(
            "--verify-manifest",
            help=("Verify a detached Ed25519 manifest for the selected policy."),
        ),
    ] = None,
    trust_store_path: Annotated[
        Path | None,
        typer.Option(
            "--trust-store",
            help=("Trusted signer store used with --verify-manifest."),
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
    policy = _load_or_exit(policy_path)

    identity = policy_identity(policy)

    if verify_manifest_path is not None or trust_store_path is not None:
        if verify_manifest_path is None or trust_store_path is None:
            console.print(
                "[bold red]Both --verify-manifest and --trust-store are required.[/bold red]"
            )
            raise typer.Exit(code=2)

        try:
            manifest = load_manifest(verify_manifest_path)
            trust_store = load_trust_store(trust_store_path)
        except (
            OSError,
            ValueError,
            ValidationError,
            json.JSONDecodeError,
        ) as exc:
            console.print(f"[bold red]Trust data validation failed:[/bold red] {exc}")
            raise typer.Exit(code=2) from exc

        decision = verify_manifest(
            policy,
            manifest,
            trust_store,
        )

        typer.echo(
            json.dumps(
                decision.model_dump(mode="json"),
                indent=2,
            )
        )

        if not decision.trusted:
            raise typer.Exit(code=3)

        return

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
