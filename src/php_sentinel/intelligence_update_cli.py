from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from php_sentinel.intelligence.update import (
    IntelligenceUpdateError,
    promote_verified_candidate,
    stage_remote_bundle,
    verify_staged_bundle,
)

app = typer.Typer(
    help=(
        "Stage and verify signed PHP Sentinel intelligence updates. "
        "Download success never establishes trust."
    )
)

console = Console()


@app.command()
def stage(
    policy_url: Annotated[
        str,
        typer.Option(
            "--policy-url",
        ),
    ],
    manifest_url: Annotated[
        str,
        typer.Option(
            "--manifest-url",
        ),
    ],
    staging_directory: Annotated[
        Path,
        typer.Option(
            "--staging-dir",
        ),
    ],
) -> None:
    try:
        metadata = stage_remote_bundle(
            policy_url=policy_url,
            manifest_url=manifest_url,
            staging_directory=(staging_directory),
        )

    except IntelligenceUpdateError as exc:
        console.print(f"[bold red]Staging failed:[/bold red] {exc}")

        raise typer.Exit(code=2) from exc

    typer.echo(
        json.dumps(
            metadata.model_dump(mode="json"),
            indent=2,
        )
    )


@app.command()
def verify(
    staging_directory: Annotated[
        Path,
        typer.Option(
            "--staging-dir",
        ),
    ],
    trust_store: Annotated[
        Path,
        typer.Option(
            "--trust-store",
            help=("LOCAL operator-controlled trusted signer store."),
        ),
    ],
    lifecycle_state: Annotated[
        Path,
        typer.Option(
            "--lifecycle-state",
        ),
    ],
    minimum_generation: Annotated[
        int,
        typer.Option(
            "--minimum-generation",
        ),
    ] = 1,
    maximum_age_days: Annotated[
        int,
        typer.Option(
            "--max-age-days",
        ),
    ] = 30,
) -> None:
    try:
        candidate = verify_staged_bundle(
            staging_directory=(staging_directory),
            trust_store_path=(trust_store),
            lifecycle_state_path=(lifecycle_state),
            minimum_generation=(minimum_generation),
            maximum_age_days=(maximum_age_days),
        )

    except (
        IntelligenceUpdateError,
        OSError,
        ValueError,
    ) as exc:
        console.print(f"[bold red]Verification failed:[/bold red] {exc}")

        raise typer.Exit(code=3) from exc

    typer.echo(
        json.dumps(
            candidate.verification_metadata.model_dump(mode="json"),
            indent=2,
        )
    )


@app.command()
def promote(
    staging_directory: Annotated[
        Path,
        typer.Option(
            "--staging-dir",
        ),
    ],
    trust_store: Annotated[
        Path,
        typer.Option(
            "--trust-store",
        ),
    ],
    lifecycle_state: Annotated[
        Path,
        typer.Option(
            "--lifecycle-state",
        ),
    ],
    verified_root: Annotated[
        Path,
        typer.Option(
            "--verified-root",
        ),
    ],
    minimum_generation: Annotated[
        int,
        typer.Option(
            "--minimum-generation",
        ),
    ] = 1,
    maximum_age_days: Annotated[
        int,
        typer.Option(
            "--max-age-days",
        ),
    ] = 30,
) -> None:
    try:
        candidate = verify_staged_bundle(
            staging_directory=(staging_directory),
            trust_store_path=(trust_store),
            lifecycle_state_path=(lifecycle_state),
            minimum_generation=(minimum_generation),
            maximum_age_days=(maximum_age_days),
        )

        destination = promote_verified_candidate(
            candidate=candidate,
            verified_root=(verified_root),
        )

    except (
        IntelligenceUpdateError,
        OSError,
        ValueError,
    ) as exc:
        console.print(f"[bold red]Promotion failed:[/bold red] {exc}")

        raise typer.Exit(code=4) from exc

    console.print("[bold green]Verified bundle cached.[/bold green]")

    console.print(f"Path: {destination}")

    console.print(
        "Activation has NOT occurred. "
        "Use the existing verified activation boundary "
        "with the cached policy and manifest."
    )


def cli() -> None:
    app()


if __name__ == "__main__":
    cli()
