from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from php_sentinel.intelligence.source_registry import (
    IntelligenceSourceRegistryError,
    activate_registry_cached_intelligence,
    load_source_registry,
    promote_registry_candidate,
    resolve_source_selection,
    stage_registry_bundle,
    verify_registry_staged_bundle,
)
from php_sentinel.intelligence.update import (
    IntelligenceUpdateError,
    discover_verified_cache,
    promote_verified_candidate,
    select_and_activate_cached_intelligence,
    select_verified_cache_candidate,
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


@app.command("cache-list")
def cache_list(
    verified_root: Annotated[
        Path,
        typer.Option(
            "--verified-root",
        ),
    ],
    policy_id: Annotated[
        str | None,
        typer.Option(
            "--policy-id",
        ),
    ] = None,
) -> None:
    try:
        entries = discover_verified_cache(
            verified_root,
            policy_id=policy_id,
        )

    except IntelligenceUpdateError as exc:
        console.print(f"[bold red]Cache inspection failed:[/bold red] {exc}")

        raise typer.Exit(code=5) from exc

    typer.echo(
        json.dumps(
            [entry.model_dump(mode="json") for entry in entries],
            indent=2,
        )
    )


@app.command("cache-select")
def cache_select(
    verified_root: Annotated[
        Path,
        typer.Option(
            "--verified-root",
        ),
    ],
    policy_id: Annotated[
        str | None,
        typer.Option(
            "--policy-id",
        ),
    ] = None,
) -> None:
    try:
        entry = select_verified_cache_candidate(
            verified_root,
            policy_id=policy_id,
        )

    except IntelligenceUpdateError as exc:
        console.print(f"[bold red]Cache selection failed:[/bold red] {exc}")

        raise typer.Exit(code=5) from exc

    typer.echo(
        json.dumps(
            entry.model_dump(mode="json"),
            indent=2,
        )
    )


@app.command("cache-activate")
def cache_activate(
    verified_root: Annotated[
        Path,
        typer.Option(
            "--verified-root",
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
    policy_id: Annotated[
        str | None,
        typer.Option(
            "--policy-id",
        ),
    ] = None,
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
        entry, selection = select_and_activate_cached_intelligence(
            verified_root=(verified_root),
            trust_store_path=(trust_store),
            lifecycle_state_path=(lifecycle_state),
            policy_id=(policy_id),
            minimum_generation=(minimum_generation),
            maximum_age_days=(maximum_age_days),
        )

    except (
        IntelligenceUpdateError,
        OSError,
        ValueError,
    ) as exc:
        console.print(f"[bold red]Cache activation failed:[/bold red] {exc}")

        raise typer.Exit(code=6) from exc

    typer.echo(
        json.dumps(
            {
                "cache_entry": (entry.model_dump(mode="json")),
                "trust": (selection.trust.model_dump(mode="json")),
                "lifecycle": (selection.lifecycle.model_dump(mode="json")),
            },
            indent=2,
        )
    )


@app.command("source-list")
def source_list(
    registry: Annotated[
        Path,
        typer.Option(
            "--registry",
        ),
    ],
) -> None:
    try:
        loaded = load_source_registry(registry)

    except IntelligenceSourceRegistryError as exc:
        console.print(f"[bold red]Registry load failed:[/bold red] {exc}")

        raise typer.Exit(code=7) from exc

    typer.echo(
        json.dumps(
            loaded.model_dump(mode="json"),
            indent=2,
        )
    )


@app.command("source-resolve")
def source_resolve(
    registry: Annotated[
        Path,
        typer.Option(
            "--registry",
        ),
    ],
    source_id: Annotated[
        str,
        typer.Option(
            "--source-id",
        ),
    ],
    channel: Annotated[
        str,
        typer.Option(
            "--channel",
        ),
    ],
) -> None:
    try:
        loaded = load_source_registry(registry)

        selection = resolve_source_selection(
            registry=loaded,
            source_id=source_id,
            channel=channel,
        )

    except IntelligenceSourceRegistryError as exc:
        console.print(f"[bold red]Source resolution failed:[/bold red] {exc}")

        raise typer.Exit(code=7) from exc

    typer.echo(
        json.dumps(
            selection.model_dump(mode="json"),
            indent=2,
        )
    )


@app.command("source-stage")
def source_stage(
    registry: Annotated[
        Path,
        typer.Option(
            "--registry",
        ),
    ],
    source_id: Annotated[
        str,
        typer.Option(
            "--source-id",
        ),
    ],
    channel: Annotated[
        str,
        typer.Option(
            "--channel",
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
        metadata = stage_registry_bundle(
            registry_path=registry,
            source_id=source_id,
            channel=channel,
            staging_directory=(staging_directory),
        )

    except IntelligenceUpdateError as exc:
        console.print(f"[bold red]Source staging failed:[/bold red] {exc}")

        raise typer.Exit(code=7) from exc

    typer.echo(
        json.dumps(
            metadata.model_dump(mode="json"),
            indent=2,
        )
    )


@app.command("source-promote")
def source_promote(
    registry: Annotated[
        Path,
        typer.Option(
            "--registry",
        ),
    ],
    source_id: Annotated[
        str,
        typer.Option(
            "--source-id",
        ),
    ],
    channel: Annotated[
        str,
        typer.Option(
            "--channel",
        ),
    ],
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
        candidate = verify_registry_staged_bundle(
            registry_path=registry,
            source_id=source_id,
            channel=channel,
            staging_directory=(staging_directory),
            trust_store_path=(trust_store),
            lifecycle_state_path=(lifecycle_state),
            minimum_generation=(minimum_generation),
            maximum_age_days=(maximum_age_days),
        )

        destination = promote_registry_candidate(
            candidate=candidate,
            verified_root=verified_root,
            expected_source_id=source_id,
            expected_channel=channel,
        )

    except IntelligenceUpdateError as exc:
        console.print(f"[bold red]Source promotion failed:[/bold red] {exc}")

        raise typer.Exit(code=8) from exc

    console.print("[bold green]Registry-constrained bundle cached.[/bold green]")
    console.print(f"Path: {destination}")
    console.print("Activation has NOT occurred.")


@app.command("source-activate")
def source_activate(
    registry: Annotated[
        Path,
        typer.Option(
            "--registry",
        ),
    ],
    source_id: Annotated[
        str,
        typer.Option(
            "--source-id",
        ),
    ],
    channel: Annotated[
        str,
        typer.Option(
            "--channel",
        ),
    ],
    verified_root: Annotated[
        Path,
        typer.Option(
            "--verified-root",
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
    policy_id: Annotated[
        str | None,
        typer.Option(
            "--policy-id",
        ),
    ] = None,
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
        entry, selection = activate_registry_cached_intelligence(
            registry_path=registry,
            source_id=source_id,
            channel=channel,
            verified_root=(verified_root),
            trust_store_path=(trust_store),
            lifecycle_state_path=(lifecycle_state),
            policy_id=policy_id,
            minimum_generation=(minimum_generation),
            maximum_age_days=(maximum_age_days),
        )

    except (
        IntelligenceUpdateError,
        OSError,
        ValueError,
    ) as exc:
        console.print(f"[bold red]Source activation failed:[/bold red] {exc}")

        raise typer.Exit(code=9) from exc

    typer.echo(
        json.dumps(
            {
                "cache_entry": (entry.model_dump(mode="json")),
                "trust": (selection.trust.model_dump(mode="json")),
                "lifecycle": (selection.lifecycle.model_dump(mode="json")),
            },
            indent=2,
        )
    )


def cli() -> None:
    app()


if __name__ == "__main__":
    cli()
