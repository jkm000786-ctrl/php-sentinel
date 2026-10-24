from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from php_sentinel.intelligence.registry_trust import (
    SourceRegistryVerificationError,
    activate_cached_intelligence_with_signed_registry,
    activate_signed_source_registry,
    stage_bundle_with_signed_registry,
    verify_signed_source_registry,
    verify_staged_bundle_with_signed_registry,
)
from php_sentinel.intelligence.source_registry import (
    IntelligenceSourceRegistryError,
    load_source_registry,
    promote_registry_candidate,
    resolve_source_selection,
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
    audit_log: Annotated[
        Path | None,
        typer.Option("--audit-log"),
    ] = None,
) -> None:
    try:
        metadata = stage_remote_bundle(
            policy_url=policy_url,
            manifest_url=manifest_url,
            staging_directory=(staging_directory),
            security_audit_path=audit_log,
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
    audit_log: Annotated[
        Path | None,
        typer.Option("--audit-log"),
    ] = None,
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
            security_audit_path=audit_log,
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
    audit_log: Annotated[
        Path | None,
        typer.Option("--audit-log"),
    ] = None,
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
            security_audit_path=audit_log,
            minimum_generation=(minimum_generation),
            maximum_age_days=(maximum_age_days),
        )

        destination = promote_verified_candidate(
            candidate=candidate,
            verified_root=(verified_root),
            security_audit_path=audit_log,
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
        typer.Option("--registry"),
    ],
    registry_manifest: Annotated[
        Path,
        typer.Option("--registry-manifest"),
    ],
    registry_trust_store: Annotated[
        Path,
        typer.Option(
            "--registry-trust-store",
            help=("LOCAL trust store for authenticating the source registry."),
        ),
    ],
    registry_state: Annotated[
        Path,
        typer.Option("--registry-state"),
    ],
    source_id: Annotated[
        str,
        typer.Option("--source-id"),
    ],
    channel: Annotated[
        str,
        typer.Option("--channel"),
    ],
    staging_directory: Annotated[
        Path,
        typer.Option("--staging-dir"),
    ],
    registry_minimum_generation: Annotated[
        int,
        typer.Option("--registry-minimum-generation"),
    ] = 1,
    audit_log: Annotated[
        Path | None,
        typer.Option("--audit-log"),
    ] = None,
    registry_maximum_age_days: Annotated[
        int,
        typer.Option("--registry-max-age-days"),
    ] = 30,
) -> None:
    """
    Stage remote intelligence using an authenticated source registry.

    Registry verification is read-only. Successful transport does not
    establish intelligence trust and does not advance registry state.
    """

    try:
        verified_registry, metadata = stage_bundle_with_signed_registry(
            registry_path=registry,
            registry_manifest_path=(registry_manifest),
            registry_trust_store_path=(registry_trust_store),
            registry_state_path=(registry_state),
            source_id=source_id,
            channel=channel,
            staging_directory=(staging_directory),
            security_audit_path=audit_log,
            registry_minimum_generation=(registry_minimum_generation),
            registry_maximum_age_days=(registry_maximum_age_days),
        )

    except (
        IntelligenceUpdateError,
        SourceRegistryVerificationError,
        OSError,
        ValueError,
    ) as exc:
        console.print(f"[bold red]Authenticated source staging failed:[/bold red] {exc}")

        raise typer.Exit(code=7) from exc

    typer.echo(
        json.dumps(
            {
                "registry_trust": (verified_registry.trust.state.value),
                "registry_lifecycle": (verified_registry.lifecycle.state.value),
                "stage": metadata.model_dump(mode="json"),
            },
            indent=2,
        )
    )


@app.command("source-promote")
def source_promote(
    registry: Annotated[
        Path,
        typer.Option("--registry"),
    ],
    registry_manifest: Annotated[
        Path,
        typer.Option("--registry-manifest"),
    ],
    registry_trust_store: Annotated[
        Path,
        typer.Option("--registry-trust-store"),
    ],
    registry_state: Annotated[
        Path,
        typer.Option("--registry-state"),
    ],
    source_id: Annotated[
        str,
        typer.Option("--source-id"),
    ],
    channel: Annotated[
        str,
        typer.Option("--channel"),
    ],
    staging_directory: Annotated[
        Path,
        typer.Option("--staging-dir"),
    ],
    trust_store: Annotated[
        Path,
        typer.Option(
            "--trust-store",
            help=("LOCAL intelligence signer trust store."),
        ),
    ],
    lifecycle_state: Annotated[
        Path,
        typer.Option("--lifecycle-state"),
    ],
    verified_root: Annotated[
        Path,
        typer.Option("--verified-root"),
    ],
    minimum_generation: Annotated[
        int,
        typer.Option("--minimum-generation"),
    ] = 1,
    maximum_age_days: Annotated[
        int,
        typer.Option("--max-age-days"),
    ] = 30,
    registry_minimum_generation: Annotated[
        int,
        typer.Option("--registry-minimum-generation"),
    ] = 1,
    audit_log: Annotated[
        Path | None,
        typer.Option("--audit-log"),
    ] = None,
    registry_maximum_age_days: Annotated[
        int,
        typer.Option("--registry-max-age-days"),
    ] = 30,
) -> None:
    """
    Verify and cache staged intelligence under authenticated registry policy.

    Registry trust and intelligence trust are evaluated independently.
    Neither lifecycle state is advanced by verification/promotion alone.
    """

    try:
        verified_registry, candidate = verify_staged_bundle_with_signed_registry(
            registry_path=registry,
            registry_manifest_path=(registry_manifest),
            registry_trust_store_path=(registry_trust_store),
            registry_state_path=(registry_state),
            source_id=source_id,
            channel=channel,
            staging_directory=(staging_directory),
            intelligence_trust_store_path=(trust_store),
            intelligence_lifecycle_state_path=(lifecycle_state),
            security_audit_path=audit_log,
            registry_minimum_generation=(registry_minimum_generation),
            registry_maximum_age_days=(registry_maximum_age_days),
            intelligence_minimum_generation=(minimum_generation),
            intelligence_maximum_age_days=(maximum_age_days),
        )

        destination = promote_registry_candidate(
            candidate=candidate,
            verified_root=verified_root,
            expected_source_id=source_id,
            expected_channel=channel,
            security_audit_path=audit_log,
        )

    except (
        IntelligenceUpdateError,
        SourceRegistryVerificationError,
        OSError,
        ValueError,
    ) as exc:
        console.print(f"[bold red]Authenticated source promotion failed:[/bold red] {exc}")

        raise typer.Exit(code=8) from exc

    console.print("[bold green]Authenticated registry-constrained bundle cached.[/bold green]")
    console.print(f"Path: {destination}")
    console.print(f"Registry trust: {verified_registry.trust.state.value}")
    console.print("Activation has NOT occurred.")


@app.command("source-activate")
def source_activate(
    registry: Annotated[
        Path,
        typer.Option("--registry"),
    ],
    registry_manifest: Annotated[
        Path,
        typer.Option("--registry-manifest"),
    ],
    registry_trust_store: Annotated[
        Path,
        typer.Option("--registry-trust-store"),
    ],
    registry_state: Annotated[
        Path,
        typer.Option("--registry-state"),
    ],
    source_id: Annotated[
        str,
        typer.Option("--source-id"),
    ],
    channel: Annotated[
        str,
        typer.Option("--channel"),
    ],
    verified_root: Annotated[
        Path,
        typer.Option("--verified-root"),
    ],
    trust_store: Annotated[
        Path,
        typer.Option(
            "--trust-store",
            help=("LOCAL intelligence signer trust store."),
        ),
    ],
    lifecycle_state: Annotated[
        Path,
        typer.Option("--lifecycle-state"),
    ],
    policy_id: Annotated[
        str | None,
        typer.Option("--policy-id"),
    ] = None,
    minimum_generation: Annotated[
        int,
        typer.Option("--minimum-generation"),
    ] = 1,
    maximum_age_days: Annotated[
        int,
        typer.Option("--max-age-days"),
    ] = 30,
    registry_minimum_generation: Annotated[
        int,
        typer.Option("--registry-minimum-generation"),
    ] = 1,
    audit_log: Annotated[
        Path | None,
        typer.Option("--audit-log"),
    ] = None,
    registry_maximum_age_days: Annotated[
        int,
        typer.Option("--registry-max-age-days"),
    ] = 30,
) -> None:
    """
    Activate cached intelligence under authenticated registry authority.

    This is the authoritative CLI path for registry-constrained activation.
    Registry and intelligence lifecycle state are committed only through
    their existing authoritative activation boundaries.
    """

    try:
        (
            verified_registry,
            entry,
            selection,
        ) = activate_cached_intelligence_with_signed_registry(
            registry_path=registry,
            registry_manifest_path=(registry_manifest),
            registry_trust_store_path=(registry_trust_store),
            registry_state_path=(registry_state),
            source_id=source_id,
            channel=channel,
            verified_root=verified_root,
            intelligence_trust_store_path=(trust_store),
            intelligence_lifecycle_state_path=(lifecycle_state),
            security_audit_path=audit_log,
            policy_id=policy_id,
            registry_minimum_generation=(registry_minimum_generation),
            registry_maximum_age_days=(registry_maximum_age_days),
            intelligence_minimum_generation=(minimum_generation),
            intelligence_maximum_age_days=(maximum_age_days),
        )

    except (
        IntelligenceUpdateError,
        SourceRegistryVerificationError,
        OSError,
        ValueError,
    ) as exc:
        console.print(f"[bold red]Authenticated source activation failed:[/bold red] {exc}")

        raise typer.Exit(code=9) from exc

    typer.echo(
        json.dumps(
            {
                "registry": {
                    "trust": (verified_registry.trust.state.value),
                    "lifecycle": (verified_registry.lifecycle.state.value),
                    "generation": (verified_registry.lifecycle.generation),
                },
                "cache_entry": entry.model_dump(mode="json"),
                "intelligence": {
                    "trust": selection.trust.model_dump(mode="json"),
                    "lifecycle": (selection.lifecycle.model_dump(mode="json")),
                },
            },
            indent=2,
        )
    )


@app.command("registry-verify")
def registry_verify(
    registry: Annotated[
        Path,
        typer.Option("--registry"),
    ],
    manifest: Annotated[
        Path,
        typer.Option("--registry-manifest"),
    ],
    trust_store: Annotated[
        Path,
        typer.Option("--registry-trust-store"),
    ],
    state: Annotated[
        Path,
        typer.Option("--registry-state"),
    ],
    minimum_generation: Annotated[
        int,
        typer.Option("--minimum-generation"),
    ] = 1,
    maximum_age_days: Annotated[
        int,
        typer.Option("--max-age-days"),
    ] = 30,
) -> None:
    try:
        verified = verify_signed_source_registry(
            registry_path=registry,
            manifest_path=manifest,
            registry_trust_store_path=trust_store,
            registry_state_path=state,
            minimum_generation=minimum_generation,
            maximum_age_days=maximum_age_days,
        )

    except (
        SourceRegistryVerificationError,
        OSError,
        ValueError,
    ) as exc:
        console.print(f"[bold red]Registry verification failed:[/bold red] {exc}")
        raise typer.Exit(code=10) from exc

    typer.echo(
        json.dumps(
            {
                "registry_sha256": (verified.trust.registry_sha256),
                "trust": (verified.trust.model_dump(mode="json")),
                "lifecycle": (verified.lifecycle.model_dump(mode="json")),
            },
            indent=2,
        )
    )


@app.command("registry-activate")
def registry_activate(
    registry: Annotated[
        Path,
        typer.Option("--registry"),
    ],
    manifest: Annotated[
        Path,
        typer.Option("--registry-manifest"),
    ],
    trust_store: Annotated[
        Path,
        typer.Option("--registry-trust-store"),
    ],
    state: Annotated[
        Path,
        typer.Option("--registry-state"),
    ],
    minimum_generation: Annotated[
        int,
        typer.Option("--minimum-generation"),
    ] = 1,
    audit_log: Annotated[
        Path | None,
        typer.Option("--audit-log"),
    ] = None,
    maximum_age_days: Annotated[
        int,
        typer.Option("--max-age-days"),
    ] = 30,
) -> None:
    try:
        verified = activate_signed_source_registry(
            registry_path=registry,
            manifest_path=manifest,
            registry_trust_store_path=trust_store,
            registry_state_path=state,
            security_audit_path=audit_log,
            minimum_generation=minimum_generation,
            maximum_age_days=maximum_age_days,
        )

    except (
        SourceRegistryVerificationError,
        OSError,
        ValueError,
    ) as exc:
        console.print(f"[bold red]Registry activation failed:[/bold red] {exc}")
        raise typer.Exit(code=11) from exc

    typer.echo(
        json.dumps(
            {
                "registry_sha256": (verified.trust.registry_sha256),
                "generation": (verified.lifecycle.generation),
                "signer_id": (verified.trust.signer_id),
                "trust": (verified.trust.state.value),
                "lifecycle": (verified.lifecycle.state.value),
            },
            indent=2,
        )
    )


def cli() -> None:
    app()


if __name__ == "__main__":
    cli()
