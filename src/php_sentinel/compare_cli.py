from __future__ import annotations

import errno
import json
import os
import stat
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from php_sentinel.comparison.engine import (
    compare_reports,
)
from php_sentinel.intelligence.platform_security import (
    PlatformSecurityCapabilityError,
    require_nofollow_open,
)
from php_sentinel.models.unified import (
    UnifiedAssessmentReport,
)

console = Console()

COMPARE_REPORT_MAX_BYTES = 8 * 1024 * 1024


def _read_report_bytes(
    path: Path,
    *,
    maximum_bytes: int = COMPARE_REPORT_MAX_BYTES,
) -> bytes:
    if maximum_bytes < 1:
        raise ValueError("maximum_bytes must be positive.")

    try:
        require_nofollow_open(
            operation="Comparison report read",
        )
    except PlatformSecurityCapabilityError as exc:
        raise ValueError(
            "Comparison report read is unavailable because the current platform "
            "cannot provide no-follow open semantics."
        ) from exc

    flags = os.O_RDONLY

    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= os.O_NOFOLLOW

    try:
        descriptor = os.open(
            path,
            flags,
        )
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"Comparison report must not be a symbolic link: {path}.") from exc
        raise

    try:
        status = os.fstat(descriptor)

        if not stat.S_ISREG(status.st_mode):
            raise ValueError(f"Comparison report is not a regular file: {path}.")

        chunks: list[bytes] = []
        total = 0

        while True:
            remaining = maximum_bytes - total

            chunk = os.read(
                descriptor,
                min(1024 * 1024, remaining + 1),
            )

            if not chunk:
                break

            total += len(chunk)

            if total > maximum_bytes:
                raise ValueError(f"Comparison report exceeds the maximum allowed size: {path}.")

            chunks.append(chunk)

        return b"".join(chunks)

    finally:
        os.close(descriptor)


def load_report(
    path: Path,
) -> UnifiedAssessmentReport:
    data = json.loads(_read_report_bytes(path).decode("utf-8"))

    return UnifiedAssessmentReport.model_validate(data)


def main(
    before: Annotated[
        Path,
        typer.Argument(
            help="Earlier PHP Sentinel JSON report.",
        ),
    ],
    after: Annotated[
        Path,
        typer.Argument(
            help="Later PHP Sentinel JSON report.",
        ),
    ],
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Emit comparison JSON.",
        ),
    ] = False,
    allow_cross_target: Annotated[
        bool,
        typer.Option(
            "--allow-cross-target",
            help=("Explicitly permit comparison of reports whose requested targets differ."),
        ),
    ] = False,
) -> None:
    before_report = load_report(before)
    after_report = load_report(after)

    result = compare_reports(
        before_report,
        after_report,
        allow_cross_target=allow_cross_target,
    )

    if json_output:
        typer.echo(
            json.dumps(
                result.model_dump(mode="json"),
                indent=2,
            )
        )
        return

    summary = Table(title="PHP Sentinel Baseline Comparison")
    summary.add_column("Field")
    summary.add_column("Before")
    summary.add_column("After")

    summary.add_row(
        "Report ID",
        result.before_report_id,
        result.after_report_id,
    )
    summary.add_row(
        "PHP version",
        result.php_version_before or "unknown",
        result.php_version_after or "unknown",
    )
    summary.add_row(
        "Assessment",
        result.assessment_before,
        result.assessment_after,
    )
    summary.add_row(
        "Policy version",
        before_report.provenance.policy_version,
        after_report.provenance.policy_version,
    )
    summary.add_row(
        "Canonical evidence",
        before_report.provenance.canonical_sha256,
        after_report.provenance.canonical_sha256,
    )
    summary.add_row(
        "Target identity",
        before_report.provenance.target_identity_sha256,
        after_report.provenance.target_identity_sha256,
    )

    console.print(summary)

    console.print(f"\n[bold]Overall transition:[/bold] {result.overall_state.value}")

    cve_table = Table(title="Per-CVE Transitions")
    cve_table.add_column("CVE")
    cve_table.add_column("Before")
    cve_table.add_column("After")
    cve_table.add_column("Transition")

    for change in result.cve_changes:
        cve_table.add_row(
            change.cve_id,
            change.before_state or "missing",
            change.after_state or "missing",
            change.transition.value,
        )

    console.print(cve_table)

    console.print("\n[bold]Observed changes[/bold]")

    if result.changes:
        for item in result.changes:
            console.print(f" • {item}")
    else:
        console.print(" • No material evidence changes.")


def cli() -> None:
    typer.run(main)


if __name__ == "__main__":
    cli()
