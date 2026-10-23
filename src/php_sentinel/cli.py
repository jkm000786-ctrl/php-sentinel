import json

import httpx
import typer
from rich.console import Console
from rich.table import Table

from php_sentinel.assessment.exposure import assess_response
from php_sentinel.http.client import fetch

app = typer.Typer(
    help="PHP Sentinel — evidence-driven PHP exposure assessment.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def analyze(
    target: str = typer.Argument(..., help="Authorized HTTP(S) target URL."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
    timeout: float = typer.Option(10.0, help="HTTP timeout in seconds."),
) -> None:
    try:
        response = fetch(target, timeout=timeout)
    except httpx.HTTPError as exc:
        console.print(f"[red]HTTP error:[/red] {exc}")
        raise typer.Exit(code=2)

    result = assess_response(target, response)

    if json_output:
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))
        return

    table = Table(title="PHP Sentinel Assessment")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Target", result.target)
    table.add_row("HTTP status", str(response.status_code))
    table.add_row("PHP detected", str(result.php_detected))
    table.add_row("PHP version", result.php_version or "unknown")
    table.add_row("Server", result.server or "unknown")
    table.add_row("Assessment", result.status.value)
    table.add_row("Relevant CVEs", ", ".join(result.applicable_cves) or "none established")
    console.print(table)

    console.print("\n[bold]Rationale[/bold]")
    for item in result.rationale:
        console.print(f" • {item}")


if __name__ == "__main__":
    app()
