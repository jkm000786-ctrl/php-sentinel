from __future__ import annotations

import typer

from php_sentinel import __version__


def version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()
