"""pki-kit CLI — optional command-line interface for pki-kit."""

from __future__ import annotations

from typing import Annotated

import typer

from pki.cli._context import CliContext, OutputFormat

app = typer.Typer(
    name="pki-kit",
    help="PKI management CLI for X.509 and Nebula certificates.",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        from importlib.metadata import version

        print(f"pki-kit {version('pki-kit')}")
        raise typer.Exit


@app.callback()
def main_callback(
    ctx: typer.Context,
    base_path: Annotated[
        str,
        typer.Option(envvar="PKI_KIT_BASE_PATH", help="Root directory for PKI filesystem stores."),
    ] = ".",
    pki_name: Annotated[
        str,
        typer.Option(envvar="PKI_KIT_PKI_NAME", help="PKI instance name (filename prefix)."),
    ] = "default",
    sops_args: Annotated[
        str | None,
        typer.Option(envvar="PKI_KIT_SOPS_ARGS", help="Extra SOPS arguments (space-separated)."),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--output-format", "-f", envvar="PKI_KIT_OUTPUT_FORMAT", help="Output format."),
    ] = OutputFormat.TABLE,
    _version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version and exit."),
    ] = None,
) -> None:
    """PKI management CLI for X.509 and Nebula certificates."""
    from pathlib import Path

    ctx.obj = CliContext(
        base_path=Path(base_path),
        pki_name=pki_name,
        sops_args=tuple(sops_args.split()) if sops_args else (),
        output_format=output_format,
    )


# Register subcommand groups (import after app is defined to avoid circular imports)
from pki.cli._nebula import nebula_app  # noqa: E402
from pki.cli._x509 import x509_app  # noqa: E402

app.add_typer(x509_app)
app.add_typer(nebula_app)


def main() -> None:
    """Entry point for the pki-kit CLI."""
    app()
