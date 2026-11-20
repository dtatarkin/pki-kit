"""Nebula CLI subcommands."""

from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from pki.cli._context import CliContext, nebula_session
from pki.cli._output import print_certificate_detail, print_certificate_table, print_issued, write_bytes_output
from pki.exceptions import PkiError
from pki.types import (
    CertificateStatus,
    KeyAlgorithm,
    RevocationReason,
    SerialNumber,
)

nebula_app = typer.Typer(name="nebula", help="Nebula certificate management.", no_args_is_help=True)

_NEBULA_ALGORITHMS = [KeyAlgorithm.ED25519, KeyAlgorithm.EC_P256]

_CA_KEY_HELP = (
    "File holding the signing CA's private key, read instead of the key store "
    "(a tmpfs path or a process substitution such as <(...))."
)


def _get_ctx(ctx: typer.Context) -> CliContext:
    result: CliContext = ctx.obj
    return result


def _parse_duration(value: str) -> timedelta:
    """Parse a human-readable duration string into a timedelta.

    Supported formats: 365d, 8760h, 525600m, 31536000s
    """
    match = re.fullmatch(r"(\d+)([dhms])", value.strip())
    if not match:
        raise typer.BadParameter(f"Invalid duration: {value!r}. Use format like 365d, 8760h, 525600m, or 31536000s.")
    amount = int(match.group(1))
    unit = match.group(2)
    if unit == "d":
        return timedelta(days=amount)
    if unit == "h":
        return timedelta(hours=amount)
    if unit == "m":
        return timedelta(minutes=amount)
    return timedelta(seconds=amount)


# --- issue-ca ---


@nebula_app.command("issue-ca")
def issue_ca(
    ctx: typer.Context,
    common_name: Annotated[str, typer.Option(help="CA certificate name.")],
    duration: Annotated[str, typer.Option(help="Certificate duration (e.g. 8760h, 365d).")],
    key_algorithm: Annotated[
        KeyAlgorithm,
        typer.Option(help="Key algorithm (ed25519 or ec-p256)."),
    ] = KeyAlgorithm.ED25519,
    groups: Annotated[list[str] | None, typer.Option(help="Nebula group (repeatable).")] = None,
    subnets: Annotated[list[str] | None, typer.Option(help="Nebula subnet (repeatable).")] = None,
    ip: Annotated[str | None, typer.Option(help="IP address/CIDR.")] = None,
) -> None:
    """Issue a Nebula CA certificate."""
    from pki.backends.nebula.pki import NebulaCertificateRequest
    from pki.models import Subject

    if key_algorithm not in _NEBULA_ALGORITHMS:
        _fail(f"Nebula only supports {', '.join(a.value for a in _NEBULA_ALGORITHMS)}.")

    cli_ctx = _get_ctx(ctx)
    td = _parse_duration(duration)

    request = NebulaCertificateRequest(
        subject=Subject(common_name=common_name),
        key_algorithm=key_algorithm,
        is_ca=True,
        duration=td,
        groups=groups or [],
        subnets=subnets or [],
        ip=ip or "",
    )

    try:
        with nebula_session(cli_ctx) as pki:
            cert = pki.issue_certificate(request=request)
    except PkiError as exc:
        _fail(str(exc))

    print_issued(cert)


# --- issue ---


@nebula_app.command("issue")
def issue(
    ctx: typer.Context,
    common_name: Annotated[str, typer.Option(help="Host certificate name.")],
    ip: Annotated[str, typer.Option(help="IP address/CIDR for the host.")],
    ca_serial: Annotated[int, typer.Option(help="Serial number of the signing CA certificate.")],
    duration: Annotated[str, typer.Option(help="Certificate duration (e.g. 8760h, 365d).")],
    key_algorithm: Annotated[
        KeyAlgorithm | None,
        typer.Option(help="Key algorithm. Default: that of --public-key, else ed25519."),
    ] = None,
    groups: Annotated[list[str] | None, typer.Option(help="Nebula group (repeatable).")] = None,
    subnets: Annotated[list[str] | None, typer.Option(help="Nebula subnet (repeatable).")] = None,
    public_key: Annotated[
        Path | None,
        typer.Option(
            help="Host public key (`nebula-cert keygen -out-pub`) to sign. The certificate is stored, no key is.",
        ),
    ] = None,
    ca_key: Annotated[Path | None, typer.Option(envvar="PKI_NEBULA_CA_KEY", help=_CA_KEY_HELP)] = None,
) -> None:
    """Issue a Nebula host certificate signed by a CA.

    With --public-key the host keeps its private key: only its public key is signed.
    Without it a key pair is generated and the private key goes to the key store.
    """
    from pki.backends.nebula.pki import NebulaCertificateRequest, NebulaPublicKey
    from pki.models import Subject
    from pki.types import PEMString

    public_key_pem: PEMString | None = None
    if public_key is not None:
        try:
            public_key_pem = PEMString(public_key.read_text())
            parsed_key = NebulaPublicKey.from_pem(pem=public_key_pem)
        except (OSError, PkiError) as exc:
            _fail(f"Cannot use public key {public_key}: {exc}")
        if key_algorithm is None:
            key_algorithm = parsed_key.key_algorithm
    if key_algorithm is None:
        key_algorithm = KeyAlgorithm.ED25519

    if key_algorithm not in _NEBULA_ALGORITHMS:
        _fail(f"Nebula only supports {', '.join(a.value for a in _NEBULA_ALGORITHMS)}.")

    cli_ctx = _get_ctx(ctx)
    td = _parse_duration(duration)

    request = NebulaCertificateRequest(
        subject=Subject(common_name=common_name),
        key_algorithm=key_algorithm,
        is_ca=False,
        duration=td,
        ip=ip,
        groups=groups or [],
        subnets=subnets or [],
        public_key=public_key_pem,
    )

    try:
        with nebula_session(cli_ctx, ca_key_path=ca_key) as pki:
            cert = pki.issue_certificate(request=request, ca_serial_number=SerialNumber(ca_serial))
    except PkiError as exc:
        _fail(str(exc))

    print_issued(cert)


# --- renew ---


@nebula_app.command("renew")
def renew(
    ctx: typer.Context,
    serial_number: Annotated[int, typer.Argument(help="Serial number of the host certificate to renew.")],
    duration: Annotated[
        str | None,
        typer.Option(help="Certificate duration (e.g. 8760h, 365d). Default: the original certificate's."),
    ] = None,
    ca_key: Annotated[Path | None, typer.Option(envvar="PKI_NEBULA_CA_KEY", help=_CA_KEY_HELP)] = None,
) -> None:
    """Re-sign a host certificate's public key with the same name, IP and groups.

    The host's private key is not needed, and the host keeps using it with the new
    certificate. The original certificate stays as it is; revoke it separately if wanted.
    """
    cli_ctx = _get_ctx(ctx)
    td = _parse_duration(duration) if duration is not None else None

    try:
        with nebula_session(cli_ctx, ca_key_path=ca_key) as pki:
            cert = pki.renew_certificate(serial_number=SerialNumber(serial_number), duration=td)
    except PkiError as exc:
        _fail(str(exc))

    print_issued(cert)


# --- list ---


@nebula_app.command("list")
def list_certs(
    ctx: typer.Context,
    status: Annotated[CertificateStatus | None, typer.Option(help="Filter by status.")] = None,
    common_name: Annotated[str | None, typer.Option(help="Filter by common name.")] = None,
    is_ca: Annotated[bool | None, typer.Option(help="Filter by CA status.")] = None,
) -> None:
    """List Nebula certificates."""
    cli_ctx = _get_ctx(ctx)
    try:
        with nebula_session(cli_ctx, save_state=False) as pki:
            certs = pki.list_certificates(status=status, common_name=common_name, is_ca=is_ca)
    except PkiError as exc:
        _fail(str(exc))

    print_certificate_table(certs, cli_ctx.output_format)


# --- show ---


@nebula_app.command("show")
def show(
    ctx: typer.Context,
    serial_number: Annotated[int, typer.Argument(help="Certificate serial number.")],
) -> None:
    """Show details of a Nebula certificate."""
    cli_ctx = _get_ctx(ctx)
    try:
        with nebula_session(cli_ctx, save_state=False) as pki:
            cert = pki.get_certificate(serial_number=SerialNumber(serial_number))
    except PkiError as exc:
        _fail(str(exc))

    if cert is None:
        _fail(f"Certificate not found: {serial_number}")

    print_certificate_detail(cert, cli_ctx.output_format)


# --- revoke ---


@nebula_app.command("revoke")
def revoke(
    ctx: typer.Context,
    serial_number: Annotated[int, typer.Argument(help="Certificate serial number.")],
    reason: Annotated[RevocationReason, typer.Option(help="Revocation reason.")] = RevocationReason.UNSPECIFIED,
) -> None:
    """Revoke a Nebula certificate."""
    cli_ctx = _get_ctx(ctx)
    try:
        with nebula_session(cli_ctx) as pki:
            cert = pki.revoke_certificate(serial_number=SerialNumber(serial_number), reason=reason)
    except PkiError as exc:
        _fail(str(exc))

    print_issued(cert)


# --- export-cert ---


@nebula_app.command("export-cert")
def export_cert(
    ctx: typer.Context,
    serial_number: Annotated[int, typer.Argument(help="Certificate serial number.")],
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file path.")] = None,
) -> None:
    """Export a Nebula certificate PEM."""
    cli_ctx = _get_ctx(ctx)
    try:
        with nebula_session(cli_ctx, save_state=False) as pki:
            data = pki.export_certificate_pem(serial_number=SerialNumber(serial_number))
    except PkiError as exc:
        _fail(str(exc))

    write_bytes_output(data, output)


# --- export-key ---


@nebula_app.command("export-key")
def export_key(
    ctx: typer.Context,
    serial_number: Annotated[int, typer.Argument(help="Certificate serial number.")],
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file path.")] = None,
) -> None:
    """Export a Nebula private key."""
    cli_ctx = _get_ctx(ctx)
    try:
        with nebula_session(cli_ctx, save_state=False) as pki:
            data = pki.export_private_key_pem(serial_number=SerialNumber(serial_number))
    except PkiError as exc:
        _fail(str(exc))

    write_bytes_output(data, output)


# --- helpers ---


def _fail(msg: str) -> NoReturn:
    from rich.console import Console

    Console(stderr=True).print(f"[red]Error:[/red] {msg}")
    raise typer.Exit(code=1)
