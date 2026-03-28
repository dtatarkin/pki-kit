"""X.509 CLI subcommands."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from pki.cli._context import CliContext, x509_session
from pki.cli._output import print_certificate_detail, print_certificate_table, print_issued, write_bytes_output
from pki.exceptions import PkiError
from pki.types import (
    CertificateStatus,
    ExtendedKeyUsage,
    KeyAlgorithm,
    KeyUsage,
    RevocationReason,
    SerialNumber,
)

x509_app = typer.Typer(name="x509", help="X.509 certificate management.", no_args_is_help=True)


def _get_ctx(ctx: typer.Context) -> CliContext:
    result: CliContext = ctx.obj
    return result


# --- issue-ca ---


@x509_app.command("issue-ca")
def issue_ca(
    ctx: typer.Context,
    common_name: Annotated[str, typer.Option(help="Certificate common name.")],
    validity_days: Annotated[int, typer.Option(help="Certificate validity in days.")] = 3650,
    key_algorithm: Annotated[KeyAlgorithm, typer.Option(help="Key algorithm.")] = KeyAlgorithm.EC_P256,
    organization: Annotated[str | None, typer.Option(help="Organization name.")] = None,
    org_unit: Annotated[str | None, typer.Option(help="Organizational unit.")] = None,
    country: Annotated[str | None, typer.Option(help="Country code.")] = None,
    state: Annotated[str | None, typer.Option("--state", help="State or province.")] = None,
    locality: Annotated[str | None, typer.Option(help="Locality.")] = None,
    email: Annotated[str | None, typer.Option(help="Email address.")] = None,
    key_usage: Annotated[list[KeyUsage] | None, typer.Option(help="Key usage (repeatable).")] = None,
) -> None:
    """Issue a self-signed CA certificate."""
    from pki.backends.x509.pki import X509CertificateRequest
    from pki.models import Subject

    cli_ctx = _get_ctx(ctx)
    now = datetime.now(tz=UTC)

    request = X509CertificateRequest(
        subject=Subject(
            common_name=common_name,
            organization=organization,
            org_unit=org_unit,
            country=country,
            state=state,
            locality=locality,
            email=email,
        ),
        not_before=now,
        not_after=now + timedelta(days=validity_days),
        key_algorithm=key_algorithm,
        is_ca=True,
        key_usages=key_usage or [KeyUsage.CERT_SIGN, KeyUsage.CRL_SIGN, KeyUsage.DIGITAL_SIGNATURE],
    )

    try:
        with x509_session(cli_ctx) as pki:
            cert = pki.issue_certificate(request=request)
    except PkiError as exc:
        _fail(str(exc))

    print_issued(cert)


# --- issue ---


@x509_app.command("issue")
def issue(
    ctx: typer.Context,
    common_name: Annotated[str, typer.Option(help="Certificate common name.")],
    ca_serial: Annotated[int, typer.Option(help="Serial number of the signing CA certificate.")],
    validity_days: Annotated[int, typer.Option(help="Certificate validity in days.")] = 365,
    key_algorithm: Annotated[KeyAlgorithm, typer.Option(help="Key algorithm.")] = KeyAlgorithm.EC_P256,
    organization: Annotated[str | None, typer.Option(help="Organization name.")] = None,
    org_unit: Annotated[str | None, typer.Option(help="Organizational unit.")] = None,
    country: Annotated[str | None, typer.Option(help="Country code.")] = None,
    state: Annotated[str | None, typer.Option("--state", help="State or province.")] = None,
    locality: Annotated[str | None, typer.Option(help="Locality.")] = None,
    email: Annotated[str | None, typer.Option(help="Email address.")] = None,
    is_ca: Annotated[bool, typer.Option(help="Issue as a sub-CA certificate.")] = False,
    key_usage: Annotated[list[KeyUsage] | None, typer.Option(help="Key usage (repeatable).")] = None,
    extended_key_usage: Annotated[
        list[ExtendedKeyUsage] | None, typer.Option(help="Extended key usage (repeatable).")
    ] = None,
    san_dns: Annotated[list[str] | None, typer.Option(help="SAN DNS name (repeatable).")] = None,
    san_ip: Annotated[list[str] | None, typer.Option(help="SAN IP address (repeatable).")] = None,
    san_email: Annotated[list[str] | None, typer.Option(help="SAN email address (repeatable).")] = None,
) -> None:
    """Issue a certificate signed by an existing CA."""
    from pki.backends.x509.pki import X509CertificateRequest
    from pki.models import Subject

    cli_ctx = _get_ctx(ctx)
    now = datetime.now(tz=UTC)

    request = X509CertificateRequest(
        subject=Subject(
            common_name=common_name,
            organization=organization,
            org_unit=org_unit,
            country=country,
            state=state,
            locality=locality,
            email=email,
        ),
        not_before=now,
        not_after=now + timedelta(days=validity_days),
        key_algorithm=key_algorithm,
        is_ca=is_ca,
        key_usages=key_usage or [],
        extended_key_usages=extended_key_usage or [],
        san_dns_names=san_dns or [],
        san_ip_addresses=san_ip or [],
        san_email_addresses=san_email or [],
    )

    try:
        with x509_session(cli_ctx) as pki:
            cert = pki.issue_certificate(request=request, ca_serial_number=SerialNumber(ca_serial))
    except PkiError as exc:
        _fail(str(exc))

    print_issued(cert)


# --- list ---


@x509_app.command("list")
def list_certs(
    ctx: typer.Context,
    status: Annotated[CertificateStatus | None, typer.Option(help="Filter by status.")] = None,
    common_name: Annotated[str | None, typer.Option(help="Filter by common name.")] = None,
    is_ca: Annotated[bool | None, typer.Option(help="Filter by CA status.")] = None,
) -> None:
    """List certificates."""
    cli_ctx = _get_ctx(ctx)
    try:
        with x509_session(cli_ctx, save_state=False) as pki:
            certs = pki.list_certificates(status=status, common_name=common_name, is_ca=is_ca)
    except PkiError as exc:
        _fail(str(exc))

    print_certificate_table(certs, cli_ctx.output_format)


# --- show ---


@x509_app.command("show")
def show(
    ctx: typer.Context,
    serial_number: Annotated[int, typer.Argument(help="Certificate serial number.")],
) -> None:
    """Show details of a certificate."""
    cli_ctx = _get_ctx(ctx)
    try:
        with x509_session(cli_ctx, save_state=False) as pki:
            cert = pki.get_certificate(serial_number=SerialNumber(serial_number))
    except PkiError as exc:
        _fail(str(exc))

    if cert is None:
        _fail(f"Certificate not found: {serial_number}")

    print_certificate_detail(cert, cli_ctx.output_format)


# --- revoke ---


@x509_app.command("revoke")
def revoke(
    ctx: typer.Context,
    serial_number: Annotated[int, typer.Argument(help="Certificate serial number.")],
    reason: Annotated[RevocationReason, typer.Option(help="Revocation reason.")] = RevocationReason.UNSPECIFIED,
) -> None:
    """Revoke a certificate."""
    cli_ctx = _get_ctx(ctx)
    try:
        with x509_session(cli_ctx) as pki:
            cert = pki.revoke_certificate(serial_number=SerialNumber(serial_number), reason=reason)
    except PkiError as exc:
        _fail(str(exc))

    print_issued(cert)


# --- export-cert ---


@x509_app.command("export-cert")
def export_cert(
    ctx: typer.Context,
    serial_number: Annotated[int, typer.Argument(help="Certificate serial number.")],
    encoding: Annotated[str, typer.Option(help="Export encoding: pem or der.")] = "pem",
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file path.")] = None,
) -> None:
    """Export a certificate."""
    cli_ctx = _get_ctx(ctx)
    sn = SerialNumber(serial_number)

    try:
        with x509_session(cli_ctx, save_state=False) as pki:
            if encoding == "der":
                data = pki.export_certificate_der(serial_number=sn)
            else:
                data = pki.export_certificate_pem(serial_number=sn)
    except PkiError as exc:
        _fail(str(exc))

    write_bytes_output(data, output)


# --- export-key ---


@x509_app.command("export-key")
def export_key(
    ctx: typer.Context,
    serial_number: Annotated[int, typer.Argument(help="Certificate serial number.")],
    encoding: Annotated[str, typer.Option(help="Export encoding: pem or der.")] = "pem",
    password: Annotated[str | None, typer.Option(help="Password for key encryption.")] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file path.")] = None,
) -> None:
    """Export a private key."""
    cli_ctx = _get_ctx(ctx)
    sn = SerialNumber(serial_number)
    pw = password.encode() if password else None

    try:
        with x509_session(cli_ctx, save_state=False) as pki:
            if encoding == "der":
                data = pki.export_private_key_der(serial_number=sn, password=pw)
            else:
                data = pki.export_private_key_pem(serial_number=sn, password=pw)
    except PkiError as exc:
        _fail(str(exc))

    write_bytes_output(data, output)


# --- export-pkcs12 ---


@x509_app.command("export-pkcs12")
def export_pkcs12(
    ctx: typer.Context,
    serial_number: Annotated[int, typer.Argument(help="Certificate serial number.")],
    friendly_name: Annotated[str, typer.Option(help="PKCS#12 friendly name.")] = "certificate",
    password: Annotated[str | None, typer.Option(help="Password for PKCS#12 encryption.")] = None,
    no_ca: Annotated[bool, typer.Option(help="Exclude CA certificate from bundle.")] = False,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file path.")] = None,
) -> None:
    """Export a PKCS#12 bundle."""
    cli_ctx = _get_ctx(ctx)
    sn = SerialNumber(serial_number)
    pw = password.encode() if password else None

    try:
        with x509_session(cli_ctx, save_state=False) as pki:
            data = pki.export_pkcs12_bytes(
                serial_number=sn,
                friendly_name=friendly_name,
                password=pw,
                include_ca=not no_ca,
            )
    except PkiError as exc:
        _fail(str(exc))

    write_bytes_output(data, output)


# --- helpers ---


def _fail(msg: str) -> NoReturn:
    from rich.console import Console

    Console(stderr=True).print(f"[red]Error:[/red] {msg}")
    raise typer.Exit(code=1)
