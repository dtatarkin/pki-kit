"""Output formatting helpers for the CLI."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Any

from pki.cli._context import OutputFormat

if TYPE_CHECKING:
    from pathlib import Path

    from pki.models import CertificateInfo


def _cert_to_dict(cert: CertificateInfo[Any, Any]) -> dict[str, Any]:
    return cert.model_dump(mode="json", exclude={"backend_data"})


def print_certificate_table(
    certs: list[CertificateInfo[Any, Any]],
    output_format: OutputFormat,
) -> None:
    """Print a list of certificates in the requested format."""
    if output_format == OutputFormat.JSON:
        print(json.dumps([_cert_to_dict(c) for c in certs], indent=2, default=str))
        return

    if output_format == OutputFormat.YAML:
        from ruamel.yaml import YAML

        yaml = YAML()
        yaml.default_flow_style = False
        yaml.dump([_cert_to_dict(c) for c in certs], sys.stdout)
        return

    # Table output via rich
    from rich.console import Console
    from rich.table import Table

    table = Table(show_header=True, header_style="bold")
    table.add_column("Serial")
    table.add_column("Common Name")
    table.add_column("Status")
    table.add_column("CA")
    table.add_column("Algorithm")
    table.add_column("Not Before")
    table.add_column("Not After")

    for cert in certs:
        table.add_row(
            str(cert.serial_number),
            cert.request.subject.common_name,
            cert.status.value,
            "yes" if cert.request.is_ca else "no",
            cert.request.key_algorithm.value,
            cert.not_before.strftime("%Y-%m-%d %H:%M UTC"),
            cert.not_after.strftime("%Y-%m-%d %H:%M UTC"),
        )

    Console(stderr=True).print(table)


def print_certificate_detail(
    cert: CertificateInfo[Any, Any],
    output_format: OutputFormat,
) -> None:
    """Print detailed info for a single certificate."""
    data = _cert_to_dict(cert)

    if output_format == OutputFormat.JSON:
        print(json.dumps(data, indent=2, default=str))
        return

    if output_format == OutputFormat.YAML:
        from ruamel.yaml import YAML

        yaml = YAML()
        yaml.default_flow_style = False
        yaml.dump(data, sys.stdout)
        return

    from rich.console import Console
    from rich.table import Table

    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column("Field", style="bold")
    table.add_column("Value")

    table.add_row("Serial", str(cert.serial_number))
    table.add_row("Common Name", cert.request.subject.common_name)
    table.add_row("Status", cert.status.value)
    table.add_row("CA", "yes" if cert.request.is_ca else "no")
    table.add_row("Algorithm", cert.request.key_algorithm.value)
    table.add_row("Not Before", cert.not_before.strftime("%Y-%m-%d %H:%M:%S UTC"))
    table.add_row("Not After", cert.not_after.strftime("%Y-%m-%d %H:%M:%S UTC"))
    table.add_row("Issue Date", cert.issue_date.strftime("%Y-%m-%d %H:%M:%S UTC"))
    if cert.ca_serial_number is not None:
        table.add_row("CA Serial", str(cert.ca_serial_number))
    if cert.revocation_date is not None:
        table.add_row("Revoked At", cert.revocation_date.strftime("%Y-%m-%d %H:%M:%S UTC"))
    if cert.revocation_reason is not None:
        table.add_row("Revocation Reason", cert.revocation_reason.value)

    # Show subject fields beyond common_name
    subj = cert.request.subject
    for field, label in [
        ("organization", "Organization"),
        ("org_unit", "Org Unit"),
        ("country", "Country"),
        ("state", "State"),
        ("locality", "Locality"),
        ("email", "Email"),
    ]:
        val = getattr(subj, field)
        if val is not None:
            table.add_row(label, val)

    # Show X.509-specific extensions if present
    req = cert.request
    if hasattr(req, "key_usages") and req.key_usages:
        table.add_row("Key Usages", ", ".join(str(u) for u in req.key_usages))
    if hasattr(req, "extended_key_usages") and req.extended_key_usages:
        table.add_row("Ext Key Usages", ", ".join(str(u) for u in req.extended_key_usages))
    if hasattr(req, "san_dns_names") and req.san_dns_names:
        table.add_row("SAN DNS", ", ".join(req.san_dns_names))
    if hasattr(req, "san_ip_addresses") and req.san_ip_addresses:
        table.add_row("SAN IPs", ", ".join(req.san_ip_addresses))
    if hasattr(req, "san_email_addresses") and req.san_email_addresses:
        table.add_row("SAN Emails", ", ".join(req.san_email_addresses))

    # Nebula-specific fields
    if hasattr(req, "ip") and req.ip:
        table.add_row("IP", req.ip)
    if hasattr(req, "groups") and req.groups:
        table.add_row("Groups", ", ".join(req.groups))
    if hasattr(req, "subnets") and req.subnets:
        table.add_row("Subnets", ", ".join(req.subnets))

    Console(stderr=True).print(table)


def write_bytes_output(data: bytes, output_path: Path | None) -> None:
    """Write bytes to a file or stdout."""
    if output_path is not None:
        output_path.write_bytes(data)
        _print_stderr(f"Written to {output_path}")
    else:
        sys.stdout.buffer.write(data)


def _print_stderr(msg: str) -> None:
    from rich.console import Console

    Console(stderr=True).print(msg)


def print_issued(cert: CertificateInfo[Any, Any]) -> None:
    """Print a short summary after issuing or revoking a certificate."""
    from rich.console import Console

    console = Console(stderr=True)
    console.print(f"Serial:      {cert.serial_number}")
    console.print(f"Common Name: {cert.request.subject.common_name}")
    console.print(f"Status:      {cert.status.value}")
