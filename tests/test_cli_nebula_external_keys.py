"""The Nebula CLI signing with a CA key held outside the PKI's base path."""

from __future__ import annotations

import shutil
import subprocess
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from pki.backends.nebula.pki import NebulaCertData, NebulaCertificateRequest, NebulaPki, NebulaPublicKey
from pki.certificate_stores.filesystem import FilesystemCertificateStore
from pki.cli import app
from pki.key_stores import InMemoryKeyStore
from pki.models import Subject
from pki.state_stores.filesystem import FilesystemStateStore
from pki.types import KeyAlgorithm, PkiType, SerialNumber

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.skipif(condition=shutil.which("nebula-cert") is None, reason="nebula-cert not found on PATH")

_PRIVATE_KEY_MARKERS = ("PRIVATE KEY", "SIGNING KEY")


def _make_base_with_external_ca(*, base: Path, outside: Path) -> SerialNumber:
    """Create a PKI under *base* whose CA key is written to *outside* only."""
    holder = InMemoryKeyStore()
    pki = NebulaPki(
        key_store=holder,
        certificate_store=FilesystemCertificateStore(
            base_dir=base / "certs",
            cert_request_type=NebulaCertificateRequest,
            cert_data_type=NebulaCertData,
            pki_type=PkiType.NEBULA,
        ),
    )
    ca = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="Test Nebula CA"),
            duration=timedelta(days=3650),
            key_algorithm=KeyAlgorithm.ED25519,
            is_ca=True,
        ),
    )
    FilesystemStateStore(base_dir=base).save_state(state=pki.export_state())
    ca_key = holder.get_key(serial_number=ca.serial_number)
    assert ca_key is not None
    outside.mkdir(parents=True, exist_ok=True)
    (outside / "ca.key").write_bytes(ca_key)
    return ca.serial_number


def _keygen(*, directory: Path, name: str) -> Path:
    subprocess.run(
        [
            "nebula-cert",
            "keygen",
            "-out-key",
            str(directory / f"{name}.key"),
            "-out-pub",
            str(directory / f"{name}.pub"),
        ],
        check=True,
        capture_output=True,
    )
    return directory / f"{name}.pub"


def _assert_no_private_key_under(*, base: Path) -> None:
    assert not (base / "keys").exists() or not any((base / "keys").iterdir())
    for path in base.rglob("*"):
        if path.is_file():
            content = path.read_text(errors="replace")
            assert not any(marker in content for marker in _PRIVATE_KEY_MARKERS), path


def _parse_issued(*, output: str) -> dict[str, str]:
    """Read the ``Label: value`` lines the CLI prints for an issued certificate."""
    return {
        label.strip(): value.strip()
        for label, _, value in (line.partition(":") for line in output.splitlines())
        if value
    }


def _issue(
    *, runner: CliRunner, base: Path, ca_serial: SerialNumber, name: str, ip: str, public_key: Path, extra: list[str]
) -> dict[str, str]:
    result = runner.invoke(
        app,
        [
            "--base-path",
            str(base),
            "nebula",
            "issue",
            "--common-name",
            name,
            "--ip",
            ip,
            "--ca-serial",
            str(ca_serial),
            "--duration",
            "30d",
            "--groups",
            "developer",
            "--public-key",
            str(public_key),
            *extra,
        ],
    )
    assert result.exit_code == 0, result.output
    return _parse_issued(output=result.output)


@pytest.mark.parametrize("via_env", [False, True], ids=["option", "env"])
def test_issue_with_ca_key_outside_base_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, via_env: bool) -> None:
    base = tmp_path / "pki"
    outside = tmp_path / "secret-store"
    ca_serial = _make_base_with_external_ca(base=base, outside=outside)
    public_key = _keygen(directory=tmp_path, name="host1")

    extra: list[str] = []
    if via_env:
        monkeypatch.setenv("PKI_NEBULA_CA_KEY", str(outside / "ca.key"))
    else:
        extra = ["--ca-key", str(outside / "ca.key")]
    issued = _issue(
        runner=CliRunner(),
        base=base,
        ca_serial=ca_serial,
        name="host1",
        ip="10.0.0.1/24",
        public_key=public_key,
        extra=extra,
    )

    assert issued["Common Name"] == "host1"
    _assert_no_private_key_under(base=base)


def test_issue_without_any_ca_key_fails(tmp_path: Path) -> None:
    base = tmp_path / "pki"
    ca_serial = _make_base_with_external_ca(base=base, outside=tmp_path / "secret-store")
    result = CliRunner().invoke(
        app,
        [
            "--base-path",
            str(base),
            "nebula",
            "issue",
            "--common-name",
            "host1",
            "--ip",
            "10.0.0.1/24",
            "--ca-serial",
            str(ca_serial),
            "--duration",
            "30d",
            "--public-key",
            str(_keygen(directory=tmp_path, name="host1")),
        ],
    )
    assert result.exit_code == 1
    assert "Key not found" in result.output


def test_issue_refuses_public_key_of_other_host(tmp_path: Path) -> None:
    base = tmp_path / "pki"
    outside = tmp_path / "secret-store"
    ca_serial = _make_base_with_external_ca(base=base, outside=outside)
    public_key = _keygen(directory=tmp_path, name="host1")
    runner = CliRunner()
    extra = ["--ca-key", str(outside / "ca.key")]
    _issue(
        runner=runner,
        base=base,
        ca_serial=ca_serial,
        name="host1",
        ip="10.0.0.1/24",
        public_key=public_key,
        extra=extra,
    )

    result = runner.invoke(
        app,
        [
            "--base-path",
            str(base),
            "nebula",
            "issue",
            "--common-name",
            "host2",
            "--ip",
            "10.0.0.2/24",
            "--ca-serial",
            str(ca_serial),
            "--duration",
            "30d",
            "--public-key",
            str(public_key),
            *extra,
        ],
    )
    assert result.exit_code == 1
    assert "'host1'" in result.output


def test_renew_with_ca_key_outside_base_path(tmp_path: Path) -> None:
    base = tmp_path / "pki"
    outside = tmp_path / "secret-store"
    ca_serial = _make_base_with_external_ca(base=base, outside=outside)
    public_key = _keygen(directory=tmp_path, name="host1")
    runner = CliRunner()
    extra = ["--ca-key", str(outside / "ca.key")]
    issued = _issue(
        runner=runner,
        base=base,
        ca_serial=ca_serial,
        name="host1",
        ip="10.0.0.1/24",
        public_key=public_key,
        extra=extra,
    )
    (tmp_path / "host1.key").unlink()

    result = runner.invoke(
        app,
        ["--base-path", str(base), "nebula", "renew", issued["Serial"], *extra],
    )

    assert result.exit_code == 0, result.output
    renewed = _parse_issued(output=result.output)
    assert renewed["Serial"] != issued["Serial"]
    assert renewed["Common Name"] == "host1"
    pki = NebulaPki(
        pki_state=FilesystemStateStore(base_dir=base).load_state(),
        certificate_store=FilesystemCertificateStore(
            base_dir=base / "certs",
            cert_request_type=NebulaCertificateRequest,
            cert_data_type=NebulaCertData,
            pki_type=PkiType.NEBULA,
        ),
    )
    assert pki.get_public_key(serial_number=SerialNumber(int(renewed["Serial"]))) == NebulaPublicKey.from_pem(
        pem=public_key.read_text(),
    )
    _assert_no_private_key_under(base=base)
