"""Nebula overlay network PKI backend."""

import json
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from pki.base import Pki
from pki.certificate_stores import CertificateStore
from pki.exceptions import (
    CertificateNotFoundError,
    KeyNotFoundError,
    NebulaCertError,
    PkiError,
    UnsupportedAlgorithmError,
)
from pki.key_stores import InMemoryKeyStore, KeyStore
from pki.models import (
    CertificateData,
    CertificateInfo,
    CertificateRequest,
    PkiState,
)
from pki.types import (
    CertificateStatus,
    Fingerprint,
    KeyAlgorithm,
    PEMString,
    SerialNumber,
)

_CURVE_MAP: dict[KeyAlgorithm, str] = {
    KeyAlgorithm.ED25519: "25519",
    KeyAlgorithm.EC_P256: "P256",
}


class NebulaCertificateRequest(CertificateRequest):
    _identity_exclude_fields: ClassVar[set[str]] = {"duration"}

    duration: timedelta
    ip: str = ""
    groups: list[str] = Field(default_factory=list)
    subnets: list[str] = Field(default_factory=list)

    def expected_not_after(self) -> datetime:
        return datetime.now(tz=UTC) + self.duration


class NebulaParsedCert(BaseModel):
    name: str
    fingerprint: Fingerprint
    not_before: datetime
    not_after: datetime
    is_ca: bool
    groups: list[str]
    networks: list[str]
    unsafe_networks: list[str]
    curve: str


class _NebulaCertJsonDetails(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str = ""
    not_before: datetime = Field(alias="notBefore")
    not_after: datetime = Field(alias="notAfter")
    is_ca: bool = Field(default=False, alias="isCa")
    groups: list[str] | None = None
    networks: list[str] | None = None
    unsafe_networks: list[str] | None = Field(default=None, alias="unsafeNetworks")


class _NebulaCertJsonEntry(BaseModel):
    details: _NebulaCertJsonDetails
    fingerprint: str
    curve: str = ""


def _run_nebula_cert(
    nebula_cert_path: str, args: list[str], *, cwd: str | Path | None = None
) -> subprocess.CompletedProcess[str]:
    cmd = [nebula_cert_path, *args]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=cwd)  # noqa: S603
    except FileNotFoundError as exc:
        raise NebulaCertError(f"nebula-cert binary not found: {nebula_cert_path}") from exc
    except subprocess.CalledProcessError as exc:
        raise NebulaCertError(
            f"nebula-cert command failed: {' '.join(cmd)}",
            stderr=exc.stderr,
        ) from exc


def _parse_nebula_cert(certificate_pem: PEMString, *, nebula_cert_path: str = "nebula-cert") -> NebulaParsedCert:
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path = Path(tmpdir) / "cert.crt"
        cert_path.write_text(certificate_pem)
        result = _run_nebula_cert(nebula_cert_path, args=["print", "-path", str(cert_path), "-json"])
    parsed: list[dict[str, object]] = json.loads(result.stdout)
    entry = _NebulaCertJsonEntry.model_validate(parsed[0])
    return NebulaParsedCert(
        name=entry.details.name,
        fingerprint=Fingerprint(entry.fingerprint),
        not_before=entry.details.not_before,
        not_after=entry.details.not_after,
        is_ca=entry.details.is_ca,
        groups=entry.details.groups or [],
        networks=entry.details.networks or [],
        unsafe_networks=entry.details.unsafe_networks or [],
        curve=entry.curve,
    )


class NebulaCertData(CertificateData):
    certificate_pem: PEMString
    parsed: NebulaParsedCert

    @property
    def not_before(self) -> datetime:
        return self.parsed.not_before

    @property
    def not_after(self) -> datetime:
        return self.parsed.not_after


def _duration_to_flag(duration: timedelta) -> str:
    return f"{int(duration.total_seconds())}s"


class NebulaPki(Pki[NebulaCertificateRequest, NebulaCertData]):
    def __init__(
        self,
        *,
        pki_state: PkiState | None = None,
        nebula_cert_path: str = "nebula-cert",
        key_store: KeyStore | None = None,
        certificate_store: CertificateStore[NebulaCertificateRequest, NebulaCertData] | None = None,
    ) -> None:
        super().__init__(pki_state=pki_state, certificate_store=certificate_store)
        self._nebula_cert_path = nebula_cert_path
        self._key_store: KeyStore = key_store or InMemoryKeyStore()

    def _run_nebula_cert(self, args: list[str], *, cwd: str | Path | None = None) -> subprocess.CompletedProcess[str]:
        return _run_nebula_cert(self._nebula_cert_path, args=args, cwd=cwd)

    def _do_issue_certificate(
        self,
        request: NebulaCertificateRequest,
        *,
        serial_number: SerialNumber,
        ca_serial_number: SerialNumber | None = None,
    ) -> CertificateInfo[NebulaCertificateRequest, NebulaCertData]:
        curve = _CURVE_MAP.get(request.key_algorithm)
        if curve is None:
            raise UnsupportedAlgorithmError(algorithm=str(request.key_algorithm))

        duration = _duration_to_flag(duration=request.duration)

        if request.is_ca and ca_serial_number is None:
            return self._issue_ca(request=request, serial=serial_number, curve=curve, duration=duration)
        if ca_serial_number is not None:
            return self._issue_host(
                request=request,
                serial=serial_number,
                curve=curve,
                duration=duration,
                ca_serial_number=ca_serial_number,
            )
        msg = "Non-CA certificates require ca_serial_number"
        raise PkiError(msg)

    def _issue_ca(
        self,
        *,
        request: NebulaCertificateRequest,
        serial: SerialNumber,
        curve: str,
        duration: str,
    ) -> CertificateInfo[NebulaCertificateRequest, NebulaCertData]:
        with tempfile.TemporaryDirectory() as tmpdir:
            args = [
                "ca",
                "-name",
                request.subject.common_name,
                "-duration",
                duration,
                "-curve",
                curve,
                "-out-crt",
                str(Path(tmpdir) / "ca.crt"),
                "-out-key",
                str(Path(tmpdir) / "ca.key"),
            ]
            if request.groups:
                args.extend(["-groups", ",".join(request.groups)])
            if request.subnets:
                args.extend(["-subnets", ",".join(request.subnets)])
            if request.ip:
                args.extend(["-ips", request.ip])

            self._run_nebula_cert(args=args)

            ca_crt_path = Path(tmpdir) / "ca.crt"
            ca_crt_pem = PEMString(ca_crt_path.read_text())
            ca_key_bytes = (Path(tmpdir) / "ca.key").read_bytes()
            parsed = _parse_nebula_cert(ca_crt_pem, nebula_cert_path=self._nebula_cert_path)

        self._key_store.store_key(serial_number=serial, data=ca_key_bytes)

        return CertificateInfo[NebulaCertificateRequest, NebulaCertData](
            request=request,
            serial_number=serial,
            status=CertificateStatus.ISSUED,
            issue_date=datetime.now(tz=UTC),
            backend_data=NebulaCertData(
                certificate_pem=ca_crt_pem,
                parsed=parsed,
            ),
        )

    def _issue_host(
        self,
        *,
        request: NebulaCertificateRequest,
        serial: SerialNumber,
        curve: str,
        duration: str,
        ca_serial_number: SerialNumber,
    ) -> CertificateInfo[NebulaCertificateRequest, NebulaCertData]:
        ca_cert_info = self.get_certificate(serial_number=ca_serial_number)
        if ca_cert_info is None:
            raise CertificateNotFoundError(serial_number=ca_serial_number)

        ca_key_bytes = self._key_store.get_key(serial_number=ca_serial_number)
        if ca_key_bytes is None:
            raise KeyNotFoundError(serial_number=ca_serial_number)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            # Write CA cert and key to temp files
            (tmppath / "ca.crt").write_text(ca_cert_info.backend_data.certificate_pem)
            (tmppath / "ca.key").write_bytes(ca_key_bytes)

            args = [
                "sign",
                "-name",
                request.subject.common_name,
                "-ip",
                request.ip,
                "-duration",
                duration,
                "-ca-crt",
                str(tmppath / "ca.crt"),
                "-ca-key",
                str(tmppath / "ca.key"),
                "-out-crt",
                str(tmppath / "host.crt"),
                "-out-key",
                str(tmppath / "host.key"),
            ]
            if request.groups:
                args.extend(["-groups", ",".join(request.groups)])
            if request.subnets:
                args.extend(["-subnets", ",".join(request.subnets)])

            self._run_nebula_cert(args=args)

            host_crt_path = tmppath / "host.crt"
            host_crt_pem = PEMString(host_crt_path.read_text())
            host_key_bytes = (tmppath / "host.key").read_bytes()
            parsed = _parse_nebula_cert(host_crt_pem, nebula_cert_path=self._nebula_cert_path)

        self._key_store.store_key(serial_number=serial, data=host_key_bytes)

        return CertificateInfo[NebulaCertificateRequest, NebulaCertData](
            request=request,
            serial_number=serial,
            ca_serial_number=ca_serial_number,
            status=CertificateStatus.ISSUED,
            issue_date=datetime.now(tz=UTC),
            backend_data=NebulaCertData(
                certificate_pem=host_crt_pem,
                parsed=parsed,
            ),
        )

    def export_certificate_pem(self, serial_number: SerialNumber) -> bytes:
        cert = self.get_certificate(serial_number=serial_number)
        if cert is None:
            raise CertificateNotFoundError(serial_number=serial_number)
        return cert.backend_data.certificate_pem.encode()

    def export_private_key_pem(self, serial_number: SerialNumber) -> bytes:
        cert = self.get_certificate(serial_number=serial_number)
        if cert is None:
            raise CertificateNotFoundError(serial_number=serial_number)
        key_data = self._key_store.get_key(serial_number=serial_number)
        if key_data is None:
            raise KeyNotFoundError(serial_number=serial_number)
        return key_data
