"""Nebula overlay network PKI backend."""

import base64
import binascii
import json
import re
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
    PublicKeyInUseError,
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

# The PEM label `nebula-cert keygen` writes for a host public key, by key algorithm.
_PUBLIC_KEY_LABELS: dict[KeyAlgorithm, str] = {
    KeyAlgorithm.ED25519: "NEBULA X25519 PUBLIC KEY",
    KeyAlgorithm.EC_P256: "NEBULA P256 PUBLIC KEY",
}

# The curve name `nebula-cert print -json` reports, by key algorithm.
_PRINTED_CURVES: dict[KeyAlgorithm, str] = {
    KeyAlgorithm.ED25519: "CURVE25519",
    KeyAlgorithm.EC_P256: "P256",
}

_PEM_RE = re.compile(r"-----BEGIN (?P<label>[A-Z0-9 ]+)-----\s*(?P<body>[A-Za-z0-9+/=\s]+?)\s*-----END (?P=label)-----")


class NebulaPublicKey(BaseModel):
    """A Nebula host public key, as written by ``nebula-cert keygen -out-pub``."""

    key_algorithm: KeyAlgorithm
    raw: bytes

    @classmethod
    def from_pem(cls, pem: str) -> "NebulaPublicKey":
        match = _PEM_RE.search(pem)
        if match is None:
            msg = "Not a PEM-encoded Nebula public key"
            raise PkiError(msg)
        label = match.group("label")
        algorithms = [algorithm for algorithm, known in _PUBLIC_KEY_LABELS.items() if known == label]
        if not algorithms:
            msg = f"Not a Nebula host public key: PEM label {label!r}"
            raise PkiError(msg)
        try:
            raw = base64.b64decode("".join(match.group("body").split()), validate=True)
        except binascii.Error as exc:
            msg = "Malformed Nebula public key: the PEM body is not base64"
            raise PkiError(msg) from exc
        return cls(key_algorithm=algorithms[0], raw=raw)

    @classmethod
    def from_printed(cls, *, curve: str, public_key_hex: str) -> "NebulaPublicKey":
        algorithms = [algorithm for algorithm, known in _PRINTED_CURVES.items() if known == curve]
        if not algorithms:
            raise UnsupportedAlgorithmError(algorithm=curve)
        return cls(key_algorithm=algorithms[0], raw=bytes.fromhex(public_key_hex))

    def to_pem(self) -> PEMString:
        label = _PUBLIC_KEY_LABELS[self.key_algorithm]
        body = base64.b64encode(self.raw).decode("ascii")
        lines = [body[i : i + 64] for i in range(0, len(body), 64)]
        return PEMString("\n".join([f"-----BEGIN {label}-----", *lines, f"-----END {label}-----", ""]))


class NebulaCertificateRequest(CertificateRequest):
    _identity_exclude_fields: ClassVar[set[str]] = {"duration"}

    duration: timedelta
    ip: str = ""
    groups: list[str] = Field(default_factory=list)
    subnets: list[str] = Field(default_factory=list)
    # A host certificate issued from a public key the host generated itself: the
    # private key never reaches the PKI, and the key store holds nothing for it.
    public_key: PEMString | None = None

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
    # Hex, as `nebula-cert print -json` reports it; empty in records stored before it was kept.
    public_key: str = ""


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
    public_key: str = Field(default="", alias="publicKey")


def _run_nebula_cert(
    nebula_cert_path: str, args: list[str], *, cwd: str | Path | None = None
) -> subprocess.CompletedProcess[str]:
    cmd = [nebula_cert_path, *args]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=cwd)
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
        public_key=entry.public_key,
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
        ca_key_path: Path | None = None,
    ) -> None:
        """Create a Nebula PKI.

        *ca_key_path* names a file holding the signing CA's private key, read once
        when the first host certificate is signed. When given, host signing takes
        the CA key from there and never from *key_store*, so the CA key can live
        outside the PKI's storage altogether (a secret manager's tmpfs mount, a
        process-substitution pipe).
        """
        super().__init__(pki_state=pki_state, certificate_store=certificate_store)
        self._nebula_cert_path = nebula_cert_path
        self._key_store: KeyStore = key_store or InMemoryKeyStore()
        self._ca_key_path = ca_key_path
        self._ca_key_from_path: bytes | None = None

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

        if request.public_key is not None and request.is_ca:
            msg = "A CA certificate cannot be issued from a public key"
            raise PkiError(msg)

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

        public_key: NebulaPublicKey | None = None
        if request.public_key is not None:
            public_key = NebulaPublicKey.from_pem(request.public_key)
            if public_key.key_algorithm != request.key_algorithm:
                msg = f"The public key is {public_key.key_algorithm}, but the request asks for {request.key_algorithm}"
                raise PkiError(msg)
            self._refuse_public_key_of_other_host(public_key=public_key, common_name=request.subject.common_name)

        ca_key_bytes = self._get_ca_key(ca_serial_number=ca_serial_number)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            # Write CA cert and key to temp files
            (tmppath / "ca.crt").write_text(ca_cert_info.backend_data.certificate_pem)
            (tmppath / "ca.key").write_bytes(ca_key_bytes)
            (tmppath / "ca.key").chmod(0o600)

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
            ]
            if public_key is None:
                args.extend(["-out-key", str(tmppath / "host.key")])
            else:
                (tmppath / "host.pub").write_text(public_key.to_pem())
                args.extend(["-in-pub", str(tmppath / "host.pub")])
            if request.groups:
                args.extend(["-groups", ",".join(request.groups)])
            if request.subnets:
                args.extend(["-subnets", ",".join(request.subnets)])

            self._run_nebula_cert(args=args)

            host_crt_path = tmppath / "host.crt"
            host_crt_pem = PEMString(host_crt_path.read_text())
            host_key_bytes = (tmppath / "host.key").read_bytes() if public_key is None else None
            parsed = _parse_nebula_cert(host_crt_pem, nebula_cert_path=self._nebula_cert_path)

        if host_key_bytes is not None:
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

    def _get_ca_key(self, *, ca_serial_number: SerialNumber) -> bytes:
        if self._ca_key_path is None:
            ca_key_bytes = self._key_store.get_key(serial_number=ca_serial_number)
            if ca_key_bytes is None:
                raise KeyNotFoundError(serial_number=ca_serial_number)
            return ca_key_bytes
        # Read once and keep in memory: a process-substitution pipe yields its
        # content a single time, and a session may sign more than one certificate.
        if self._ca_key_from_path is None:
            try:
                self._ca_key_from_path = self._ca_key_path.read_bytes()
            except OSError as exc:
                msg = f"Cannot read the CA key from {self._ca_key_path}: {exc.strerror}"
                raise PkiError(msg) from exc
        return self._ca_key_from_path

    def get_public_key(self, serial_number: SerialNumber) -> NebulaPublicKey:
        """Return the public key a stored certificate was issued for."""
        cert = self.get_certificate(serial_number=serial_number)
        if cert is None:
            raise CertificateNotFoundError(serial_number=serial_number)
        parsed = cert.backend_data.parsed
        if not parsed.public_key:
            parsed = _parse_nebula_cert(cert.backend_data.certificate_pem, nebula_cert_path=self._nebula_cert_path)
        return NebulaPublicKey.from_printed(curve=parsed.curve, public_key_hex=parsed.public_key)

    def _refuse_public_key_of_other_host(self, *, public_key: NebulaPublicKey, common_name: str) -> None:
        """Refuse a key another host's certificate, current or not, was issued for.

        One key must identify one host: a key signed under a second name lets
        whoever holds it claim both. The same name may be signed again with its
        own key, which is what a renewal does.
        """
        for cert in self.list_certificates():
            if cert.request.subject.common_name == common_name:
                continue
            if self.get_public_key(serial_number=cert.serial_number) == public_key:
                raise PublicKeyInUseError(
                    common_name=cert.request.subject.common_name, serial_number=cert.serial_number
                )

    def renew_certificate(
        self,
        serial_number: SerialNumber,
        *,
        duration: timedelta | None = None,
    ) -> CertificateInfo[NebulaCertificateRequest, NebulaCertData]:
        """Re-sign a host certificate's own public key with the same name, IP, groups and subnets.

        Needs neither the host's private key nor a new key from the host. The
        renewed certificate is signed by the same CA, for *duration* or else the
        original request's duration. The original certificate is left as it is:
        revoking it, if wanted, is a separate step.
        """
        cert = self.get_certificate(serial_number=serial_number)
        if cert is None:
            raise CertificateNotFoundError(serial_number=serial_number)
        if cert.request.is_ca or cert.ca_serial_number is None:
            msg = f"Only a host certificate can be renewed: {serial_number} is a CA certificate"
            raise PkiError(msg)
        public_key = self.get_public_key(serial_number=serial_number)
        request = cert.request.model_copy(
            update={
                "duration": duration if duration is not None else cert.request.duration,
                "key_algorithm": public_key.key_algorithm,
                "public_key": public_key.to_pem(),
            }
        )
        return self.issue_certificate(request=request, ca_serial_number=cert.ca_serial_number)

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
