"""Issuing Nebula host certificates from a public key the host generated itself."""

from __future__ import annotations

import shutil
import subprocess
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest

from pki import KeyNotFoundError, PkiError, PublicKeyInUseError
from pki.backends.nebula.pki import NebulaCertData, NebulaCertificateRequest, NebulaPki, NebulaPublicKey
from pki.certificate_stores import InMemoryCertificateStore
from pki.key_stores import InMemoryKeyStore
from pki.models import Subject
from pki.types import KeyAlgorithm, PEMString, SerialNumber

if TYPE_CHECKING:
    from pathlib import Path

_NEBULA_CERT = shutil.which("nebula-cert")
pytestmark = pytest.mark.skipif(condition=_NEBULA_CERT is None, reason="nebula-cert not found on PATH")

_CA_DURATION = timedelta(days=3650)
_CERT_DURATION = timedelta(days=365)

_CURVES: dict[KeyAlgorithm, str] = {KeyAlgorithm.ED25519: "25519", KeyAlgorithm.EC_P256: "P256"}


def _keygen(*, directory: Path, name: str, key_algorithm: KeyAlgorithm = KeyAlgorithm.ED25519) -> PEMString:
    """Generate a host key pair the way a host owner does, returning the public key PEM."""
    subprocess.run(
        [
            "nebula-cert",
            "keygen",
            "-curve",
            _CURVES[key_algorithm],
            "-out-key",
            str(directory / f"{name}.key"),
            "-out-pub",
            str(directory / f"{name}.pub"),
        ],
        check=True,
        capture_output=True,
    )
    return PEMString((directory / f"{name}.pub").read_text())


def _make_pki(*, key_store: InMemoryKeyStore) -> tuple[NebulaPki, SerialNumber]:
    pki = NebulaPki(
        key_store=key_store,
        certificate_store=InMemoryCertificateStore[NebulaCertificateRequest, NebulaCertData](),
    )
    ca = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="Test Nebula CA"),
            duration=_CA_DURATION,
            key_algorithm=KeyAlgorithm.ED25519,
            is_ca=True,
        ),
    )
    return pki, ca.serial_number


def _host_request(*, name: str, ip: str, public_key: PEMString | None) -> NebulaCertificateRequest:
    return NebulaCertificateRequest(
        subject=Subject(common_name=name),
        duration=_CERT_DURATION,
        ip=ip,
        groups=["servers", "web"],
        key_algorithm=KeyAlgorithm.ED25519,
        public_key=public_key,
    )


# --- issuing from a public key ---


def test_issue_from_public_key_stores_no_key(tmp_path: Path) -> None:
    key_store = InMemoryKeyStore()
    pki, ca_serial = _make_pki(key_store=key_store)
    public_key_pem = _keygen(directory=tmp_path, name="host1")

    cert = pki.issue_certificate(
        request=_host_request(name="host1", ip="10.0.0.1/24", public_key=public_key_pem),
        ca_serial_number=ca_serial,
    )

    assert key_store.get_key(serial_number=cert.serial_number) is None
    with pytest.raises(KeyNotFoundError):
        pki.export_private_key_pem(serial_number=cert.serial_number)
    assert pki.get_public_key(serial_number=cert.serial_number) == NebulaPublicKey.from_pem(pem=public_key_pem)
    assert cert.backend_data.parsed.public_key == NebulaPublicKey.from_pem(pem=public_key_pem).raw.hex()


def test_issued_certificate_verifies_against_ca_and_pairs_with_host_key(tmp_path: Path) -> None:
    pki, ca_serial = _make_pki(key_store=InMemoryKeyStore())
    public_key_pem = _keygen(directory=tmp_path, name="host1")
    cert = pki.issue_certificate(
        request=_host_request(name="host1", ip="10.0.0.1/24", public_key=public_key_pem),
        ca_serial_number=ca_serial,
    )
    (tmp_path / "ca.crt").write_bytes(pki.export_certificate_pem(serial_number=ca_serial))
    (tmp_path / "host1.crt").write_bytes(pki.export_certificate_pem(serial_number=cert.serial_number))

    subprocess.run(
        ["nebula-cert", "verify", "-ca", str(tmp_path / "ca.crt"), "-crt", str(tmp_path / "host1.crt")],
        check=True,
        capture_output=True,
    )
    # The certificate's public key is the one beside the private key the host kept.
    printed = subprocess.run(
        ["nebula-cert", "print", "-path", str(tmp_path / "host1.crt"), "-json"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert NebulaPublicKey.from_pem(pem=public_key_pem).raw.hex() in printed.stdout


def test_issue_from_public_key_p256(tmp_path: Path) -> None:
    pki = NebulaPki(certificate_store=InMemoryCertificateStore[NebulaCertificateRequest, NebulaCertData]())
    ca = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="P256 CA"),
            duration=_CA_DURATION,
            key_algorithm=KeyAlgorithm.EC_P256,
            is_ca=True,
        ),
    )
    public_key_pem = _keygen(directory=tmp_path, name="host-p256", key_algorithm=KeyAlgorithm.EC_P256)
    cert = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="host-p256"),
            duration=_CERT_DURATION,
            ip="10.0.0.5/24",
            key_algorithm=KeyAlgorithm.EC_P256,
            public_key=public_key_pem,
        ),
        ca_serial_number=ca.serial_number,
    )
    assert pki.get_public_key(serial_number=cert.serial_number) == NebulaPublicKey.from_pem(pem=public_key_pem)


def test_public_key_must_match_requested_algorithm(tmp_path: Path) -> None:
    pki, ca_serial = _make_pki(key_store=InMemoryKeyStore())
    public_key_pem = _keygen(directory=tmp_path, name="host1", key_algorithm=KeyAlgorithm.EC_P256)
    with pytest.raises(PkiError, match="ec_p256"):
        pki.issue_certificate(
            request=_host_request(name="host1", ip="10.0.0.1/24", public_key=public_key_pem),
            ca_serial_number=ca_serial,
        )


def test_ca_cannot_be_issued_from_public_key(tmp_path: Path) -> None:
    pki = NebulaPki()
    with pytest.raises(PkiError, match="CA certificate"):
        pki.issue_certificate(
            request=NebulaCertificateRequest(
                subject=Subject(common_name="CA"),
                duration=_CA_DURATION,
                key_algorithm=KeyAlgorithm.ED25519,
                is_ca=True,
                public_key=_keygen(directory=tmp_path, name="ca"),
            ),
        )


@pytest.mark.parametrize(
    "pem",
    [
        "not a key",
        "-----BEGIN NEBULA X25519 PRIVATE KEY-----\nAAAA\n-----END NEBULA X25519 PRIVATE KEY-----\n",
    ],
)
def test_public_key_pem_is_validated(pem: str) -> None:
    with pytest.raises(PkiError):
        NebulaPublicKey.from_pem(pem=pem)


def test_public_key_pem_round_trip(tmp_path: Path) -> None:
    pem = _keygen(directory=tmp_path, name="host1")
    assert NebulaPublicKey.from_pem(pem=pem).to_pem() == pem


# --- refusing a public key signed for another host ---


def test_public_key_of_another_host_is_refused(tmp_path: Path) -> None:
    pki, ca_serial = _make_pki(key_store=InMemoryKeyStore())
    public_key_pem = _keygen(directory=tmp_path, name="host1")
    first = pki.issue_certificate(
        request=_host_request(name="host1", ip="10.0.0.1/24", public_key=public_key_pem),
        ca_serial_number=ca_serial,
    )

    with pytest.raises(PublicKeyInUseError, match="'host1'") as excinfo:
        pki.issue_certificate(
            request=_host_request(name="host2", ip="10.0.0.2/24", public_key=public_key_pem),
            ca_serial_number=ca_serial,
        )
    assert excinfo.value.common_name == "host1"
    assert excinfo.value.serial_number == first.serial_number


def test_public_key_of_revoked_certificate_of_another_host_is_refused(tmp_path: Path) -> None:
    pki, ca_serial = _make_pki(key_store=InMemoryKeyStore())
    public_key_pem = _keygen(directory=tmp_path, name="host1")
    first = pki.issue_certificate(
        request=_host_request(name="host1", ip="10.0.0.1/24", public_key=public_key_pem),
        ca_serial_number=ca_serial,
    )
    pki.revoke_certificate(serial_number=first.serial_number)

    with pytest.raises(PublicKeyInUseError, match="'host1'"):
        pki.issue_certificate(
            request=_host_request(name="host2", ip="10.0.0.2/24", public_key=public_key_pem),
            ca_serial_number=ca_serial,
        )


def test_public_key_of_generated_key_pair_is_refused_for_another_host(tmp_path: Path) -> None:
    """A key pair the PKI generated is guarded too, though its certificate carries no stored public key."""
    pki, ca_serial = _make_pki(key_store=InMemoryKeyStore())
    generated = pki.issue_certificate(
        request=_host_request(name="host1", ip="10.0.0.1/24", public_key=None),
        ca_serial_number=ca_serial,
    )
    reused = pki.get_public_key(serial_number=generated.serial_number).to_pem()

    with pytest.raises(PublicKeyInUseError, match="'host1'"):
        pki.issue_certificate(
            request=_host_request(name="host2", ip="10.0.0.2/24", public_key=reused),
            ca_serial_number=ca_serial,
        )


def test_same_host_may_be_signed_again_with_its_key(tmp_path: Path) -> None:
    pki, ca_serial = _make_pki(key_store=InMemoryKeyStore())
    public_key_pem = _keygen(directory=tmp_path, name="host1")
    first = pki.issue_certificate(
        request=_host_request(name="host1", ip="10.0.0.1/24", public_key=public_key_pem),
        ca_serial_number=ca_serial,
    )
    second = pki.issue_certificate(
        request=_host_request(name="host1", ip="10.0.0.1/24", public_key=public_key_pem),
        ca_serial_number=ca_serial,
    )
    assert second.serial_number != first.serial_number


# --- CA key from outside the key store ---


def test_ca_key_path_signs_without_key_store(tmp_path: Path) -> None:
    holder = InMemoryKeyStore()
    pki, ca_serial = _make_pki(key_store=holder)
    ca_key_bytes = holder.get_key(serial_number=ca_serial)
    assert ca_key_bytes is not None
    (tmp_path / "ca.key").write_bytes(ca_key_bytes)

    empty_key_store = InMemoryKeyStore()
    store = InMemoryCertificateStore[NebulaCertificateRequest, NebulaCertData]()
    ca = pki.get_certificate(serial_number=ca_serial)
    assert ca is not None
    store.save_certificate(cert=ca)
    signer = NebulaPki(
        pki_state=pki.export_state(),
        key_store=empty_key_store,
        certificate_store=store,
        ca_key_path=tmp_path / "ca.key",
    )

    for index in range(2):
        signer.issue_certificate(
            request=_host_request(
                name=f"host{index}",
                ip=f"10.0.0.{index + 1}/24",
                public_key=_keygen(directory=tmp_path, name=f"host{index}"),
            ),
            ca_serial_number=ca_serial,
        )
    assert empty_key_store.get_key(serial_number=ca_serial) is None


def test_unreadable_ca_key_path_fails(tmp_path: Path) -> None:
    pki, ca_serial = _make_pki(key_store=InMemoryKeyStore())
    store = InMemoryCertificateStore[NebulaCertificateRequest, NebulaCertData]()
    ca = pki.get_certificate(serial_number=ca_serial)
    assert ca is not None
    store.save_certificate(cert=ca)
    signer = NebulaPki(
        pki_state=pki.export_state(),
        certificate_store=store,
        ca_key_path=tmp_path / "missing.key",
    )
    with pytest.raises(PkiError, match="Cannot read the CA key"):
        signer.issue_certificate(
            request=_host_request(name="host1", ip="10.0.0.1/24", public_key=_keygen(directory=tmp_path, name="h")),
            ca_serial_number=ca_serial,
        )


# --- renewal ---


def test_renew_resigns_the_same_public_key_without_the_host_key(tmp_path: Path) -> None:
    key_store = InMemoryKeyStore()
    pki, ca_serial = _make_pki(key_store=key_store)
    public_key_pem = _keygen(directory=tmp_path, name="host1")
    original = pki.issue_certificate(
        request=_host_request(name="host1", ip="10.0.0.1/24", public_key=public_key_pem),
        ca_serial_number=ca_serial,
    )
    (tmp_path / "host1.key").unlink()

    renewed = pki.renew_certificate(serial_number=original.serial_number, duration=timedelta(days=30))

    assert renewed.serial_number != original.serial_number
    assert renewed.ca_serial_number == ca_serial
    assert pki.get_public_key(serial_number=renewed.serial_number) == NebulaPublicKey.from_pem(pem=public_key_pem)
    assert renewed.backend_data.parsed.name == "host1"
    assert renewed.backend_data.parsed.networks == ["10.0.0.1/24"]
    assert sorted(renewed.backend_data.parsed.groups) == ["servers", "web"]
    assert renewed.request.duration == timedelta(days=30)
    assert key_store.get_key(serial_number=renewed.serial_number) is None


def test_renew_certificate_issued_with_generated_key(tmp_path: Path) -> None:
    """A certificate whose key pair the PKI generated renews from the key in the certificate."""
    key_store = InMemoryKeyStore()
    pki, ca_serial = _make_pki(key_store=key_store)
    original = pki.issue_certificate(
        request=_host_request(name="host1", ip="10.0.0.1/24", public_key=None),
        ca_serial_number=ca_serial,
    )

    renewed = pki.renew_certificate(serial_number=original.serial_number)

    assert pki.get_public_key(serial_number=renewed.serial_number) == pki.get_public_key(
        serial_number=original.serial_number,
    )
    assert renewed.request.duration == original.request.duration
    assert key_store.get_key(serial_number=renewed.serial_number) is None


def test_renew_refuses_a_ca_certificate() -> None:
    pki, ca_serial = _make_pki(key_store=InMemoryKeyStore())
    with pytest.raises(PkiError, match="Only a host certificate"):
        pki.renew_certificate(serial_number=ca_serial)
