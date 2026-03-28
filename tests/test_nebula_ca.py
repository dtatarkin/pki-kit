"""Tests for NebulaPki."""

import shutil
from datetime import UTC, datetime, timedelta

import pytest

from pki import (
    CertificateConflictError,
    CertificateNotFoundError,
    CertificateValidityExceedsCAError,
    PkiError,
    UnsupportedAlgorithmError,
    generate_serial_number,
)
from pki.backends.nebula.pki import NebulaCertData, NebulaCertificateRequest, NebulaPki
from pki.certificate_stores import InMemoryCertificateStore
from pki.key_stores import InMemoryKeyStore
from pki.models import Subject
from pki.types import (
    CertificateStatus,
    KeyAlgorithm,
    SerialNumber,
)

_NEBULA_CERT = shutil.which("nebula-cert")
pytestmark = pytest.mark.skipif(condition=_NEBULA_CERT is None, reason="nebula-cert not found on PATH")

_CA_DURATION = timedelta(days=3650)
_CERT_DURATION = timedelta(days=365)


def _make_pki(
    *,
    key_store: InMemoryKeyStore | None = None,
    certificate_store: InMemoryCertificateStore[NebulaCertificateRequest, NebulaCertData] | None = None,
) -> NebulaPki:
    return NebulaPki(
        key_store=key_store or InMemoryKeyStore(),
        certificate_store=certificate_store or InMemoryCertificateStore[NebulaCertificateRequest, NebulaCertData](),
    )


def _create_ca(
    *,
    pki: NebulaPki | None = None,
    key_algorithm: KeyAlgorithm = KeyAlgorithm.ED25519,
    serial_number: SerialNumber | None = None,
) -> tuple[NebulaPki, SerialNumber]:
    if pki is None:
        pki = _make_pki()
    ca_cert = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="Test Nebula CA"),
            duration=_CA_DURATION,
            key_algorithm=key_algorithm,
            is_ca=True,
        ),
        serial_number=serial_number,
    )
    return pki, ca_cert.serial_number


# --- CA creation ---


@pytest.mark.parametrize("key_algorithm", [KeyAlgorithm.ED25519, KeyAlgorithm.EC_P256])
def test_create_ca(key_algorithm: KeyAlgorithm) -> None:
    pki, ca_serial = _create_ca(key_algorithm=key_algorithm)
    ca_cert = pki.get_certificate(serial_number=ca_serial)
    assert ca_cert is not None
    assert ca_cert.request.subject.common_name == "Test Nebula CA"
    assert ca_cert.request.key_algorithm == key_algorithm

    assert ca_cert.backend_data.certificate_pem


def test_create_ca_with_groups() -> None:
    pki = _make_pki()
    ca_cert = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="CA with groups"),
            duration=_CA_DURATION,
            is_ca=True,
            key_algorithm=KeyAlgorithm.ED25519,
            groups=["servers", "web"],
        ),
    )
    assert ca_cert.request.groups == ["servers", "web"]


# --- Parsed certificate metadata ---


@pytest.mark.parametrize(
    ("key_algorithm", "expected_curve"),
    [(KeyAlgorithm.ED25519, "CURVE25519"), (KeyAlgorithm.EC_P256, "P256")],
)
def test_ca_parsed_metadata(key_algorithm: KeyAlgorithm, expected_curve: str) -> None:
    pki, ca_serial = _create_ca(key_algorithm=key_algorithm)
    ca_cert = pki.get_certificate(serial_number=ca_serial)
    assert ca_cert is not None
    parsed = ca_cert.backend_data.parsed

    assert parsed.name == "Test Nebula CA"
    assert parsed.is_ca is True
    assert parsed.curve == expected_curve
    assert parsed.fingerprint
    assert parsed.not_before <= parsed.not_after


def test_host_parsed_metadata() -> None:
    pki, ca_serial = _create_ca()
    cert_info = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="meta-host"),
            duration=_CERT_DURATION,
            ip="10.0.0.42/24",
            key_algorithm=KeyAlgorithm.ED25519,
            groups=["web"],
        ),
        ca_serial_number=ca_serial,
    )
    parsed = cert_info.backend_data.parsed

    assert parsed.name == "meta-host"
    assert parsed.is_ca is False
    assert parsed.curve == "CURVE25519"
    assert parsed.fingerprint
    assert parsed.not_before <= parsed.not_after
    assert "web" in parsed.groups

    # not_before/not_after on CertificateInfo delegate to parsed
    assert cert_info.not_before == parsed.not_before
    assert cert_info.not_after == parsed.not_after


# --- Host certificate issuance ---


def test_issue_host_certificate() -> None:
    pki, ca_serial = _create_ca()
    cert_info = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="host1"),
            duration=_CERT_DURATION,
            ip="10.0.0.1/24",
            key_algorithm=KeyAlgorithm.ED25519,
        ),
        ca_serial_number=ca_serial,
    )

    assert cert_info.backend_data.certificate_pem
    assert cert_info.ca_serial_number == ca_serial
    assert cert_info.request.subject.common_name == "host1"
    assert cert_info.status == CertificateStatus.ISSUED
    assert isinstance(cert_info.issue_date, datetime)


def test_issue_host_certificate_with_groups() -> None:
    pki, ca_serial = _create_ca()
    cert_info = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="host2"),
            duration=_CERT_DURATION,
            ip="10.0.0.2/24",
            key_algorithm=KeyAlgorithm.ED25519,
            groups=["servers", "web"],
        ),
        ca_serial_number=ca_serial,
    )
    assert cert_info.request.groups == ["servers", "web"]


def test_issue_host_certificate_with_subnets() -> None:
    pki, ca_serial = _create_ca()
    cert_info = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="host3"),
            duration=_CERT_DURATION,
            ip="10.0.0.3/24",
            key_algorithm=KeyAlgorithm.ED25519,
            subnets=["192.168.1.0/24"],
        ),
        ca_serial_number=ca_serial,
    )
    assert cert_info.request.subnets == ["192.168.1.0/24"]


def test_issue_host_certificate_p256() -> None:
    pki, ca_serial = _create_ca(key_algorithm=KeyAlgorithm.EC_P256)
    cert_info = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="host-p256"),
            duration=_CERT_DURATION,
            ip="10.0.0.10/24",
            key_algorithm=KeyAlgorithm.EC_P256,
        ),
        ca_serial_number=ca_serial,
    )

    assert cert_info.backend_data.certificate_pem


# --- Certificate lookup ---


def test_get_certificate() -> None:
    pki, ca_serial = _create_ca()
    cert_info = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="lookup"),
            duration=_CERT_DURATION,
            ip="10.0.0.5/24",
            key_algorithm=KeyAlgorithm.ED25519,
        ),
        ca_serial_number=ca_serial,
    )
    found = pki.get_certificate(serial_number=cert_info.serial_number)
    assert found is not None
    assert found.serial_number == cert_info.serial_number


def test_get_certificate_not_found() -> None:
    pki, _ca_serial = _create_ca()
    assert pki.get_certificate(serial_number=SerialNumber(9999)) is None


def test_list_certificates() -> None:
    pki, ca_serial = _create_ca()
    for i in range(3):
        pki.issue_certificate(
            request=NebulaCertificateRequest(
                subject=Subject(common_name=f"host-{i}"),
                duration=_CERT_DURATION,
                ip=f"10.0.0.{i + 1}/24",
                key_algorithm=KeyAlgorithm.ED25519,
            ),
            ca_serial_number=ca_serial,
        )
    certs = pki.list_certificates()
    assert len(certs) == 4  # 3 hosts + 1 CA


def test_list_certificates_is_ca() -> None:
    pki, ca_serial = _create_ca()
    for i in range(2):
        pki.issue_certificate(
            request=NebulaCertificateRequest(
                subject=Subject(common_name=f"host-{i}"),
                duration=_CERT_DURATION,
                ip=f"10.0.0.{i + 1}/24",
                key_algorithm=KeyAlgorithm.ED25519,
            ),
            ca_serial_number=ca_serial,
        )

    ca_certs = pki.list_certificates(is_ca=True)
    assert len(ca_certs) == 1
    assert ca_certs[0].request.is_ca is True

    non_ca_certs = pki.list_certificates(is_ca=False)
    assert len(non_ca_certs) == 2
    assert all(not c.request.is_ca for c in non_ca_certs)


def test_get_ca_certificate() -> None:
    pki, ca_serial = _create_ca()
    pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="host"),
            duration=_CERT_DURATION,
            ip="10.0.0.1/24",
            key_algorithm=KeyAlgorithm.ED25519,
        ),
        ca_serial_number=ca_serial,
    )

    ca = pki.get_ca_certificate()
    assert ca is not None
    assert ca.serial_number == ca_serial
    assert ca.request.is_ca is True


def test_get_ca_certificate_empty() -> None:
    pki = _make_pki()
    assert pki.get_ca_certificate() is None


def test_get_ca_certificate_skips_revoked() -> None:
    from pki.types import RevocationReason

    pki, ca_serial = _create_ca()
    pki.revoke_certificate(ca_serial, reason=RevocationReason.SUPERSEDED)

    assert pki.get_ca_certificate() is None


# --- Revocation ---


def test_revoke_certificate() -> None:
    from pki.types import RevocationReason

    pki, ca_serial = _create_ca()
    cert_info = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="to-revoke"),
            duration=_CERT_DURATION,
            ip="10.0.0.99/24",
            key_algorithm=KeyAlgorithm.ED25519,
        ),
        ca_serial_number=ca_serial,
    )

    revoked = pki.revoke_certificate(serial_number=cert_info.serial_number, reason=RevocationReason.KEY_COMPROMISE)
    assert revoked.status == CertificateStatus.REVOKED

    revoked_list = pki.list_certificates(status=CertificateStatus.REVOKED)
    assert len(revoked_list) == 1


# --- Idempotency and conflict ---


def test_issue_certificate_idempotent() -> None:
    pki, ca_serial = _create_ca()
    explicit_serial = generate_serial_number()
    request = NebulaCertificateRequest(
        subject=Subject(common_name="idempotent"),
        duration=_CERT_DURATION,
        ip="10.0.0.50/24",
        key_algorithm=KeyAlgorithm.ED25519,
    )
    cert1 = pki.issue_certificate(request=request, serial_number=explicit_serial, ca_serial_number=ca_serial)
    cert2 = pki.issue_certificate(request=request, serial_number=explicit_serial, ca_serial_number=ca_serial)

    assert cert1.serial_number == cert2.serial_number

    assert cert1.backend_data.certificate_pem == cert2.backend_data.certificate_pem


def test_issue_certificate_conflict() -> None:
    pki, ca_serial = _create_ca()
    explicit_serial = generate_serial_number()
    request1 = NebulaCertificateRequest(
        subject=Subject(common_name="first"),
        duration=_CERT_DURATION,
        ip="10.0.0.60/24",
        key_algorithm=KeyAlgorithm.ED25519,
    )
    pki.issue_certificate(request=request1, serial_number=explicit_serial, ca_serial_number=ca_serial)

    request2 = NebulaCertificateRequest(
        subject=Subject(common_name="second"),
        duration=_CERT_DURATION,
        ip="10.0.0.61/24",
        key_algorithm=KeyAlgorithm.ED25519,
    )
    with pytest.raises(CertificateConflictError):
        pki.issue_certificate(request=request2, serial_number=explicit_serial, ca_serial_number=ca_serial)


# --- State persistence ---


def test_export_load_roundtrip() -> None:
    key_store = InMemoryKeyStore()
    cert_store = InMemoryCertificateStore[NebulaCertificateRequest, NebulaCertData]("test")
    pki, ca_serial = _create_ca(pki=NebulaPki(key_store=key_store, certificate_store=cert_store))

    cert1 = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="before-export"),
            duration=_CERT_DURATION,
            ip="10.0.0.70/24",
            key_algorithm=KeyAlgorithm.ED25519,
        ),
        ca_serial_number=ca_serial,
    )

    state = pki.export_state()

    pki2 = NebulaPki(
        pki_state=state,
        key_store=key_store,
        certificate_store=cert_store,
    )

    assert len(pki2.list_certificates()) == 2
    assert pki2.get_certificate(serial_number=cert1.serial_number) is not None


# --- Export helpers ---


def test_export_certificate_pem() -> None:
    pki, ca_serial = _create_ca()
    cert_bytes = pki.export_certificate_pem(serial_number=ca_serial)
    assert b"NEBULA" in cert_bytes or b"nebula" in cert_bytes or len(cert_bytes) > 0


def test_export_private_key_pem() -> None:
    pki, ca_serial = _create_ca()
    key_bytes = pki.export_private_key_pem(serial_number=ca_serial)
    assert len(key_bytes) > 0


def test_export_nonexistent_serial() -> None:
    pki, _ca_serial = _create_ca()
    with pytest.raises(CertificateNotFoundError):
        pki.export_certificate_pem(serial_number=SerialNumber(9999))
    with pytest.raises(CertificateNotFoundError):
        pki.export_private_key_pem(serial_number=SerialNumber(9999))


# --- Error cases ---


def test_unsupported_algorithm() -> None:
    pki = _make_pki()
    with pytest.raises(UnsupportedAlgorithmError):
        pki.issue_certificate(
            request=NebulaCertificateRequest(
                subject=Subject(common_name="bad-algo"),
                duration=_CERT_DURATION,
                key_algorithm=KeyAlgorithm.RSA_2048,
                is_ca=True,
            ),
        )


def test_issue_certificate_exceeds_ca_validity() -> None:
    pki, ca_serial = _create_ca()
    with pytest.raises(CertificateValidityExceedsCAError):
        pki.issue_certificate(
            request=NebulaCertificateRequest(
                subject=Subject(common_name="too-long"),
                duration=_CA_DURATION + timedelta(days=1),
                ip="10.0.0.99/24",
                key_algorithm=KeyAlgorithm.ED25519,
            ),
            ca_serial_number=ca_serial,
        )


def test_host_cert_requires_ca_serial() -> None:
    pki = _make_pki()
    with pytest.raises(PkiError, match="Non-CA certificates require ca_serial_number"):
        pki.issue_certificate(
            request=NebulaCertificateRequest(
                subject=Subject(common_name="no-ca"),
                duration=_CERT_DURATION,
                ip="10.0.0.1/24",
                key_algorithm=KeyAlgorithm.ED25519,
            ),
        )


# --- get_or_issue_certificate tests ---


def test_get_or_issue_returns_existing_cert() -> None:
    pki, ca_serial = _create_ca()
    request = NebulaCertificateRequest(
        subject=Subject(common_name="host-1"),
        duration=_CERT_DURATION,
        ip="10.0.0.1/24",
        key_algorithm=KeyAlgorithm.ED25519,
    )
    issued = pki.issue_certificate(request=request, ca_serial_number=ca_serial)

    # Same identity but different duration
    new_request = NebulaCertificateRequest(
        subject=Subject(common_name="host-1"),
        duration=timedelta(days=730),
        ip="10.0.0.1/24",
        key_algorithm=KeyAlgorithm.ED25519,
    )
    result = pki.get_or_issue_certificate(
        new_request,
        not_expired_at=datetime.now(tz=UTC) + timedelta(days=10),
        ca_serial_number=ca_serial,
    )
    assert result.serial_number == issued.serial_number
    # CA + 1 cert
    assert len(pki.list_certificates()) == 2


def test_get_or_issue_issues_when_no_match() -> None:
    pki, ca_serial = _create_ca()

    request = NebulaCertificateRequest(
        subject=Subject(common_name="new-host"),
        duration=_CERT_DURATION,
        ip="10.0.0.50/24",
        key_algorithm=KeyAlgorithm.ED25519,
    )
    result = pki.get_or_issue_certificate(
        request,
        not_expired_at=datetime.now(tz=UTC) + timedelta(days=10),
        ca_serial_number=ca_serial,
    )
    assert result.request.subject.common_name == "new-host"
    assert result.status == CertificateStatus.ISSUED
    # CA + new cert
    assert len(pki.list_certificates()) == 2


def test_get_or_issue_ignores_revoked() -> None:
    from pki.types import RevocationReason

    pki, ca_serial = _create_ca()
    request = NebulaCertificateRequest(
        subject=Subject(common_name="revoked-host"),
        duration=_CERT_DURATION,
        ip="10.0.0.80/24",
        key_algorithm=KeyAlgorithm.ED25519,
    )
    issued = pki.issue_certificate(request=request, ca_serial_number=ca_serial)
    pki.revoke_certificate(serial_number=issued.serial_number, reason=RevocationReason.KEY_COMPROMISE)

    new_request = NebulaCertificateRequest(
        subject=Subject(common_name="revoked-host"),
        duration=_CERT_DURATION,
        ip="10.0.0.80/24",
        key_algorithm=KeyAlgorithm.ED25519,
    )
    result = pki.get_or_issue_certificate(
        new_request,
        not_expired_at=datetime.now(tz=UTC) + timedelta(days=10),
        ca_serial_number=ca_serial,
    )
    assert result.serial_number != issued.serial_number
    assert result.status == CertificateStatus.ISSUED


def test_get_or_issue_no_match_different_identity() -> None:
    pki, ca_serial = _create_ca()
    pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="host-a"),
            duration=_CERT_DURATION,
            ip="10.0.0.1/24",
            groups=["web"],
            key_algorithm=KeyAlgorithm.ED25519,
        ),
        ca_serial_number=ca_serial,
    )

    # Different groups — should not match
    result = pki.get_or_issue_certificate(
        NebulaCertificateRequest(
            subject=Subject(common_name="host-a"),
            duration=_CERT_DURATION,
            ip="10.0.0.1/24",
            groups=["db"],
            key_algorithm=KeyAlgorithm.ED25519,
        ),
        not_expired_at=datetime.now(tz=UTC) + timedelta(days=10),
        ca_serial_number=ca_serial,
    )
    assert result.request.groups == ["db"]
    # CA + original + new
    assert len(pki.list_certificates()) == 3

    # Different IP — should not match
    result2 = pki.get_or_issue_certificate(
        NebulaCertificateRequest(
            subject=Subject(common_name="host-a"),
            duration=_CERT_DURATION,
            ip="10.0.0.2/24",
            groups=["web"],
            key_algorithm=KeyAlgorithm.ED25519,
        ),
        not_expired_at=datetime.now(tz=UTC) + timedelta(days=10),
        ca_serial_number=ca_serial,
    )
    assert result2.request.ip == "10.0.0.2/24"
    # CA + original + groups-db + ip-2
    assert len(pki.list_certificates()) == 4
