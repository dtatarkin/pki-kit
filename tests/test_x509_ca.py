"""Tests for X509Pki."""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from pydantic import ValidationError

from pki import (
    CertificateConflictError,
    CertificateNotFoundError,
    CertificateValidityExceedsCAError,
    X509Pki,
    generate_serial_number,
)
from pki.backends.x509.crypto_provider import SoftwareCryptoProvider
from pki.backends.x509.pki import X509CertData, X509CertificateRequest
from pki.certificate_stores import CertificateStore, InMemoryCertificateStore
from pki.models import Subject
from pki.types import (
    CertificateStatus,
    ExtendedKeyUsage,
    KeyAlgorithm,
    KeyUsage,
    RevocationReason,
    SerialNumber,
)

_NOW = datetime.now(tz=UTC)
_CA_NOT_BEFORE = _NOW
_CA_NOT_AFTER = _NOW + timedelta(days=3650)
_CERT_NOT_BEFORE = _NOW
_CERT_NOT_AFTER = _NOW + timedelta(days=365)

_CA_KEY_USAGES = [KeyUsage.CERT_SIGN, KeyUsage.CRL_SIGN, KeyUsage.DIGITAL_SIGNATURE]


def _create_ca(
    ca_subject: Subject,
    crypto_provider: SoftwareCryptoProvider,
    key_algorithm: KeyAlgorithm = KeyAlgorithm.EC_P256,
    *,
    serial_number: SerialNumber | None = None,
    certificate_store: CertificateStore[X509CertificateRequest, X509CertData] | None = None,
) -> tuple[X509Pki, SerialNumber]:
    """Helper to create a PKI and issue a self-signed CA certificate."""
    pki = X509Pki(crypto_provider=crypto_provider, certificate_store=certificate_store)
    ca_cert = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=ca_subject,
            not_before=_CA_NOT_BEFORE,
            not_after=_CA_NOT_AFTER,
            key_algorithm=key_algorithm,
            is_ca=True,
            key_usages=_CA_KEY_USAGES,
        ),
        serial_number=serial_number,
    )
    return pki, ca_cert.serial_number


def test_create_ca(ca_subject: Subject, key_algorithm: KeyAlgorithm, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider, key_algorithm)
    ca_cert = pki.get_certificate(serial_number=ca_serial)
    assert ca_cert is not None
    assert ca_cert.request.subject.common_name == "Test CA"
    assert ca_cert.request.key_algorithm == key_algorithm
    assert ca_cert.request.not_before < ca_cert.request.not_after


def test_issue_certificate(
    ca_subject: Subject, key_algorithm: KeyAlgorithm, crypto_provider: SoftwareCryptoProvider
) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider, key_algorithm)
    request = X509CertificateRequest(
        subject=Subject(common_name="server.example.com"),
        not_before=_CERT_NOT_BEFORE,
        not_after=_CERT_NOT_AFTER,
        key_algorithm=key_algorithm,
    )
    cert_info = pki.issue_certificate(request=request, ca_serial_number=ca_serial)

    assert cert_info.backend_data.certificate_pem
    assert cert_info.ca_serial_number == ca_serial
    assert cert_info.request.subject.common_name == "server.example.com"
    assert cert_info.status == CertificateStatus.ISSUED
    assert isinstance(cert_info.issue_date, datetime)

    # Parse the PEM to verify it's a valid cert
    cert = x509.load_pem_x509_certificate(data=cert_info.backend_data.certificate_pem.encode())
    assert cert.serial_number == cert_info.serial_number


def test_issue_certificate_with_email(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)

    # Subject email only
    cert_info = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="user", email="user@example.com"),
            not_before=_CERT_NOT_BEFORE,
            not_after=_CERT_NOT_AFTER,
        ),
        ca_serial_number=ca_serial,
    )

    cert = x509.load_pem_x509_certificate(data=cert_info.backend_data.certificate_pem.encode())
    email_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.EMAIL_ADDRESS)
    assert len(email_attrs) == 1
    assert email_attrs[0].value == "user@example.com"

    # SAN email only
    cert_info = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="user2"),
            not_before=_CERT_NOT_BEFORE,
            not_after=_CERT_NOT_AFTER,
            san_email_addresses=["san@example.com"],
        ),
        ca_serial_number=ca_serial,
    )

    cert = x509.load_pem_x509_certificate(data=cert_info.backend_data.certificate_pem.encode())
    san = cert.extensions.get_extension_for_class(extclass=x509.SubjectAlternativeName)
    rfc822_names = san.value.get_values_for_type(type=x509.RFC822Name)
    assert "san@example.com" in rfc822_names

    # Both subject email and SAN email
    cert_info = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="user3", email="subject@example.com"),
            not_before=_CERT_NOT_BEFORE,
            not_after=_CERT_NOT_AFTER,
            san_email_addresses=["san1@example.com", "san2@example.com"],
        ),
        ca_serial_number=ca_serial,
    )

    cert = x509.load_pem_x509_certificate(data=cert_info.backend_data.certificate_pem.encode())
    email_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.EMAIL_ADDRESS)
    assert email_attrs[0].value == "subject@example.com"
    san = cert.extensions.get_extension_for_class(extclass=x509.SubjectAlternativeName)
    rfc822_names = san.value.get_values_for_type(type=x509.RFC822Name)
    assert "san1@example.com" in rfc822_names
    assert "san2@example.com" in rfc822_names


def test_issue_certificate_with_san(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    request = X509CertificateRequest(
        subject=Subject(common_name="server.example.com"),
        not_before=_CERT_NOT_BEFORE,
        not_after=_CERT_NOT_AFTER,
        san_dns_names=["server.example.com", "*.example.com"],
        san_ip_addresses=["192.168.1.1"],
    )
    cert_info = pki.issue_certificate(request=request, ca_serial_number=ca_serial)

    cert = x509.load_pem_x509_certificate(data=cert_info.backend_data.certificate_pem.encode())

    san = cert.extensions.get_extension_for_class(extclass=x509.SubjectAlternativeName)
    dns_names = san.value.get_values_for_type(type=x509.DNSName)
    assert "server.example.com" in dns_names
    assert "*.example.com" in dns_names

    ips = san.value.get_values_for_type(type=x509.IPAddress)
    assert len(ips) == 1


def test_issue_certificate_key_usages(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    request = X509CertificateRequest(
        subject=Subject(common_name="server.example.com"),
        not_before=_CERT_NOT_BEFORE,
        not_after=_CERT_NOT_AFTER,
        key_usages=[KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT],
        extended_key_usages=[ExtendedKeyUsage.SERVER_AUTH, ExtendedKeyUsage.CLIENT_AUTH],
    )
    cert_info = pki.issue_certificate(request=request, ca_serial_number=ca_serial)

    cert = x509.load_pem_x509_certificate(data=cert_info.backend_data.certificate_pem.encode())

    ku = cert.extensions.get_extension_for_class(extclass=x509.KeyUsage)
    assert ku.value.digital_signature is True
    assert ku.value.key_encipherment is True
    assert ku.value.key_cert_sign is False

    eku = cert.extensions.get_extension_for_class(extclass=x509.ExtendedKeyUsage)
    assert len(list(eku.value)) == 2


def test_get_certificate(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    cert_info = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="test"), not_before=_CERT_NOT_BEFORE, not_after=_CERT_NOT_AFTER
        ),
        ca_serial_number=ca_serial,
    )

    found = pki.get_certificate(serial_number=cert_info.serial_number)
    assert found is not None
    assert found.serial_number == cert_info.serial_number


def test_get_certificate_not_found(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, _ca_serial = _create_ca(ca_subject, crypto_provider)
    assert pki.get_certificate(serial_number=SerialNumber(9999)) is None


def test_list_certificates(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    for i in range(3):
        pki.issue_certificate(
            request=X509CertificateRequest(
                subject=Subject(common_name=f"cert-{i}"), not_before=_CERT_NOT_BEFORE, not_after=_CERT_NOT_AFTER
            ),
            ca_serial_number=ca_serial,
        )
    certs = pki.list_certificates()
    assert len(certs) == 4  # 3 issued + 1 CA cert


def test_list_certificates_by_common_name(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    for i in range(3):
        pki.issue_certificate(
            request=X509CertificateRequest(
                subject=Subject(common_name=f"host-{i}"), not_before=_CERT_NOT_BEFORE, not_after=_CERT_NOT_AFTER
            ),
            ca_serial_number=ca_serial,
        )
    # Issue a second cert with the same CN as host-0
    pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="host-0"),
            not_before=_CERT_NOT_BEFORE,
            not_after=_NOW + timedelta(days=730),
        ),
        ca_serial_number=ca_serial,
    )

    certs = pki.list_certificates(common_name="host-0")
    assert len(certs) == 2
    assert all(c.request.subject.common_name == "host-0" for c in certs)

    certs = pki.list_certificates(common_name="host-1")
    assert len(certs) == 1

    certs = pki.list_certificates(common_name="nonexistent")
    assert len(certs) == 0

    # Combined filters
    certs = pki.list_certificates(common_name="host-0", status=CertificateStatus.ISSUED)
    assert len(certs) == 2


def test_list_certificates_is_ca(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    for i in range(2):
        pki.issue_certificate(
            request=X509CertificateRequest(
                subject=Subject(common_name=f"host-{i}"), not_before=_CERT_NOT_BEFORE, not_after=_CERT_NOT_AFTER
            ),
            ca_serial_number=ca_serial,
        )

    ca_certs = pki.list_certificates(is_ca=True)
    assert len(ca_certs) == 1
    assert ca_certs[0].request.is_ca is True

    non_ca_certs = pki.list_certificates(is_ca=False)
    assert len(non_ca_certs) == 2
    assert all(not c.request.is_ca for c in non_ca_certs)


def test_get_ca_certificate(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="host"), not_before=_CERT_NOT_BEFORE, not_after=_CERT_NOT_AFTER
        ),
        ca_serial_number=ca_serial,
    )

    ca = pki.get_ca_certificate()
    assert ca is not None
    assert ca.serial_number == ca_serial
    assert ca.request.is_ca is True


def test_get_ca_certificate_empty(crypto_provider: SoftwareCryptoProvider) -> None:
    pki = X509Pki(crypto_provider=crypto_provider)
    assert pki.get_ca_certificate() is None


def test_get_ca_certificate_returns_most_recent(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki = X509Pki(crypto_provider=crypto_provider)
    ca1 = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=ca_subject,
            not_before=_CA_NOT_BEFORE,
            not_after=_CA_NOT_AFTER,
            is_ca=True,
            key_usages=_CA_KEY_USAGES,
        ),
    )
    ca2 = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="Second CA"),
            not_before=_CA_NOT_BEFORE,
            not_after=_CA_NOT_AFTER,
            is_ca=True,
            key_usages=_CA_KEY_USAGES,
        ),
    )

    result = pki.get_ca_certificate()
    assert result is not None
    assert result.issue_date >= ca1.issue_date
    assert result.serial_number == ca2.serial_number


def test_get_ca_certificate_skips_revoked(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki = X509Pki(crypto_provider=crypto_provider)
    ca = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=ca_subject,
            not_before=_CA_NOT_BEFORE,
            not_after=_CA_NOT_AFTER,
            is_ca=True,
            key_usages=_CA_KEY_USAGES,
        ),
    )
    pki.revoke_certificate(ca.serial_number)

    assert pki.get_ca_certificate() is None


def test_list_certificates_not_expired_at(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    # Issue a cert that expires in 30 days
    pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="short-lived"),
            not_before=_NOW,
            not_after=_NOW + timedelta(days=30),
        ),
        ca_serial_number=ca_serial,
    )
    # Issue a cert that expires in 2 years
    pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="long-lived"),
            not_before=_NOW,
            not_after=_NOW + timedelta(days=730),
        ),
        ca_serial_number=ca_serial,
    )

    # Filter: not expired at 60 days from now — should exclude the 30-day cert
    check_time = _NOW + timedelta(days=60)
    certs = pki.list_certificates(not_expired_at=check_time)
    names = [c.request.subject.common_name for c in certs]
    assert "long-lived" in names
    assert "short-lived" not in names

    # Filter: not expired at 10 days from now — both should be included (plus CA)
    certs = pki.list_certificates(not_expired_at=_NOW + timedelta(days=10))
    assert len(certs) == 3  # CA + short-lived + long-lived


def test_revoke_certificate(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    cert_info = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="to-revoke"), not_before=_CERT_NOT_BEFORE, not_after=_CERT_NOT_AFTER
        ),
        ca_serial_number=ca_serial,
    )

    revoked = pki.revoke_certificate(serial_number=cert_info.serial_number, reason=RevocationReason.KEY_COMPROMISE)

    assert revoked.status == CertificateStatus.REVOKED
    assert revoked.serial_number == cert_info.serial_number
    assert revoked.revocation_reason == RevocationReason.KEY_COMPROMISE

    revoked_list = pki.list_certificates(status=CertificateStatus.REVOKED)
    assert len(revoked_list) == 1
    assert revoked_list[0].serial_number == cert_info.serial_number


def test_revoke_certificate_not_found(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, _ca_serial = _create_ca(ca_subject, crypto_provider)
    with pytest.raises(CertificateNotFoundError):
        pki.revoke_certificate(serial_number=SerialNumber(9999))


def test_export_load_roundtrip(
    ca_subject: Subject, key_algorithm: KeyAlgorithm, crypto_provider: SoftwareCryptoProvider
) -> None:
    cert_store = InMemoryCertificateStore[X509CertificateRequest, X509CertData]("test")
    pki, ca_serial = _create_ca(ca_subject, crypto_provider, key_algorithm, certificate_store=cert_store)

    # Issue a cert before export
    cert1 = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="before-export"),
            not_before=_CERT_NOT_BEFORE,
            not_after=_CERT_NOT_AFTER,
            key_algorithm=key_algorithm,
        ),
        ca_serial_number=ca_serial,
    )

    state = pki.export_state()

    # Load into a new instance (same crypto provider and certificate store)
    pki2 = X509Pki(pki_state=state, crypto_provider=crypto_provider, certificate_store=cert_store)

    # Verify state was preserved (CA cert + 1 issued)
    assert len(pki2.list_certificates()) == 2
    assert pki2.get_certificate(serial_number=cert1.serial_number) is not None

    # Issue another cert from loaded PKI
    cert2 = pki2.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="after-load"),
            not_before=_CERT_NOT_BEFORE,
            not_after=_CERT_NOT_AFTER,
            key_algorithm=key_algorithm,
        ),
        ca_serial_number=ca_serial,
    )
    assert cert2.serial_number > cert1.serial_number

    # Verify the new cert parses

    parsed = x509.load_pem_x509_certificate(data=cert2.backend_data.certificate_pem.encode())
    assert parsed.serial_number == cert2.serial_number


def test_serial_number_unique(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    serials = []
    for _ in range(3):
        cert_info = pki.issue_certificate(
            request=X509CertificateRequest(
                subject=Subject(common_name="test"), not_before=_CERT_NOT_BEFORE, not_after=_CERT_NOT_AFTER
            ),
            ca_serial_number=ca_serial,
        )
        serials.append(cert_info.serial_number)
    assert len(set(serials)) == 3


# --- Export tests ---


def test_export_ca_certificate_pem(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    pem_bytes = pki.export_certificate_pem(serial_number=ca_serial)
    cert = x509.load_pem_x509_certificate(data=pem_bytes)
    assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "Test CA"


def test_export_ca_certificate_der(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    der_bytes = pki.export_certificate_der(serial_number=ca_serial)
    cert = x509.load_der_x509_certificate(data=der_bytes)
    assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "Test CA"


def test_export_ca_private_key_pem(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    pem_bytes = pki.export_private_key_pem(serial_number=ca_serial)
    key = serialization.load_pem_private_key(data=pem_bytes, password=None)
    assert key is not None


def test_export_ca_private_key_der(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    der_bytes = pki.export_private_key_der(serial_number=ca_serial)
    key = serialization.load_der_private_key(data=der_bytes, password=None)
    assert key is not None


def test_export_ca_private_key_encrypted(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    password = b"test-password"
    pem_bytes = pki.export_private_key_pem(serial_number=ca_serial, password=password)
    key = serialization.load_pem_private_key(data=pem_bytes, password=password)
    assert key is not None


def test_export_ca_pkcs12(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    p12_bytes = pki.export_pkcs12_bytes(serial_number=ca_serial, password=b"test")
    key, cert, _cas = pkcs12.load_key_and_certificates(data=p12_bytes, password=b"test")
    assert key is not None
    assert cert is not None
    assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "Test CA"


def test_export_issued_certificate_pem(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    cert_info = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="server"), not_before=_CERT_NOT_BEFORE, not_after=_CERT_NOT_AFTER
        ),
        ca_serial_number=ca_serial,
    )

    pem_bytes = pki.export_certificate_pem(serial_number=cert_info.serial_number)
    cert = x509.load_pem_x509_certificate(data=pem_bytes)
    assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "server"


def test_export_issued_certificate_der(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    cert_info = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="server"), not_before=_CERT_NOT_BEFORE, not_after=_CERT_NOT_AFTER
        ),
        ca_serial_number=ca_serial,
    )

    der_bytes = pki.export_certificate_der(serial_number=cert_info.serial_number)
    cert = x509.load_der_x509_certificate(data=der_bytes)
    assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "server"


def test_export_issued_private_key_pem(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    cert_info = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="server"), not_before=_CERT_NOT_BEFORE, not_after=_CERT_NOT_AFTER
        ),
        ca_serial_number=ca_serial,
    )

    pem_bytes = pki.export_private_key_pem(serial_number=cert_info.serial_number)
    key = serialization.load_pem_private_key(data=pem_bytes, password=None)
    assert key is not None


def test_export_issued_private_key_der(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    cert_info = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="server"), not_before=_CERT_NOT_BEFORE, not_after=_CERT_NOT_AFTER
        ),
        ca_serial_number=ca_serial,
    )

    der_bytes = pki.export_private_key_der(serial_number=cert_info.serial_number)
    key = serialization.load_der_private_key(data=der_bytes, password=None)
    assert key is not None


def test_export_issued_pkcs12_with_ca(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    cert_info = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="server"), not_before=_CERT_NOT_BEFORE, not_after=_CERT_NOT_AFTER
        ),
        ca_serial_number=ca_serial,
    )

    p12_bytes = pki.export_pkcs12_bytes(serial_number=cert_info.serial_number, password=b"test", include_ca=True)
    key, cert, cas = pkcs12.load_key_and_certificates(data=p12_bytes, password=b"test")
    assert key is not None
    assert cert is not None
    assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "server"
    assert cas is not None
    assert len(cas) == 1


def test_export_issued_pkcs12_without_ca(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    cert_info = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="server"), not_before=_CERT_NOT_BEFORE, not_after=_CERT_NOT_AFTER
        ),
        ca_serial_number=ca_serial,
    )

    p12_bytes = pki.export_pkcs12_bytes(serial_number=cert_info.serial_number, password=b"test", include_ca=False)
    key, cert, cas = pkcs12.load_key_and_certificates(data=p12_bytes, password=b"test")
    assert key is not None
    assert cert is not None
    assert cas is None or len(cas) == 0


def test_export_nonexistent_serial(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, _ca_serial = _create_ca(ca_subject, crypto_provider)
    with pytest.raises(CertificateNotFoundError):
        pki.export_certificate_pem(serial_number=SerialNumber(9999))
    with pytest.raises(CertificateNotFoundError):
        pki.export_private_key_pem(serial_number=SerialNumber(9999))
    with pytest.raises(CertificateNotFoundError):
        pki.export_pkcs12_bytes(serial_number=SerialNumber(9999))


def test_state_roundtrip_exports(
    ca_subject: Subject, key_algorithm: KeyAlgorithm, crypto_provider: SoftwareCryptoProvider
) -> None:
    cert_store = InMemoryCertificateStore[X509CertificateRequest, X509CertData]("test")
    pki, ca_serial = _create_ca(ca_subject, crypto_provider, key_algorithm, certificate_store=cert_store)
    cert_info = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="roundtrip"),
            not_before=_CERT_NOT_BEFORE,
            not_after=_CERT_NOT_AFTER,
            key_algorithm=key_algorithm,
        ),
        ca_serial_number=ca_serial,
    )

    state = pki.export_state()
    pki2 = X509Pki(pki_state=state, crypto_provider=crypto_provider, certificate_store=cert_store)

    # CA exports still work after load
    ca_cert_bytes = pki2.export_certificate_der(serial_number=ca_serial)
    cert = x509.load_der_x509_certificate(data=ca_cert_bytes)
    assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "Test CA"

    ca_key_bytes = pki2.export_private_key_pem(serial_number=ca_serial)
    assert serialization.load_pem_private_key(data=ca_key_bytes, password=None) is not None

    # Issued cert exports still work after load
    cert_bytes = pki2.export_certificate_pem(serial_number=cert_info.serial_number)
    assert x509.load_pem_x509_certificate(data=cert_bytes) is not None

    key_bytes = pki2.export_private_key_pem(serial_number=cert_info.serial_number)
    assert serialization.load_pem_private_key(data=key_bytes, password=None) is not None


# --- generate_serial_number tests ---


def test_generate_serial_number_returns_int() -> None:
    serial = generate_serial_number()
    assert isinstance(serial, int)


def test_generate_serial_number_unique() -> None:
    serials = {generate_serial_number() for _ in range(10)}
    assert len(serials) == 10


# --- Explicit serial number tests ---


def test_create_with_explicit_serial(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    explicit_serial = generate_serial_number()
    _pki, ca_serial = _create_ca(ca_subject, crypto_provider, serial_number=explicit_serial)
    assert ca_serial == explicit_serial


def test_issue_certificate_with_explicit_serial(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    explicit_serial = generate_serial_number()
    request = X509CertificateRequest(
        subject=Subject(common_name="explicit-serial"),
        not_before=_CERT_NOT_BEFORE,
        not_after=_CERT_NOT_AFTER,
    )
    cert_info = pki.issue_certificate(request=request, serial_number=explicit_serial, ca_serial_number=ca_serial)
    assert cert_info.serial_number == explicit_serial

    cert = x509.load_pem_x509_certificate(data=cert_info.backend_data.certificate_pem.encode())
    assert cert.serial_number == explicit_serial


def test_issue_certificate_idempotent(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    explicit_serial = generate_serial_number()
    request = X509CertificateRequest(
        subject=Subject(common_name="idempotent"),
        not_before=_CERT_NOT_BEFORE,
        not_after=_CERT_NOT_AFTER,
    )
    cert1 = pki.issue_certificate(request=request, serial_number=explicit_serial, ca_serial_number=ca_serial)
    cert2 = pki.issue_certificate(request=request, serial_number=explicit_serial, ca_serial_number=ca_serial)

    assert cert1.serial_number == cert2.serial_number
    assert cert1.backend_data.certificate_pem == cert2.backend_data.certificate_pem
    # Only one certificate should be stored (plus the CA cert)
    assert len(pki.list_certificates()) == 2


def test_issue_certificate_conflict(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    explicit_serial = generate_serial_number()
    request1 = X509CertificateRequest(
        subject=Subject(common_name="first"),
        not_before=_CERT_NOT_BEFORE,
        not_after=_CERT_NOT_AFTER,
    )
    pki.issue_certificate(request=request1, serial_number=explicit_serial, ca_serial_number=ca_serial)

    request2 = X509CertificateRequest(
        subject=Subject(common_name="second"),
        not_before=_CERT_NOT_BEFORE,
        not_after=_CERT_NOT_AFTER,
    )
    with pytest.raises(CertificateConflictError):
        pki.issue_certificate(request=request2, serial_number=explicit_serial, ca_serial_number=ca_serial)


# --- Date validation tests ---


def test_certificate_request_rejects_invalid_dates() -> None:
    with pytest.raises(ValidationError, match="not_after must be after not_before"):
        X509CertificateRequest(
            subject=Subject(common_name="test"),
            not_before=_NOW + timedelta(days=1),
            not_after=_NOW,
        )


def test_issue_certificate_exceeds_ca_validity(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    with pytest.raises(CertificateValidityExceedsCAError):
        pki.issue_certificate(
            request=X509CertificateRequest(
                subject=Subject(common_name="too-long"),
                not_before=_NOW,
                not_after=_CA_NOT_AFTER + timedelta(days=1),
            ),
            ca_serial_number=ca_serial,
        )


def test_issue_certificate_at_ca_boundary(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    """Certificate with not_after equal to CA not_after should be allowed."""
    # Use second-precision timestamps since X509 truncates microseconds
    now = _NOW.replace(microsecond=0)
    ca_not_after = now + timedelta(days=3650)
    pki = X509Pki(crypto_provider=crypto_provider)
    pki.issue_certificate(
        request=X509CertificateRequest(
            subject=ca_subject,
            not_before=now,
            not_after=ca_not_after,
            key_algorithm=KeyAlgorithm.EC_P256,
            is_ca=True,
            key_usages=_CA_KEY_USAGES,
        ),
    )
    ca_serial = pki.list_certificates()[0].serial_number
    cert = pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="at-boundary"),
            not_before=now,
            not_after=ca_not_after,
        ),
        ca_serial_number=ca_serial,
    )
    assert cert.request.subject.common_name == "at-boundary"


def test_certificate_request_rejects_equal_dates() -> None:
    with pytest.raises(ValidationError, match="not_after must be after not_before"):
        X509CertificateRequest(
            subject=Subject(common_name="test"),
            not_before=_NOW,
            not_after=_NOW,
        )


# --- get_or_issue_certificate tests ---


def test_get_or_issue_returns_existing_cert(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    request = X509CertificateRequest(
        subject=Subject(common_name="server"),
        not_before=_CERT_NOT_BEFORE,
        not_after=_CERT_NOT_AFTER,
    )
    issued = pki.issue_certificate(request=request, ca_serial_number=ca_serial)

    # Same identity but different time bounds
    new_request = X509CertificateRequest(
        subject=Subject(common_name="server"),
        not_before=_NOW + timedelta(days=100),
        not_after=_NOW + timedelta(days=500),
    )
    result = pki.get_or_issue_certificate(
        new_request,
        not_expired_at=_NOW + timedelta(days=10),
        ca_serial_number=ca_serial,
    )
    assert result.serial_number == issued.serial_number
    # No new cert issued (CA + 1 cert)
    assert len(pki.list_certificates()) == 2


def test_get_or_issue_issues_when_no_match(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)

    request = X509CertificateRequest(
        subject=Subject(common_name="new-server"),
        not_before=_CERT_NOT_BEFORE,
        not_after=_CERT_NOT_AFTER,
    )
    result = pki.get_or_issue_certificate(
        request,
        not_expired_at=_NOW + timedelta(days=10),
        ca_serial_number=ca_serial,
    )
    assert result.request.subject.common_name == "new-server"
    assert result.status == CertificateStatus.ISSUED
    # CA + new cert
    assert len(pki.list_certificates()) == 2


def test_get_or_issue_issues_when_expired(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    # Issue a short-lived cert
    request = X509CertificateRequest(
        subject=Subject(common_name="ephemeral"),
        not_before=_NOW,
        not_after=_NOW + timedelta(days=30),
    )
    original = pki.issue_certificate(request=request, ca_serial_number=ca_serial)

    # Ask for cert not expired at day 60 — original is expired by then
    new_request = X509CertificateRequest(
        subject=Subject(common_name="ephemeral"),
        not_before=_NOW + timedelta(days=30),
        not_after=_NOW + timedelta(days=365),
    )
    result = pki.get_or_issue_certificate(
        new_request,
        not_expired_at=_NOW + timedelta(days=60),
        ca_serial_number=ca_serial,
    )
    assert result.serial_number != original.serial_number
    # CA + 2 certs
    assert len(pki.list_certificates()) == 3


def test_get_or_issue_ignores_revoked(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    request = X509CertificateRequest(
        subject=Subject(common_name="revoked-server"),
        not_before=_CERT_NOT_BEFORE,
        not_after=_CERT_NOT_AFTER,
    )
    issued = pki.issue_certificate(request=request, ca_serial_number=ca_serial)
    pki.revoke_certificate(serial_number=issued.serial_number)

    new_request = X509CertificateRequest(
        subject=Subject(common_name="revoked-server"),
        not_before=_CERT_NOT_BEFORE,
        not_after=_CERT_NOT_AFTER,
    )
    result = pki.get_or_issue_certificate(
        new_request,
        not_expired_at=_NOW + timedelta(days=10),
        ca_serial_number=ca_serial,
    )
    assert result.serial_number != issued.serial_number
    assert result.status == CertificateStatus.ISSUED


def test_get_or_issue_returns_most_recent(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    # Issue two certs with the same identity
    request1 = X509CertificateRequest(
        subject=Subject(common_name="multi"),
        not_before=_NOW,
        not_after=_NOW + timedelta(days=365),
    )
    cert1 = pki.issue_certificate(request=request1, ca_serial_number=ca_serial)

    request2 = X509CertificateRequest(
        subject=Subject(common_name="multi"),
        not_before=_NOW + timedelta(days=1),
        not_after=_NOW + timedelta(days=730),
    )
    pki.issue_certificate(request=request2, ca_serial_number=ca_serial)

    lookup_request = X509CertificateRequest(
        subject=Subject(common_name="multi"),
        not_before=_NOW + timedelta(days=50),
        not_after=_NOW + timedelta(days=400),
    )
    result = pki.get_or_issue_certificate(
        lookup_request,
        not_expired_at=_NOW + timedelta(days=10),
        ca_serial_number=ca_serial,
    )
    # Should return the more recently issued cert
    assert result.issue_date >= cert1.issue_date
    # No new cert issued (CA + 2 certs)
    assert len(pki.list_certificates()) == 3


def test_get_or_issue_no_match_different_identity(ca_subject: Subject, crypto_provider: SoftwareCryptoProvider) -> None:
    pki, ca_serial = _create_ca(ca_subject, crypto_provider)
    pki.issue_certificate(
        request=X509CertificateRequest(
            subject=Subject(common_name="server-a"),
            not_before=_CERT_NOT_BEFORE,
            not_after=_CERT_NOT_AFTER,
            key_usages=[KeyUsage.DIGITAL_SIGNATURE],
        ),
        ca_serial_number=ca_serial,
    )

    # Different common_name
    result = pki.get_or_issue_certificate(
        X509CertificateRequest(
            subject=Subject(common_name="server-b"),
            not_before=_CERT_NOT_BEFORE,
            not_after=_CERT_NOT_AFTER,
            key_usages=[KeyUsage.DIGITAL_SIGNATURE],
        ),
        not_expired_at=_NOW + timedelta(days=10),
        ca_serial_number=ca_serial,
    )
    assert result.request.subject.common_name == "server-b"
    # CA + original + new
    assert len(pki.list_certificates()) == 3

    # Different key_usages
    result2 = pki.get_or_issue_certificate(
        X509CertificateRequest(
            subject=Subject(common_name="server-a"),
            not_before=_CERT_NOT_BEFORE,
            not_after=_CERT_NOT_AFTER,
            key_usages=[KeyUsage.KEY_ENCIPHERMENT],
        ),
        not_expired_at=_NOW + timedelta(days=10),
        ca_serial_number=ca_serial,
    )
    assert result2.request.key_usages == [KeyUsage.KEY_ENCIPHERMENT]
    # CA + original + server-b + new key_usages
    assert len(pki.list_certificates()) == 4
