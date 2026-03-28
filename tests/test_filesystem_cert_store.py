"""Tests for FilesystemCertificateStore."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from ruamel.yaml import YAML

from pki.backends.x509.pki import X509CertData, X509CertificateRequest
from pki.certificate_stores.filesystem import FilesystemCertificateStore
from pki.models import CertificateInfo, Subject
from pki.types import (
    CertificateStatus,
    KeyAlgorithm,
    KeyUsage,
    PEMString,
    PkiType,
    RevocationReason,
    SerialNumber,
)

_NOW = datetime.now(tz=UTC)

# Minimal self-signed PEM for testing (not a real cert, but valid enough for model)
_DUMMY_PEM = PEMString(
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBkTCB+wIUXr5MRiTnqVo2mJmCyjQPJ0bYkpswDQYJKoZIhvcNAQELBQAwEjEQ"
    "MA4GA1UEAwwHVGVzdCBDQTAeFw0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAwMDBa"
    "MBIxEDAOBgNVBAMMB1Rlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT7"
    "Z5KMHkxAqPcOqBHJaEAcak4GR0HZrYkfzAATPIOjkjfj+xj13MfCa+g7iR6xT+lf"
    "cFi0dfTnvPLTq05VEHUqoyMwITAfBgNVHREEGDAWhwR/AAABhwQKAAABhwTAqAAB"
    "MA0GCSqGSIb3DQEBCwUAA0EAV8VwQ0TeMlU+5ZYeBtF/3X9E0fMOPjFJ0KO3RVPD"
    "yZUP8f/n+u/GZP6O5+9J3X1HsLwqF6NlPqd3sEv1JK6dA==\n"
    "-----END CERTIFICATE-----\n"
)


def _make_cert_info(
    common_name: str = "test.example.com",
    serial_number: int = 100,
    ca_serial_number: int | None = 1,
) -> CertificateInfo[X509CertificateRequest, X509CertData]:
    return CertificateInfo[X509CertificateRequest, X509CertData](
        request=X509CertificateRequest(
            subject=Subject(common_name=common_name),
            not_before=_NOW,
            not_after=_NOW + timedelta(days=365),
            key_algorithm=KeyAlgorithm.EC_P256,
            key_usages=[KeyUsage.DIGITAL_SIGNATURE],
        ),
        serial_number=SerialNumber(serial_number),
        ca_serial_number=SerialNumber(ca_serial_number) if ca_serial_number is not None else None,
        issue_date=_NOW,
        backend_data=X509CertData(certificate_pem=_DUMMY_PEM),
    )


def _make_store(
    base_dir: Path, pki_name: str = "test"
) -> FilesystemCertificateStore[X509CertificateRequest, X509CertData]:
    return FilesystemCertificateStore(
        base_dir=base_dir,
        cert_request_type=X509CertificateRequest,
        cert_data_type=X509CertData,
        pki_type=PkiType.X509,
        pki_name=pki_name,
    )


def test_save_and_get_roundtrip(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    cert = _make_cert_info()
    store.save_certificate(cert)

    loaded = store.get_certificate(cert.serial_number)
    assert loaded is not None
    assert loaded.serial_number == cert.serial_number
    assert loaded.request.subject.common_name == "test.example.com"
    assert loaded.backend_data.certificate_pem == _DUMMY_PEM
    assert loaded.status == CertificateStatus.ISSUED
    assert loaded.issue_date == _NOW


def test_get_nonexistent_returns_none(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    assert store.get_certificate(SerialNumber(999)) is None


def test_delete_certificate(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    cert = _make_cert_info()
    store.save_certificate(cert)
    store.delete_certificate(cert.serial_number)
    assert store.get_certificate(cert.serial_number) is None


def test_delete_nonexistent_is_silent(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    store.delete_certificate(SerialNumber(999))  # should not raise


def test_save_overwrites(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    cert = _make_cert_info()
    store.save_certificate(cert)

    updated = cert.model_copy(
        update={"status": CertificateStatus.REVOKED, "revocation_reason": RevocationReason.KEY_COMPROMISE},
    )
    store.save_certificate(updated)

    loaded = store.get_certificate(cert.serial_number)
    assert loaded is not None
    assert loaded.status == CertificateStatus.REVOKED
    assert loaded.revocation_reason == RevocationReason.KEY_COMPROMISE


@pytest.mark.parametrize(
    "common_name",
    [
        "server with spaces",
        "server/with/slashes",
        "server@special!chars",
        "unicode-сервер",
    ],
)
def test_filename_sanitization(tmp_path: Path, common_name: str) -> None:
    store = _make_store(tmp_path)
    cert = _make_cert_info(common_name=common_name)
    store.save_certificate(cert)

    loaded = store.get_certificate(cert.serial_number)
    assert loaded is not None
    assert loaded.request.subject.common_name == common_name


def test_auto_creates_base_dir(tmp_path: Path) -> None:
    nested = tmp_path / "a" / "b" / "c"
    store = _make_store(nested)
    assert nested.is_dir()

    cert = _make_cert_info()
    store.save_certificate(cert)
    assert store.get_certificate(cert.serial_number) is not None


def test_yaml_file_structure(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    cert = _make_cert_info()
    store.save_certificate(cert)

    yaml_files = list(tmp_path.glob("*.yaml"))
    assert len(yaml_files) == 1

    yaml = YAML()
    with yaml_files[0].open() as fh:
        data = yaml.load(fh)

    assert data["format_version"] == 1
    assert data["content_type"] == "x509"
    assert "certificate" in data
    assert data["certificate"]["serial_number"] == 100
    assert data["certificate"]["request"]["subject"]["common_name"] == "test.example.com"


def test_filename_pattern(tmp_path: Path) -> None:
    store = _make_store(tmp_path, pki_name="myca")
    cert = _make_cert_info(common_name="web.server", serial_number=42)
    store.save_certificate(cert)

    yaml_files = list(tmp_path.glob("*.yaml"))
    assert len(yaml_files) == 1
    assert yaml_files[0].name == "myca-42-cert.yaml"


def test_multiple_certificates(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    certs = [_make_cert_info(common_name=f"host{i}", serial_number=i) for i in range(5)]
    for cert in certs:
        store.save_certificate(cert)

    for cert in certs:
        loaded = store.get_certificate(cert.serial_number)
        assert loaded is not None
        assert loaded.serial_number == cert.serial_number


def test_repr(tmp_path: Path) -> None:
    store = _make_store(tmp_path, pki_name="myca")
    r = repr(store)
    assert "FilesystemCertificateStore" in r
    assert "myca" in r
