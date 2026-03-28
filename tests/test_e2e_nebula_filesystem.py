"""End-to-end Nebula PKI lifecycle test using filesystem stores."""

from __future__ import annotations

import shutil
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from pki.backends.nebula.pki import NebulaCertData, NebulaCertificateRequest, NebulaPki
from pki.certificate_stores.filesystem import FilesystemCertificateStore
from pki.key_stores.filesystem import FilesystemKeyStore
from pki.models import Subject
from pki.state_stores.filesystem import FilesystemStateStore
from pki.types import CertificateStatus, KeyAlgorithm, PkiType, RevocationReason
from tests.consts import FAKE_TMP_PATH

if TYPE_CHECKING:
    from pathlib import Path

if FAKE_TMP_PATH:
    from _pytest.fixtures import fixture

    @fixture
    def tmp_path() -> Path:
        from pathlib import Path

        return Path("~/test-nebula")


pytestmark = [
    pytest.mark.skipif(not shutil.which("sops"), reason="sops must be available on PATH"),
    pytest.mark.skipif(not shutil.which("nebula-cert"), reason="nebula-cert not found on PATH"),
]


def test_nebula_full_lifecycle(tmp_path: Path, age_recipient: str) -> None:
    """Full Nebula PKI lifecycle with filesystem persistence."""
    key_store = FilesystemKeyStore(tmp_path / "keys", sops_args=("--age", age_recipient))
    cert_store = FilesystemCertificateStore(
        tmp_path / "certs",
        NebulaCertificateRequest,
        NebulaCertData,
        pki_type=PkiType.NEBULA,
    )
    state_store = FilesystemStateStore(tmp_path)

    # 1. Create empty PKI
    pki = NebulaPki(key_store=key_store, certificate_store=cert_store)
    assert pki.list_certificates() == []

    # 2. Save empty state
    state_store.save_state(pki.export_state())

    # 3. Load empty state → new PKI, verify empty
    loaded_state = state_store.load_state()
    assert loaded_state is not None
    assert loaded_state.issued_certificates == set()
    pki = NebulaPki(pki_state=loaded_state, key_store=key_store, certificate_store=cert_store)
    assert pki.list_certificates() == []

    # 4. Issue CA cert
    ca_cert = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="Test Nebula CA"),
            duration=timedelta(days=3650),
            key_algorithm=KeyAlgorithm.ED25519,
            is_ca=True,
        ),
    )
    ca_serial = ca_cert.serial_number
    assert ca_cert.request.is_ca is True
    assert ca_cert.backend_data.certificate_pem
    assert isinstance(ca_cert.issue_date, datetime)

    # 5. Save state
    state_store.save_state(pki.export_state())

    # 6. Recreate PKI from saved state — verify CA accessible
    pki = NebulaPki(
        pki_state=state_store.load_state(),
        key_store=key_store,
        certificate_store=cert_store,
    )
    assert len(pki.list_certificates()) == 1
    loaded_ca = pki.get_certificate(ca_serial)
    assert loaded_ca is not None
    assert loaded_ca.request.subject.common_name == "Test Nebula CA"
    # Verify CA key is retrievable
    ca_key_bytes = pki.export_private_key_pem(ca_serial)
    assert len(ca_key_bytes) > 0

    # 7. Issue cert for host1
    host1_cert = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="host1"),
            duration=timedelta(days=365),
            ip="10.0.0.1/24",
            key_algorithm=KeyAlgorithm.ED25519,
            groups=["servers"],
        ),
        ca_serial_number=ca_serial,
    )
    host1_serial = host1_cert.serial_number

    # 8. Issue cert for host2
    host2_cert = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="host2"),
            duration=timedelta(days=365),
            ip="10.0.0.2/24",
            key_algorithm=KeyAlgorithm.ED25519,
            groups=["servers"],
        ),
        ca_serial_number=ca_serial,
    )
    host2_serial = host2_cert.serial_number

    # 9. Issue second cert for host1 (different serial, same CN, different IP)
    host1_cert2 = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="host1"),
            duration=timedelta(days=730),
            ip="10.0.0.10/24",
            key_algorithm=KeyAlgorithm.ED25519,
            groups=["servers"],
        ),
        ca_serial_number=ca_serial,
    )
    host1_serial2 = host1_cert2.serial_number
    assert host1_serial2 != host1_serial

    # 10. Revoke first host1 cert
    revoked = pki.revoke_certificate(host1_serial, reason=RevocationReason.SUPERSEDED)
    assert revoked.status == CertificateStatus.REVOKED
    assert revoked.revocation_reason == RevocationReason.SUPERSEDED
    assert revoked.revocation_date is not None

    # 11. Save state
    state_store.save_state(pki.export_state())

    # 12. Recreate PKI from saved state — full verification
    pki = NebulaPki(
        pki_state=state_store.load_state(),
        key_store=key_store,
        certificate_store=cert_store,
    )

    all_certs = pki.list_certificates()
    assert len(all_certs) == 4

    issued = pki.list_certificates(status=CertificateStatus.ISSUED)
    assert len(issued) == 3

    revoked_list = pki.list_certificates(status=CertificateStatus.REVOKED)
    assert len(revoked_list) == 1
    assert revoked_list[0].serial_number == host1_serial
    assert revoked_list[0].revocation_reason == RevocationReason.SUPERSEDED

    # Verify filtering by common_name
    host1_certs = pki.list_certificates(common_name="host1")
    assert len(host1_certs) == 2

    host1_issued = pki.list_certificates(common_name="host1", status=CertificateStatus.ISSUED)
    assert len(host1_issued) == 1
    assert host1_issued[0].serial_number == host1_serial2

    # Verify each cert is accessible
    for sn in [ca_serial, host1_serial, host2_serial, host1_serial2]:
        assert pki.get_certificate(sn) is not None

    # Verify keys are retrievable
    for sn in [ca_serial, host1_serial, host2_serial, host1_serial2]:
        assert len(pki.export_private_key_pem(sn)) > 0

    # 13. get_or_issue_certificate returns existing cert (host2 identity, different duration)
    got_cert = pki.get_or_issue_certificate(
        NebulaCertificateRequest(
            subject=Subject(common_name="host2"),
            duration=timedelta(days=730),
            ip="10.0.0.2/24",
            key_algorithm=KeyAlgorithm.ED25519,
            groups=["servers"],
        ),
        not_expired_at=ca_cert.not_before + timedelta(days=30),
        ca_serial_number=ca_serial,
    )
    assert got_cert.serial_number == host2_serial
    assert len(pki.list_certificates()) == 4  # no new cert

    # 14. get_or_issue_certificate issues new cert (new identity)
    new_cert = pki.get_or_issue_certificate(
        NebulaCertificateRequest(
            subject=Subject(common_name="host3"),
            duration=timedelta(days=365),
            ip="10.0.0.3/24",
            key_algorithm=KeyAlgorithm.ED25519,
            groups=["servers"],
        ),
        not_expired_at=ca_cert.not_before + timedelta(days=30),
        ca_serial_number=ca_serial,
    )
    assert new_cert.request.subject.common_name == "host3"
    assert new_cert.serial_number not in {ca_serial, host1_serial, host2_serial, host1_serial2}
    assert len(pki.list_certificates()) == 5
