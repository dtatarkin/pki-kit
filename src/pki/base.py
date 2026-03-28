"""Abstract base class for PKI backends."""

from abc import ABC, abstractmethod
from datetime import UTC, datetime

from pki.certificate_stores import CertificateStore, InMemoryCertificateStore
from pki.exceptions import CertificateConflictError, CertificateNotFoundError, CertificateValidityExceedsCAError
from pki.models import (
    CertificateData,
    CertificateInfo,
    CertificateRequest,
    PkiState,
)
from pki.types import (
    CertificateStatus,
    RevocationReason,
    SerialNumber,
)
from pki.utils import generate_serial_number


class Pki[CertRequestT: CertificateRequest, CertDataT: CertificateData](ABC):
    def __init__(
        self,
        *,
        pki_state: PkiState | None = None,
        certificate_store: CertificateStore[CertRequestT, CertDataT] | None = None,
    ) -> None:
        self._certificate_store: CertificateStore[CertRequestT, CertDataT] = (
            certificate_store or InMemoryCertificateStore[CertRequestT, CertDataT]()
        )
        self._issued_serial_numbers: set[SerialNumber] = pki_state.issued_certificates.copy() if pki_state else set()

    def issue_certificate(
        self,
        request: CertRequestT,
        *,
        serial_number: SerialNumber | None = None,
        ca_serial_number: SerialNumber | None = None,
    ) -> CertificateInfo[CertRequestT, CertDataT]:
        # Idempotency check
        if serial_number is not None:
            existing = self.get_certificate(serial_number=serial_number)
            if existing is not None:
                if existing.request != request:
                    raise CertificateConflictError(serial_number=serial_number)
                return existing

        if ca_serial_number is not None:
            ca_cert = self.get_certificate(serial_number=ca_serial_number)
            expected_not_after = request.expected_not_after()
            if ca_cert is not None and expected_not_after is not None and expected_not_after > ca_cert.not_after:
                raise CertificateValidityExceedsCAError(
                    cert_not_after=str(expected_not_after),
                    ca_not_after=str(ca_cert.not_after),
                )

        serial = serial_number if serial_number is not None else generate_serial_number()
        cert_info = self._do_issue_certificate(
            request=request,
            serial_number=serial,
            ca_serial_number=ca_serial_number,
        )
        self._certificate_store.save_certificate(cert=cert_info)
        self._issued_serial_numbers.add(serial)
        return cert_info

    @abstractmethod
    def _do_issue_certificate(
        self,
        request: CertRequestT,
        *,
        serial_number: SerialNumber,
        ca_serial_number: SerialNumber | None = None,
    ) -> CertificateInfo[CertRequestT, CertDataT]: ...

    def get_certificate(self, serial_number: SerialNumber) -> CertificateInfo[CertRequestT, CertDataT] | None:
        return self._certificate_store.get_certificate(serial_number=serial_number)

    def revoke_certificate(
        self,
        serial_number: SerialNumber,
        *,
        reason: RevocationReason = RevocationReason.UNSPECIFIED,
    ) -> CertificateInfo[CertRequestT, CertDataT]:
        cert = self.get_certificate(serial_number=serial_number)
        if cert is None:
            raise CertificateNotFoundError(serial_number=serial_number)

        revoked_cert = cert.model_copy(
            update={
                "status": CertificateStatus.REVOKED,
                "revocation_date": datetime.now(tz=UTC),
                "revocation_reason": reason,
            }
        )
        self._certificate_store.save_certificate(cert=revoked_cert)
        return revoked_cert

    def export_state(self) -> PkiState:
        return PkiState(issued_certificates=self._issued_serial_numbers.copy())

    def get_or_issue_certificate(
        self,
        request: CertRequestT,
        *,
        not_expired_at: datetime,
        ca_serial_number: SerialNumber | None = None,
    ) -> CertificateInfo[CertRequestT, CertDataT]:
        candidates = self.list_certificates(
            status=CertificateStatus.ISSUED,
            not_expired_at=not_expired_at,
        )
        matching = [c for c in candidates if c.request.identity_eq(request)]
        if matching:
            matching.sort(key=lambda c: c.issue_date, reverse=True)
            return matching[0]
        return self.issue_certificate(
            request=request,
            ca_serial_number=ca_serial_number,
        )

    def get_ca_certificate(self, *, common_name: str | None = None) -> CertificateInfo[CertRequestT, CertDataT] | None:
        certs = self.list_certificates(status=CertificateStatus.ISSUED, is_ca=True, common_name=common_name)
        if not certs:
            return None
        certs.sort(key=lambda c: c.issue_date, reverse=True)
        return certs[0]

    def list_certificates(
        self,
        *,
        status: CertificateStatus | None = None,
        not_expired_at: datetime | None = None,
        common_name: str | None = None,
        is_ca: bool | None = None,
    ) -> list[CertificateInfo[CertRequestT, CertDataT]]:
        result: list[CertificateInfo[CertRequestT, CertDataT]] = []
        for serial in self._issued_serial_numbers:
            cert = self.get_certificate(serial_number=serial)
            if cert is None:
                raise CertificateNotFoundError(serial_number=serial)
            if status is not None and cert.status != status:
                continue
            if not_expired_at is not None and cert.not_after < not_expired_at:
                continue
            if common_name is not None and cert.request.subject.common_name != common_name:
                continue
            if is_ca is not None and cert.request.is_ca != is_ca:
                continue
            result.append(cert)
        return result

    @abstractmethod
    def export_certificate_pem(self, serial_number: SerialNumber) -> bytes: ...

    @abstractmethod
    def export_private_key_pem(self, serial_number: SerialNumber) -> bytes: ...

    def __repr__(self) -> str:
        return f"{type(self).__name__}(issued_certificates={len(self._issued_serial_numbers)})"
