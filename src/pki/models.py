"""Pydantic DTOs for pki-kit."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import ClassVar

from pydantic import BaseModel, Field

from pki.types import (
    CertificateStatus,
    KeyAlgorithm,
    RevocationReason,
    SerialNumber,
)


class CertificateData(ABC, BaseModel):
    @property
    @abstractmethod
    def not_before(self) -> datetime: ...

    @property
    @abstractmethod
    def not_after(self) -> datetime: ...


class Subject(BaseModel):
    common_name: str
    email: str | None = None
    organization: str | None = None
    org_unit: str | None = None
    country: str | None = None
    state: str | None = None
    locality: str | None = None


class CertificateRequest(BaseModel):
    _identity_exclude_fields: ClassVar[set[str]] = set()

    subject: Subject
    key_algorithm: KeyAlgorithm = KeyAlgorithm.EC_P256
    is_ca: bool = False

    def expected_not_after(self) -> datetime | None:
        """Return the expected not_after for this request, or None if unknown."""
        return None

    def identity_eq(self, other: "CertificateRequest") -> bool:
        if type(self) is not type(other):
            return False
        return self.model_dump(exclude=self._identity_exclude_fields) == other.model_dump(
            exclude=other._identity_exclude_fields
        )


class CertificateInfo[CertRequestT: CertificateRequest, CertDataT: CertificateData](BaseModel):
    request: CertRequestT
    serial_number: SerialNumber
    ca_serial_number: SerialNumber | None = None
    status: CertificateStatus = CertificateStatus.ISSUED
    issue_date: datetime
    revocation_date: datetime | None = None
    revocation_reason: RevocationReason | None = None
    backend_data: CertDataT

    @property
    def not_before(self) -> datetime:
        return self.backend_data.not_before

    @property
    def not_after(self) -> datetime:
        return self.backend_data.not_after


class PkiState(BaseModel):
    issued_certificates: set[SerialNumber] = Field(default_factory=set)
