"""Abstract certificate storage."""

from abc import ABC, abstractmethod

from pki.models import CertificateData, CertificateInfo, CertificateRequest
from pki.types import SerialNumber


class CertificateStore[CertRequestT: CertificateRequest, CertDataT: CertificateData](ABC):
    """Abstract persistence layer for certificates."""

    def __init__(self, pki_name: str = "default") -> None:
        self._pki_name = pki_name

    @property
    def pki_name(self) -> str:
        return self._pki_name

    @abstractmethod
    def save_certificate(self, cert: CertificateInfo[CertRequestT, CertDataT]) -> None: ...

    @abstractmethod
    def get_certificate(self, serial_number: SerialNumber) -> CertificateInfo[CertRequestT, CertDataT] | None: ...

    @abstractmethod
    def delete_certificate(self, serial_number: SerialNumber) -> None: ...

    def __repr__(self) -> str:
        return f"{type(self).__name__}(pki_name={self._pki_name!r})"
