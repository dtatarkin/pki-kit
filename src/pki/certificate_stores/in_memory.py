"""In-memory certificate storage."""

from pki.certificate_stores.base import CertificateStore
from pki.models import CertificateData, CertificateInfo, CertificateRequest
from pki.types import SerialNumber


class InMemoryCertificateStore[CertRequestT: CertificateRequest, CertDataT: CertificateData](
    CertificateStore[CertRequestT, CertDataT],
):
    """Dict-backed in-memory certificate store."""

    def __init__(self, pki_name: str = "default") -> None:
        super().__init__(pki_name)
        self._certificates: dict[SerialNumber, CertificateInfo[CertRequestT, CertDataT]] = {}

    def save_certificate(self, cert: CertificateInfo[CertRequestT, CertDataT]) -> None:
        self._certificates[cert.serial_number] = cert

    def get_certificate(self, serial_number: SerialNumber) -> CertificateInfo[CertRequestT, CertDataT] | None:
        return self._certificates.get(serial_number)

    def delete_certificate(self, serial_number: SerialNumber) -> None:
        self._certificates.pop(serial_number, None)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(pki_name={self._pki_name!r}, certificates={len(self._certificates)})"
