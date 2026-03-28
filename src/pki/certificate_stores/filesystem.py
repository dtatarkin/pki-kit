"""Filesystem-backed certificate storage using YAML files."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import JsonValue, TypeAdapter
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString

from pki.certificate_stores.base import CertificateStore
from pki.models import CertificateData, CertificateInfo, CertificateRequest

if TYPE_CHECKING:
    from pathlib import Path

    from pki.types import PkiType, SerialNumber

_FORMAT_VERSION = 1


def _use_block_scalars(obj: JsonValue) -> JsonValue | LiteralScalarString:
    """Convert multi-line strings to LiteralScalarString for YAML block style."""
    if isinstance(obj, dict):
        return {k: _use_block_scalars(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_use_block_scalars(item) for item in obj]
    if isinstance(obj, str) and "\n" in obj:
        return LiteralScalarString(obj)
    return obj


class FilesystemCertificateStore[CertRequestT: CertificateRequest, CertDataT: CertificateData](
    CertificateStore[CertRequestT, CertDataT],
):
    """YAML file-backed certificate store.

    Each certificate is persisted as a separate YAML file named
    ``{pki_name}-{serial_number}-cert.yaml``.
    """

    def __init__(
        self,
        base_dir: Path,
        cert_request_type: type[CertRequestT],
        cert_data_type: type[CertDataT],
        pki_type: PkiType,
        pki_name: str = "default",
    ) -> None:
        super().__init__(pki_name)
        self._base_dir = base_dir
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._content_type = pki_type
        self._type_adapter: TypeAdapter[CertificateInfo[CertRequestT, CertDataT]] = TypeAdapter(
            CertificateInfo[cert_request_type, cert_data_type],  # type: ignore[valid-type]
        )
        self._yaml = YAML()
        self._yaml.default_flow_style = False
        self._yaml.representer.sort_base_mapping_type_on_output = True

    def save_certificate(self, cert: CertificateInfo[CertRequestT, CertDataT]) -> None:
        filepath = self._cert_filepath(serial_number=cert.serial_number)
        data: dict[str, Any] = {
            "format_version": _FORMAT_VERSION,
            "content_type": str(self._content_type),
            "certificate": _use_block_scalars(
                self._type_adapter.dump_python(cert, mode="json", exclude_defaults=True),
            ),
        }
        tmp_path = filepath.with_suffix(".tmp")
        with tmp_path.open("w") as fh:
            self._yaml.dump(data, fh)
        tmp_path.rename(filepath)

    def get_certificate(self, serial_number: SerialNumber) -> CertificateInfo[CertRequestT, CertDataT] | None:
        filepath = self._cert_filepath(serial_number=serial_number)
        if not filepath.exists():
            return None
        with filepath.open() as fh:
            data = self._yaml.load(fh)
        return self._type_adapter.validate_python(data["certificate"])

    def delete_certificate(self, serial_number: SerialNumber) -> None:
        filepath = self._cert_filepath(serial_number=serial_number)
        filepath.unlink(missing_ok=True)

    def _cert_filepath(self, serial_number: SerialNumber) -> Path:
        return self._base_dir / f"{self._pki_name}-{serial_number}-cert.yaml"

    def __repr__(self) -> str:
        return f"{type(self).__name__}(pki_name={self._pki_name!r}, base_dir={self._base_dir!r})"
