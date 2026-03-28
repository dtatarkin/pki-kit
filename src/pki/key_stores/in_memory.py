"""In-memory key storage."""

from pki.key_stores.base import KeyStore
from pki.types import SerialNumber


class InMemoryKeyStore(KeyStore):
    """Dict-backed in-memory key store."""

    def __init__(self, pki_name: str = "default") -> None:
        super().__init__(pki_name)
        self._keys: dict[SerialNumber, bytes] = {}

    def store_key(self, serial_number: SerialNumber, data: bytes) -> None:
        self._keys[serial_number] = data

    def get_key(self, serial_number: SerialNumber) -> bytes | None:
        return self._keys.get(serial_number)

    def delete_key(self, serial_number: SerialNumber) -> None:
        self._keys.pop(serial_number, None)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(pki_name={self._pki_name!r}, keys={len(self._keys)})"
