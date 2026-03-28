"""Abstract key storage."""

from abc import ABC, abstractmethod

from pki.types import SerialNumber


class KeyStore(ABC):
    def __init__(self, pki_name: str = "default") -> None:
        self._pki_name = pki_name

    @property
    def pki_name(self) -> str:
        return self._pki_name

    @abstractmethod
    def store_key(self, serial_number: SerialNumber, data: bytes) -> None: ...

    @abstractmethod
    def get_key(self, serial_number: SerialNumber) -> bytes | None: ...

    @abstractmethod
    def delete_key(self, serial_number: SerialNumber) -> None: ...

    def __repr__(self) -> str:
        return f"{type(self).__name__}(pki_name={self._pki_name!r})"
