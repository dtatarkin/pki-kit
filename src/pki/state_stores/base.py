"""Abstract state storage."""

from abc import ABC, abstractmethod

from pki.models import PkiState


class StateStore(ABC):
    """Abstract persistence layer for PKI state."""

    def __init__(self, pki_name: str = "default") -> None:
        self._pki_name = pki_name

    @property
    def pki_name(self) -> str:
        return self._pki_name

    @abstractmethod
    def save_state(self, state: PkiState) -> None: ...

    @abstractmethod
    def load_state(self) -> PkiState | None: ...

    @abstractmethod
    def delete(self) -> None: ...

    def __repr__(self) -> str:
        return f"{type(self).__name__}(pki_name={self._pki_name!r})"
