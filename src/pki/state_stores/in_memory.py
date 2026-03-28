"""In-memory state storage."""

from pki.models import PkiState
from pki.state_stores.base import StateStore


class InMemoryStateStore(StateStore):
    """In-memory state store."""

    def __init__(self, pki_name: str = "default") -> None:
        super().__init__(pki_name)
        self._state: PkiState | None = None

    def save_state(self, state: PkiState) -> None:
        self._state = state

    def load_state(self) -> PkiState | None:
        return self._state

    def delete(self) -> None:
        self._state = None

    def __repr__(self) -> str:
        return f"{type(self).__name__}(pki_name={self._pki_name!r}, has_state={self._state is not None})"
