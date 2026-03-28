"""Filesystem-backed state storage using YAML files."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ruamel.yaml import YAML

from pki.models import PkiState
from pki.state_stores.base import StateStore

if TYPE_CHECKING:
    from pathlib import Path

_FORMAT_VERSION = 1


class FilesystemStateStore(StateStore):
    """YAML file-backed state store.

    State is persisted as a single YAML file named
    ``{pki_name}-state.yaml``.
    """

    def __init__(self, base_dir: Path, pki_name: str = "default") -> None:
        super().__init__(pki_name)
        self._base_dir = base_dir
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._yaml = YAML()
        self._yaml.default_flow_style = False
        self._yaml.representer.sort_base_mapping_type_on_output = True

    def save_state(self, state: PkiState) -> None:
        filepath = self._state_filepath()
        state_data = state.model_dump(mode="json", exclude_defaults=True)
        if "issued_certificates" in state_data:
            state_data["issued_certificates"] = sorted(state_data["issued_certificates"])
        data: dict[str, Any] = {
            "format_version": _FORMAT_VERSION,
            "state": state_data,
        }
        tmp_path = filepath.with_suffix(".tmp")
        with tmp_path.open("w") as fh:
            self._yaml.dump(data, fh)
        tmp_path.rename(filepath)

    def load_state(self) -> PkiState | None:
        filepath = self._state_filepath()
        if not filepath.exists():
            return None
        with filepath.open() as fh:
            data = self._yaml.load(fh)
        return PkiState.model_validate(data["state"])

    def delete(self) -> None:
        filepath = self._state_filepath()
        if filepath.exists():
            filepath.unlink()

    def _state_filepath(self) -> Path:
        return self._base_dir / f"{self._pki_name}-state.yaml"

    def __repr__(self) -> str:
        return f"{type(self).__name__}(pki_name={self._pki_name!r}, base_dir={self._base_dir!r})"
