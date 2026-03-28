"""Tests for FilesystemStateStore."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ruamel.yaml import YAML

from pki.models import PkiState
from pki.state_stores.filesystem import FilesystemStateStore
from pki.types import SerialNumber

if TYPE_CHECKING:
    from pathlib import Path


def _make_store(base_dir: Path, pki_name: str = "test") -> FilesystemStateStore:
    return FilesystemStateStore(base_dir=base_dir, pki_name=pki_name)


def _make_state(*serials: int) -> PkiState:
    return PkiState(issued_certificates={SerialNumber(s) for s in serials})


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    state = _make_state(100, 200, 300)
    store.save_state(state)

    loaded = store.load_state()
    assert loaded is not None
    assert loaded.issued_certificates == state.issued_certificates


def test_load_when_no_file_returns_none(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    assert store.load_state() is None


def test_delete_then_load_returns_none(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    store.save_state(_make_state(1))
    store.delete()
    assert store.load_state() is None


def test_delete_nonexistent_is_silent(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    store.delete()  # should not raise


def test_save_overwrites(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    store.save_state(_make_state(1, 2))
    store.save_state(_make_state(1, 2, 3))

    loaded = store.load_state()
    assert loaded is not None
    assert loaded.issued_certificates == {SerialNumber(1), SerialNumber(2), SerialNumber(3)}


def test_auto_creates_base_dir(tmp_path: Path) -> None:
    nested = tmp_path / "a" / "b" / "c"
    store = _make_store(nested)
    assert nested.is_dir()

    store.save_state(_make_state(42))
    assert store.load_state() is not None


def test_yaml_file_structure(tmp_path: Path) -> None:
    store = _make_store(tmp_path, pki_name="myca")
    store.save_state(_make_state(300, 100, 200))

    yaml_files = list(tmp_path.glob("*.yaml"))
    assert len(yaml_files) == 1
    assert yaml_files[0].name == "myca-state.yaml"

    yaml = YAML()
    with yaml_files[0].open() as fh:
        data = yaml.load(fh)

    assert data["format_version"] == 1
    assert "state" in data
    # issued_certificates should be sorted
    assert data["state"]["issued_certificates"] == [100, 200, 300]


def test_repr(tmp_path: Path) -> None:
    store = _make_store(tmp_path, pki_name="myca")
    r = repr(store)
    assert "FilesystemStateStore" in r
    assert "myca" in r
