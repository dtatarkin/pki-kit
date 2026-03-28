"""Tests for FilesystemKeyStore with SOPS encryption."""

from __future__ import annotations

import shutil
from typing import TYPE_CHECKING

import pytest
from ruamel.yaml import YAML

from pki.exceptions import SopsError
from pki.key_stores.filesystem import FilesystemKeyStore
from pki.types import SerialNumber

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.skipif(
    not shutil.which("sops"),
    reason="sops must be available on PATH",
)


@pytest.fixture
def store(tmp_path: Path, age_recipient: str) -> FilesystemKeyStore:
    return FilesystemKeyStore(
        base_dir=tmp_path,
        pki_name="test",
        sops_args=("--age", age_recipient),
    )


_SAMPLE_KEY = b"\x00\x01\x02\x03\x04\x05" * 10


def test_store_and_get_roundtrip(store: FilesystemKeyStore) -> None:
    store.store_key(SerialNumber(100), _SAMPLE_KEY)
    loaded = store.get_key(SerialNumber(100))
    assert loaded == _SAMPLE_KEY


def test_get_nonexistent_returns_none(store: FilesystemKeyStore) -> None:
    assert store.get_key(SerialNumber(999)) is None


def test_delete_key(store: FilesystemKeyStore) -> None:
    store.store_key(SerialNumber(100), _SAMPLE_KEY)
    store.delete_key(SerialNumber(100))
    assert store.get_key(SerialNumber(100)) is None


def test_delete_nonexistent_is_silent(store: FilesystemKeyStore) -> None:
    store.delete_key(SerialNumber(999))  # should not raise


def test_store_overwrites(store: FilesystemKeyStore) -> None:
    store.store_key(SerialNumber(100), b"old-key-data")
    store.store_key(SerialNumber(100), b"new-key-data")
    loaded = store.get_key(SerialNumber(100))
    assert loaded == b"new-key-data"


def test_multiple_keys(store: FilesystemKeyStore) -> None:
    keys = {SerialNumber(i): f"key-data-{i}".encode() for i in range(5)}
    for sn, data in keys.items():
        store.store_key(sn, data)

    for sn, data in keys.items():
        assert store.get_key(sn) == data


def test_encrypted_file_structure(store: FilesystemKeyStore, tmp_path: Path) -> None:
    store.store_key(SerialNumber(42), _SAMPLE_KEY)

    yaml_files = list(tmp_path.glob("*.yaml"))
    assert len(yaml_files) == 1
    assert yaml_files[0].name == "test-42-key.yaml"

    yaml = YAML()
    with yaml_files[0].open() as fh:
        data = yaml.load(fh)

    # format_version should be plaintext
    assert data["format_version"] == 1
    # key value should be encrypted (ENC[...])
    assert isinstance(data["key"], str)
    assert data["key"].startswith("ENC[")
    # sops metadata block should be present
    assert "sops" in data


def test_auto_creates_base_dir(tmp_path: Path, age_recipient: str) -> None:
    nested = tmp_path / "a" / "b" / "c"
    store = FilesystemKeyStore(
        base_dir=nested,
        pki_name="test",
        sops_args=("--age", age_recipient),
    )
    assert nested.is_dir()
    store.store_key(SerialNumber(1), _SAMPLE_KEY)
    assert store.get_key(SerialNumber(1)) == _SAMPLE_KEY


def test_sops_error_on_bad_binary(tmp_path: Path) -> None:
    store = FilesystemKeyStore(
        base_dir=tmp_path,
        pki_name="test",
        sops_binary="/nonexistent/sops",
    )
    with pytest.raises(SopsError, match="SOPS binary not found"):
        store.store_key(SerialNumber(1), _SAMPLE_KEY)


def test_repr(store: FilesystemKeyStore) -> None:
    r = repr(store)
    assert "FilesystemKeyStore" in r
    assert "test" in r
