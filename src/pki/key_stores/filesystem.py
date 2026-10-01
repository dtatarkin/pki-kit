"""Filesystem-backed key storage with SOPS encryption."""

from __future__ import annotations

import subprocess
from base64 import b64decode, b64encode
from io import StringIO
from typing import TYPE_CHECKING, Any

from ruamel.yaml import YAML

from pki.exceptions import SopsError
from pki.key_stores.base import KeyStore

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from pki.types import SerialNumber

_FORMAT_VERSION = 1


class FilesystemKeyStore(KeyStore):
    """SOPS-encrypted YAML file-backed key store.

    Each key is persisted as a separate YAML file named
    ``{pki_name}-{serial_number}-key.yaml``, encrypted with SOPS.
    """

    def __init__(
        self,
        base_dir: Path,
        pki_name: str = "default",
        sops_binary: str = "sops",
        sops_args: Sequence[str] = (),
    ) -> None:
        super().__init__(pki_name)
        self._base_dir = base_dir
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._sops_binary = sops_binary
        self._sops_args = tuple(sops_args)
        self._yaml = YAML()
        self._yaml.default_flow_style = False
        self._yaml.representer.sort_base_mapping_type_on_output = True

    def store_key(self, serial_number: SerialNumber, data: bytes) -> None:
        filepath = self._key_filepath(serial_number)
        plaintext_data: dict[str, Any] = {
            "format_version": _FORMAT_VERSION,
            "key": b64encode(data).decode("ascii"),
        }
        buf = StringIO()
        self._yaml.dump(plaintext_data, buf)
        plaintext_yaml = buf.getvalue()

        result = self._run_sops(
            [
                "encrypt",
                *self._sops_args,
                "--input-type",
                "yaml",
                "--output-type",
                "yaml",
                "--encrypted-regex",
                "^key$",
                "/dev/stdin",
            ],
            input_data=plaintext_yaml,
        )

        tmp_path = filepath.with_suffix(".tmp")
        tmp_path.write_text(result.stdout)
        tmp_path.rename(filepath)

    def get_key(self, serial_number: SerialNumber) -> bytes | None:
        matches = list(self._base_dir.glob(f"{self._pki_name}-{serial_number}-key.yaml"))
        if not matches:
            return None

        result = self._run_sops(["decrypt", str(matches[0])])
        data = self._yaml.load(result.stdout)
        return b64decode(data["key"])

    def delete_key(self, serial_number: SerialNumber) -> None:
        for match in self._base_dir.glob(f"{self._pki_name}-{serial_number}-key.yaml"):
            match.unlink()

    def _key_filepath(self, serial_number: SerialNumber) -> Path:
        return self._base_dir / f"{self._pki_name}-{serial_number}-key.yaml"

    def _run_sops(
        self,
        args: list[str],
        input_data: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        cmd = [self._sops_binary, *args]
        try:
            return subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                check=True,
            )
        except FileNotFoundError as exc:
            raise SopsError(f"SOPS binary not found: {self._sops_binary}") from exc
        except subprocess.CalledProcessError as exc:
            raise SopsError(
                f"SOPS command failed: {' '.join(cmd)}",
                stderr=exc.stderr,
            ) from exc

    def __repr__(self) -> str:
        return f"{type(self).__name__}(pki_name={self._pki_name!r}, base_dir={self._base_dir!r})"
