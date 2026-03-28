"""CLI context and PKI factory helpers."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from pki.backends.nebula.pki import NebulaPki
    from pki.backends.x509.pki import X509Pki


class OutputFormat(StrEnum):
    TABLE = auto()
    JSON = auto()
    YAML = auto()


@dataclass(frozen=True)
class CliContext:
    base_path: Path
    pki_name: str
    sops_args: tuple[str, ...]
    output_format: OutputFormat


@contextmanager
def x509_session(ctx: CliContext, *, save_state: bool = True) -> Iterator[X509Pki]:
    """Create a fully-wired X509Pki with filesystem stores, yielding it for use.

    State is automatically saved on successful exit when *save_state* is True.
    """
    from pki.backends.x509.crypto_provider import SoftwareCryptoProvider
    from pki.backends.x509.pki import X509CertData, X509CertificateRequest, X509Pki
    from pki.certificate_stores.filesystem import FilesystemCertificateStore
    from pki.key_stores.filesystem import FilesystemKeyStore
    from pki.state_stores.filesystem import FilesystemStateStore
    from pki.types import PkiType

    key_store = FilesystemKeyStore(
        ctx.base_path / "keys",
        pki_name=ctx.pki_name,
        sops_args=ctx.sops_args,
    )
    crypto_provider = SoftwareCryptoProvider(key_store=key_store)
    cert_store = FilesystemCertificateStore(
        ctx.base_path / "certs",
        X509CertificateRequest,
        X509CertData,
        pki_type=PkiType.X509,
        pki_name=ctx.pki_name,
    )
    state_store = FilesystemStateStore(ctx.base_path, pki_name=ctx.pki_name)
    pki_state = state_store.load_state()

    pki = X509Pki(pki_state=pki_state, crypto_provider=crypto_provider, certificate_store=cert_store)
    yield pki

    if save_state:
        state_store.save_state(pki.export_state())


@contextmanager
def nebula_session(ctx: CliContext, *, save_state: bool = True) -> Iterator[NebulaPki]:
    """Create a fully-wired NebulaPki with filesystem stores."""
    from pki.backends.nebula.pki import NebulaCertData, NebulaCertificateRequest, NebulaPki
    from pki.certificate_stores.filesystem import FilesystemCertificateStore
    from pki.key_stores.filesystem import FilesystemKeyStore
    from pki.state_stores.filesystem import FilesystemStateStore
    from pki.types import PkiType

    key_store = FilesystemKeyStore(
        ctx.base_path / "keys",
        pki_name=ctx.pki_name,
        sops_args=ctx.sops_args,
    )
    cert_store = FilesystemCertificateStore(
        ctx.base_path / "certs",
        NebulaCertificateRequest,
        NebulaCertData,
        pki_type=PkiType.NEBULA,
        pki_name=ctx.pki_name,
    )
    state_store = FilesystemStateStore(ctx.base_path, pki_name=ctx.pki_name)
    pki_state = state_store.load_state()

    pki = NebulaPki(pki_state=pki_state, key_store=key_store, certificate_store=cert_store)
    yield pki

    if save_state:
        state_store.save_state(pki.export_state())
