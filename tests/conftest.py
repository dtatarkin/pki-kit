"""Shared test fixtures."""

import shutil
import subprocess

import pytest

from pki.backends.x509.crypto_provider import SoftwareCryptoProvider
from pki.key_stores import InMemoryKeyStore
from pki.models import Subject
from pki.types import KeyAlgorithm


@pytest.fixture
def crypto_provider() -> SoftwareCryptoProvider:
    return SoftwareCryptoProvider(key_store=InMemoryKeyStore())


@pytest.fixture
def ca_subject() -> Subject:
    return Subject(
        common_name="Test CA",
        organization="Test Org",
        country="US",
    )


@pytest.fixture(params=[KeyAlgorithm.EC_P256, KeyAlgorithm.RSA_2048])
def key_algorithm(request: pytest.FixtureRequest) -> KeyAlgorithm:
    return request.param  # type: ignore[no-any-return]


@pytest.fixture
def age_recipient(monkeypatch: pytest.MonkeyPatch) -> str:
    """Generate an age keypair and configure env for SOPS decryption."""
    if not shutil.which("age-keygen"):
        pytest.skip("age-keygen not found on PATH")
    result = subprocess.run(
        ["age-keygen"],
        capture_output=True,
        text=True,
        check=True,
    )
    recipient = ""
    secret_key = ""
    for line in result.stderr.splitlines():
        if line.startswith("Public key:"):
            recipient = line.split(": ", 1)[1].strip()
    for line in result.stdout.splitlines():
        if not line.startswith("#"):
            secret_key = line.strip()

    monkeypatch.setenv("SOPS_AGE_KEY", secret_key)
    return recipient
