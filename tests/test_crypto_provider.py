"""Tests for SoftwareCryptoProvider."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from pki import KeyNotFoundError
from pki.backends.x509.crypto_provider import SoftwareCryptoProvider
from pki.key_stores import InMemoryKeyStore
from pki.types import KeyAlgorithm, SerialNumber


@pytest.fixture
def provider() -> SoftwareCryptoProvider:
    return SoftwareCryptoProvider(key_store=InMemoryKeyStore())


@pytest.mark.parametrize("algorithm", list(KeyAlgorithm))
def test_generate_key(provider: SoftwareCryptoProvider, algorithm: KeyAlgorithm) -> None:
    serial = SerialNumber(1)
    provider.generate_key(algorithm=algorithm, serial_number=serial)
    public_bytes = provider.get_public_key_bytes(serial_number=serial)
    assert len(public_bytes) > 0


@pytest.mark.parametrize("algorithm", list(KeyAlgorithm))
def test_sign_verify_roundtrip(provider: SoftwareCryptoProvider, algorithm: KeyAlgorithm) -> None:
    serial = SerialNumber(1)
    provider.generate_key(algorithm=algorithm, serial_number=serial)
    data = b"test data to sign"
    signature = provider.sign(serial_number=serial, data=data)
    assert len(signature) > 0

    # Verify using the public key
    pub_pem = provider.export_public_pem(serial_number=serial)
    pub_key = load_pem_public_key(data=pub_pem.encode())

    if isinstance(pub_key, rsa.RSAPublicKey):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        hash_alg = hashes.SHA256() if algorithm == KeyAlgorithm.RSA_2048 else hashes.SHA384()
        pub_key.verify(signature=signature, data=data, padding=padding.PKCS1v15(), algorithm=hash_alg)
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

        hash_alg = hashes.SHA256() if algorithm == KeyAlgorithm.EC_P256 else hashes.SHA384()
        pub_key.verify(signature=signature, data=data, signature_algorithm=ECDSA(algorithm=hash_alg))
    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        pub_key.verify(signature=signature, data=data)


@pytest.mark.parametrize("algorithm", list(KeyAlgorithm))
def test_pem_export(provider: SoftwareCryptoProvider, algorithm: KeyAlgorithm) -> None:
    serial = SerialNumber(1)
    provider.generate_key(algorithm=algorithm, serial_number=serial)
    private_pem = provider.export_private_pem(serial_number=serial)
    public_pem = provider.export_public_pem(serial_number=serial)

    assert private_pem.startswith("-----BEGIN")
    assert "BEGIN PUBLIC KEY" in public_pem


def test_invalid_handle_raises(provider: SoftwareCryptoProvider) -> None:
    with pytest.raises(KeyNotFoundError):
        provider.sign(serial_number=SerialNumber(999999), data=b"data")


def test_invalid_handle_export(provider: SoftwareCryptoProvider) -> None:
    with pytest.raises(KeyNotFoundError):
        provider.export_private_pem(serial_number=SerialNumber(999999))
