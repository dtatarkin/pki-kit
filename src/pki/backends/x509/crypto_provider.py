from abc import ABC, abstractmethod

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, types

from pki.exceptions import KeyNotFoundError, UnsupportedAlgorithmError
from pki.key_stores import InMemoryKeyStore, KeyStore
from pki.types import KeyAlgorithm, PEMString, SerialNumber


class CryptoProvider(ABC):
    def __init__(self, key_store: KeyStore | None = None) -> None:
        self._key_store = key_store or InMemoryKeyStore()

    @property
    def key_store(self) -> KeyStore:
        return self._key_store

    @abstractmethod
    def generate_key(self, algorithm: KeyAlgorithm, serial_number: SerialNumber) -> None: ...

    @abstractmethod
    def sign(self, serial_number: SerialNumber, data: bytes) -> bytes: ...

    @abstractmethod
    def get_public_key_bytes(self, serial_number: SerialNumber) -> bytes: ...

    @abstractmethod
    def load_private_key(self, serial_number: SerialNumber) -> types.PrivateKeyTypes: ...

    @abstractmethod
    def export_private_pem(self, serial_number: SerialNumber) -> PEMString: ...

    @abstractmethod
    def export_public_pem(self, serial_number: SerialNumber) -> PEMString: ...

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"


class SoftwareCryptoProvider(CryptoProvider):
    """Software-based crypto provider using the cryptography library."""

    def load_private_key(self, serial_number: SerialNumber) -> types.PrivateKeyTypes:
        data = self._key_store.get_key(serial_number=serial_number)
        if data is None:
            raise KeyNotFoundError(serial_number=serial_number)
        return serialization.load_der_private_key(data=data, password=None)

    def generate_key(self, algorithm: KeyAlgorithm, serial_number: SerialNumber) -> None:
        key: types.PrivateKeyTypes
        if algorithm == KeyAlgorithm.RSA_2048:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif algorithm == KeyAlgorithm.RSA_4096:
            key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        elif algorithm == KeyAlgorithm.EC_P256:
            key = ec.generate_private_key(curve=ec.SECP256R1())
        elif algorithm == KeyAlgorithm.EC_P384:
            key = ec.generate_private_key(curve=ec.SECP384R1())
        elif algorithm == KeyAlgorithm.ED25519:
            key = ed25519.Ed25519PrivateKey.generate()
        else:
            raise UnsupportedAlgorithmError(algorithm=algorithm)

        der_bytes = key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self._key_store.store_key(serial_number=serial_number, data=der_bytes)

    def sign(self, serial_number: SerialNumber, data: bytes) -> bytes:
        key = self.load_private_key(serial_number=serial_number)

        if isinstance(key, rsa.RSAPrivateKey):
            hash_alg = hashes.SHA384() if key.key_size > 2048 else hashes.SHA256()
            result: bytes = key.sign(data=data, padding=padding.PKCS1v15(), algorithm=hash_alg)
            return result
        if isinstance(key, ec.EllipticCurvePrivateKey):
            hash_alg = hashes.SHA384() if isinstance(key.curve, ec.SECP384R1) else hashes.SHA256()
            result = key.sign(data=data, signature_algorithm=ec.ECDSA(algorithm=hash_alg))
            return result
        if isinstance(key, ed25519.Ed25519PrivateKey):
            result = key.sign(data=data)
            return result

        raise UnsupportedAlgorithmError(algorithm=type(key).__name__)

    def get_public_key_bytes(self, serial_number: SerialNumber) -> bytes:
        key = self.load_private_key(serial_number=serial_number)
        result: bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return result

    def export_private_pem(self, serial_number: SerialNumber) -> PEMString:
        key = self.load_private_key(serial_number=serial_number)
        pem_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return PEMString(pem_bytes.decode())

    def export_public_pem(self, serial_number: SerialNumber) -> PEMString:
        key = self.load_private_key(serial_number=serial_number)
        pem_bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return PEMString(pem_bytes.decode())
