"""X.509 PKI backend."""

import hashlib
import ipaddress
from datetime import UTC, datetime
from functools import cached_property
from typing import TYPE_CHECKING, ClassVar, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pydantic import ConfigDict, Field, model_validator

from pki.backends.x509.crypto_provider import CryptoProvider, SoftwareCryptoProvider
from pki.base import Pki
from pki.certificate_stores import CertificateStore
from pki.exceptions import CertificateNotFoundError
from pki.models import (
    CertificateData,
    CertificateInfo,
    CertificateRequest,
    PkiState,
    Subject,
)
from pki.types import (
    CertificateStatus,
    ExtendedKeyUsage,
    Fingerprint,
    KeyAlgorithm,
    KeyUsage,
    PEMString,
    SerialNumber,
)

if TYPE_CHECKING:
    from typing import Self

    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519

    type _CertPrivateKey = (
        rsa.RSAPrivateKey
        | dsa.DSAPrivateKey
        | ec.EllipticCurvePrivateKey
        | ed25519.Ed25519PrivateKey
        | ed448.Ed448PrivateKey
    )
    type _CertPublicKey = (
        rsa.RSAPublicKey
        | dsa.DSAPublicKey
        | ec.EllipticCurvePublicKey
        | ed25519.Ed25519PublicKey
        | ed448.Ed448PublicKey
        | x25519.X25519PublicKey
        | x448.X448PublicKey
    )
    type _AKIPublicKey = (
        rsa.RSAPublicKey
        | dsa.DSAPublicKey
        | ec.EllipticCurvePublicKey
        | ed25519.Ed25519PublicKey
        | ed448.Ed448PublicKey
    )


class X509CertificateRequest(CertificateRequest):
    _identity_exclude_fields: ClassVar[set[str]] = {"not_before", "not_after"}

    not_before: datetime
    not_after: datetime
    key_usages: list[KeyUsage] = Field(default_factory=list)
    extended_key_usages: list[ExtendedKeyUsage] = Field(default_factory=list)
    san_dns_names: list[str] = Field(default_factory=list)
    san_ip_addresses: list[str] = Field(default_factory=list)
    san_email_addresses: list[str] = Field(default_factory=list)

    def expected_not_after(self) -> datetime:
        return self.not_after

    @model_validator(mode="after")
    def _validate_dates(self) -> "Self":
        if self.not_after <= self.not_before:
            raise ValueError("not_after must be after not_before")
        return self


class X509CertData(CertificateData):
    model_config = ConfigDict(frozen=True)

    certificate_pem: PEMString

    @cached_property
    def parsed_certificate(self) -> x509.Certificate:
        return x509.load_pem_x509_certificate(data=self.certificate_pem.encode())

    @property
    def not_before(self) -> datetime:
        result: datetime = self.parsed_certificate.not_valid_before_utc
        return result

    @property
    def not_after(self) -> datetime:
        result: datetime = self.parsed_certificate.not_valid_after_utc
        return result

    @property
    def fingerprint(self) -> Fingerprint:
        digest = hashlib.sha256(self.parsed_certificate.public_bytes(encoding=serialization.Encoding.DER)).hexdigest()
        return Fingerprint(digest)


# --- Helper functions ---

_NAME_ATTR_MAP = {
    "common_name": NameOID.COMMON_NAME,
    "organization": NameOID.ORGANIZATION_NAME,
    "org_unit": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "country": NameOID.COUNTRY_NAME,
    "state": NameOID.STATE_OR_PROVINCE_NAME,
    "locality": NameOID.LOCALITY_NAME,
    "email": NameOID.EMAIL_ADDRESS,
}

_EKU_MAP: dict[ExtendedKeyUsage, x509.ObjectIdentifier] = {
    ExtendedKeyUsage.SERVER_AUTH: ExtendedKeyUsageOID.SERVER_AUTH,
    ExtendedKeyUsage.CLIENT_AUTH: ExtendedKeyUsageOID.CLIENT_AUTH,
    ExtendedKeyUsage.CODE_SIGNING: ExtendedKeyUsageOID.CODE_SIGNING,
    ExtendedKeyUsage.EMAIL_PROTECTION: ExtendedKeyUsageOID.EMAIL_PROTECTION,
}


def _subject_to_x509_name(subject: Subject) -> x509.Name:
    attrs: list[x509.NameAttribute[str]] = []
    for field_name, oid in _NAME_ATTR_MAP.items():
        value: str | None = getattr(subject, field_name)
        if value is not None:
            attrs.append(x509.NameAttribute[str](oid=oid, value=value))
    return x509.Name(attributes=attrs)


def _build_key_usage(usages: list[KeyUsage]) -> x509.KeyUsage:
    usage_set = set(usages)
    return x509.KeyUsage(
        digital_signature=KeyUsage.DIGITAL_SIGNATURE in usage_set,
        key_encipherment=KeyUsage.KEY_ENCIPHERMENT in usage_set,
        data_encipherment=KeyUsage.DATA_ENCIPHERMENT in usage_set,
        key_agreement=KeyUsage.KEY_AGREEMENT in usage_set,
        key_cert_sign=KeyUsage.CERT_SIGN in usage_set,
        crl_sign=KeyUsage.CRL_SIGN in usage_set,
        content_commitment=False,
        encipher_only=False,
        decipher_only=False,
    )


def _get_hash_for_algorithm(algorithm: KeyAlgorithm) -> hashes.SHA256 | hashes.SHA384 | None:
    if algorithm in (KeyAlgorithm.RSA_2048, KeyAlgorithm.EC_P256):
        return hashes.SHA256()
    if algorithm in (KeyAlgorithm.RSA_4096, KeyAlgorithm.EC_P384):
        return hashes.SHA384()
    return None  # ED25519


def _sign_builder(
    builder: x509.CertificateBuilder,
    private_key: "_CertPrivateKey",
    algorithm: KeyAlgorithm,
) -> x509.Certificate:
    hash_alg = _get_hash_for_algorithm(algorithm=algorithm)
    return builder.sign(private_key=private_key, algorithm=hash_alg)


class X509Pki(Pki[X509CertificateRequest, X509CertData]):
    def __init__(
        self,
        *,
        pki_state: PkiState | None = None,
        crypto_provider: CryptoProvider | None = None,
        certificate_store: CertificateStore[X509CertificateRequest, X509CertData] | None = None,
    ) -> None:
        super().__init__(pki_state=pki_state, certificate_store=certificate_store)
        self._crypto_provider: CryptoProvider = crypto_provider or SoftwareCryptoProvider()

    def _do_issue_certificate(
        self,
        request: X509CertificateRequest,
        *,
        serial_number: SerialNumber,
        ca_serial_number: SerialNumber | None = None,
    ) -> CertificateInfo[X509CertificateRequest, X509CertData]:
        serial = serial_number
        self._crypto_provider.generate_key(algorithm=request.key_algorithm, serial_number=serial)

        subject_name = _subject_to_x509_name(subject=request.subject)
        cert_public_bytes = self._crypto_provider.get_public_key_bytes(serial_number=serial)
        cert_public_key = cast("_CertPublicKey", serialization.load_der_public_key(data=cert_public_bytes))

        # Resolve issuer info
        ca_cert_info: CertificateInfo[X509CertificateRequest, X509CertData] | None = None
        if ca_serial_number is None:
            issuer_name = subject_name
            signing_serial = serial
            signing_algorithm = request.key_algorithm
        else:
            ca_cert_info = self.get_certificate(serial_number=ca_serial_number)
            if ca_cert_info is None:
                raise CertificateNotFoundError(serial_number=ca_serial_number)
            issuer_name = _subject_to_x509_name(subject=ca_cert_info.request.subject)
            signing_serial = ca_serial_number
            signing_algorithm = ca_cert_info.request.key_algorithm

        builder = (
            x509.CertificateBuilder()
            .subject_name(name=subject_name)
            .issuer_name(name=issuer_name)
            .serial_number(number=serial)
            .not_valid_before(time=request.not_before)
            .not_valid_after(time=request.not_after)
            .public_key(key=cert_public_key)
            .add_extension(
                extval=x509.BasicConstraints(ca=request.is_ca, path_length=None),
                critical=True,
            )
        )

        # Key Usage
        if request.key_usages:
            builder = builder.add_extension(extval=_build_key_usage(usages=request.key_usages), critical=True)

        # Extended Key Usage
        if request.extended_key_usages:
            eku_oids = [_EKU_MAP[eku] for eku in request.extended_key_usages]
            builder = builder.add_extension(extval=x509.ExtendedKeyUsage(usages=eku_oids), critical=False)

        # SAN
        san_names: list[x509.GeneralName] = []
        for dns_name in request.san_dns_names:
            san_names.append(x509.DNSName(value=dns_name))
        for ip_str in request.san_ip_addresses:
            san_names.append(x509.IPAddress(value=ipaddress.ip_address(ip_str)))
        for email in request.san_email_addresses:
            san_names.append(x509.RFC822Name(value=email))
        if san_names:
            builder = builder.add_extension(extval=x509.SubjectAlternativeName(general_names=san_names), critical=False)

        # Subject Key Identifier
        builder = builder.add_extension(
            extval=x509.SubjectKeyIdentifier.from_public_key(public_key=cert_public_key),
            critical=False,
        )

        # Authority Key Identifier
        if ca_cert_info is None:
            aki_key = cast("_AKIPublicKey", cert_public_key)
        else:
            aki_key = cast("_AKIPublicKey", ca_cert_info.backend_data.parsed_certificate.public_key())
        builder = builder.add_extension(
            extval=x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key=aki_key),
            critical=False,
        )

        # Sign
        signing_key = self._load_private_key(serial_number=signing_serial)
        signed_cert = _sign_builder(builder=builder, private_key=signing_key, algorithm=signing_algorithm)
        cert_pem = PEMString(signed_cert.public_bytes(encoding=serialization.Encoding.PEM).decode())

        cert_info = CertificateInfo[X509CertificateRequest, X509CertData](
            request=request,
            serial_number=serial,
            ca_serial_number=ca_serial_number,
            status=CertificateStatus.ISSUED,
            issue_date=datetime.now(tz=UTC),
            backend_data=X509CertData(
                certificate_pem=cert_pem,
            ),
        )

        return cert_info

    # --- Private helpers ---

    def _get_cert_info(self, serial_number: SerialNumber) -> CertificateInfo[X509CertificateRequest, X509CertData]:
        cert = self.get_certificate(serial_number=serial_number)
        if cert is None:
            raise CertificateNotFoundError(serial_number=serial_number)
        return cert

    def _load_private_key(self, serial_number: SerialNumber) -> "_CertPrivateKey":
        return cast("_CertPrivateKey", self._crypto_provider.load_private_key(serial_number=serial_number))

    def _build_encryption(
        self,
        password: bytes | None,
    ) -> serialization.KeySerializationEncryption:
        if password is not None:
            return serialization.BestAvailableEncryption(password=password)
        return serialization.NoEncryption()

    # --- Certificate/key exports ---

    def export_certificate_pem(self, serial_number: SerialNumber) -> bytes:
        cert_info = self._get_cert_info(serial_number=serial_number)
        result: bytes = cert_info.backend_data.parsed_certificate.public_bytes(
            encoding=serialization.Encoding.PEM,
        )
        return result

    def export_certificate_der(self, serial_number: SerialNumber) -> bytes:
        cert_info = self._get_cert_info(serial_number=serial_number)
        result: bytes = cert_info.backend_data.parsed_certificate.public_bytes(
            encoding=serialization.Encoding.DER,
        )
        return result

    def export_private_key_pem(
        self,
        serial_number: SerialNumber,
        *,
        password: bytes | None = None,
    ) -> bytes:
        self._get_cert_info(serial_number=serial_number)
        key = self._load_private_key(serial_number=serial_number)
        result: bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=self._build_encryption(password=password),
        )
        return result

    def export_private_key_der(
        self,
        serial_number: SerialNumber,
        *,
        password: bytes | None = None,
    ) -> bytes:
        self._get_cert_info(serial_number=serial_number)
        key = self._load_private_key(serial_number=serial_number)
        result: bytes = key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=self._build_encryption(password=password),
        )
        return result

    def export_pkcs12_bytes(
        self,
        serial_number: SerialNumber,
        *,
        friendly_name: str = "certificate",
        password: bytes | None = None,
        include_ca: bool = True,
    ) -> bytes:
        cert_info = self._get_cert_info(serial_number=serial_number)
        cert = cert_info.backend_data.parsed_certificate
        key = self._load_private_key(serial_number=serial_number)
        cas: list[x509.Certificate] | None = None
        if include_ca and cert_info.ca_serial_number is not None:
            ca_cert_info = self._get_cert_info(serial_number=cert_info.ca_serial_number)
            cas = [ca_cert_info.backend_data.parsed_certificate]
        result: bytes = pkcs12.serialize_key_and_certificates(
            name=friendly_name.encode(),
            key=key,
            cert=cert,
            cas=cas,
            encryption_algorithm=self._build_encryption(password=password),
        )
        return result
