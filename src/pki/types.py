"""Enums, type aliases, and constants for pki-kit."""

from enum import StrEnum, auto
from typing import NewType

SerialNumber = NewType("SerialNumber", int)

Fingerprint = NewType("Fingerprint", str)
PEMString = NewType("PEMString", str)


class PkiType(StrEnum):
    X509 = auto()
    NEBULA = auto()


class KeyAlgorithm(StrEnum):
    RSA_2048 = auto()
    RSA_4096 = auto()
    EC_P256 = auto()
    EC_P384 = auto()
    ED25519 = auto()


class KeyUsage(StrEnum):
    DIGITAL_SIGNATURE = auto()
    KEY_ENCIPHERMENT = auto()
    DATA_ENCIPHERMENT = auto()
    KEY_AGREEMENT = auto()
    CERT_SIGN = auto()
    CRL_SIGN = auto()


class ExtendedKeyUsage(StrEnum):
    SERVER_AUTH = auto()
    CLIENT_AUTH = auto()
    CODE_SIGNING = auto()
    EMAIL_PROTECTION = auto()


class CertificateStatus(StrEnum):
    ISSUED = auto()
    REVOKED = auto()


class RevocationReason(StrEnum):
    UNSPECIFIED = auto()
    KEY_COMPROMISE = auto()
    CA_COMPROMISE = auto()
    AFFILIATION_CHANGED = auto()
    SUPERSEDED = auto()
    CESSATION_OF_OPERATION = auto()
