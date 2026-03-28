from pki.types import SerialNumber


class PkiError(Exception):
    """Base exception for pki-kit."""


class CertificateNotFoundError(PkiError):
    def __init__(self, serial_number: SerialNumber) -> None:
        self.serial_number = serial_number
        super().__init__(f"Certificate not found: {serial_number}")


class CertificateConflictError(PkiError):
    def __init__(self, serial_number: SerialNumber) -> None:
        self.serial_number = serial_number
        super().__init__(f"Certificate with serial {serial_number} already exists but request fields differ")


class KeyNotFoundError(PkiError):
    def __init__(self, serial_number: SerialNumber) -> None:
        self.serial_number = serial_number
        super().__init__(f"Key not found: {serial_number}")


class CertificateValidityExceedsCAError(PkiError):
    def __init__(self, cert_not_after: str, ca_not_after: str) -> None:
        super().__init__(f"Certificate not_after ({cert_not_after}) exceeds CA not_after ({ca_not_after})")


class UnsupportedAlgorithmError(PkiError):
    def __init__(self, algorithm: str) -> None:
        self.algorithm = algorithm
        super().__init__(f"Unsupported algorithm: {algorithm}")


class NebulaCertError(PkiError):
    """Raised when a nebula-cert command fails."""

    def __init__(self, message: str, stderr: str = "") -> None:
        self.stderr = stderr
        super().__init__(message)


class SopsError(PkiError):
    """Raised when a SOPS encrypt/decrypt operation fails."""

    def __init__(self, message: str, stderr: str = "") -> None:
        self.stderr = stderr
        super().__init__(message)
