from ulid import ULID

from pki.types import SerialNumber


def generate_serial_number() -> SerialNumber:
    """Generate a unique serial number based on ULID."""
    return SerialNumber(int(ULID()))
