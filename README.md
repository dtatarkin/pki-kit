# pki-kit

A Python library for managing Public Key Infrastructures with a unified API across **X.509** and
**[Nebula](https://github.com/slackhq/nebula)** certificate backends. Issue, revoke, export, and persist certificates
programmatically or from the CLI.

## Why pki-kit?

Setting up mutual TLS or a Nebula overlay network typically means juggling `openssl`, `nebula-cert`, and ad-hoc scripts.
pki-kit replaces all of that with a single, typed Python API:

- **Dual backend** -- X.509 and Nebula certificates through one interface
- **Pluggable storage** -- in-memory (tests/CI) or filesystem with optional [SOPS](https://github.com/getsops/sops) encryption for private keys
- **Idempotent operations** -- re-issuing the same request + serial returns the existing certificate
- **Full lifecycle** -- issue, revoke, filter, export (PEM, DER, PKCS#12)
- **Type-safe** -- Pydantic models, strict mypy, generics throughout
- **CLI included** -- `pki-kit` command for scripting and quick operations

## Installation

```bash
pip install pki-kit

# with CLI support
pip install pki-kit[cli]
```

Requires Python 3.12+.

For **Nebula** backend: install [`nebula-cert`](https://github.com/slackhq/nebula/releases) and make sure it's on your `PATH`.

## Quick Start

### X.509: Create a CA and issue a leaf certificate

```python
from datetime import UTC, datetime, timedelta

from pki import (
    ExtendedKeyUsage,
    KeyAlgorithm,
    KeyUsage,
    Subject,
    X509CertificateRequest,
    X509Pki,
)

pki = X509Pki()
now = datetime.now(tz=UTC)

# Self-signed CA
ca = pki.issue_certificate(
    X509CertificateRequest(
        subject=Subject(common_name="My Root CA"),
        not_before=now,
        not_after=now + timedelta(days=3650),
        key_algorithm=KeyAlgorithm.EC_P256,
        is_ca=True,
        key_usages=[KeyUsage.CERT_SIGN, KeyUsage.CRL_SIGN],
    )
)

# Leaf certificate signed by the CA
leaf = pki.issue_certificate(
    X509CertificateRequest(
        subject=Subject(common_name="api.example.com"),
        not_before=now,
        not_after=now + timedelta(days=365),
        key_algorithm=KeyAlgorithm.EC_P256,
        san_dns_names=["api.example.com", "*.api.example.com"],
        extended_key_usages=[ExtendedKeyUsage.SERVER_AUTH],
    ),
    ca_serial_number=ca.serial_number,
)

# Export PEM
cert_pem = pki.export_certificate_pem(leaf.serial_number)
key_pem = pki.export_private_key_pem(leaf.serial_number)

# Or grab a PKCS#12 bundle
p12 = pki.export_pkcs12_bytes(leaf.serial_number, password=b"changeit")
```

### Nebula: Create a CA and issue host certificates

```python
from datetime import timedelta

from pki import KeyAlgorithm, NebulaCertificateRequest, NebulaPki, Subject

pki = NebulaPki()

ca = pki.issue_certificate(
    NebulaCertificateRequest(
        subject=Subject(common_name="Nebula CA"),
        duration=timedelta(days=3650),
        is_ca=True,
        key_algorithm=KeyAlgorithm.ED25519,
    )
)

host = pki.issue_certificate(
    NebulaCertificateRequest(
        subject=Subject(common_name="lighthouse-1"),
        duration=timedelta(days=365),
        ip="10.0.0.1/24",
        groups=["lighthouses", "servers"],
        key_algorithm=KeyAlgorithm.ED25519,
    ),
    ca_serial_number=ca.serial_number,
)
```

### Persistent storage with filesystem stores

```python
from pathlib import Path

from pki import X509Pki
from pki.stores import (
    FilesystemCertificateStore,
    FilesystemKeyStore,
    FilesystemStateStore,
    SoftwareCryptoProvider,
)

base = Path("./my-pki")
name = "production"

state_store = FilesystemStateStore(base_dir=base, pki_name=name)
cert_store = FilesystemCertificateStore(base_dir=base, pki_name=name)
key_store = FilesystemKeyStore(base_dir=base, pki_name=name)  # SOPS-encrypted

pki = X509Pki(
    pki_state=state_store.load(),
    certificate_store=cert_store,
    crypto_provider=SoftwareCryptoProvider(key_store=key_store),
)

# ... issue certificates ...

# Persist state
state_store.save(pki.export_state())
```

## CLI

```bash
# X.509
pki-kit x509 issue-ca --common-name "My CA" --days 3650 --algorithm ec-p256
pki-kit x509 issue --common-name "server.local" --days 365 --san-dns "server.local"
pki-kit x509 list
pki-kit x509 export-cert <serial>
pki-kit x509 revoke <serial> --reason key-compromise

# Nebula
pki-kit nebula issue-ca --common-name "Nebula CA" --days 3650
pki-kit nebula issue --common-name "host1" --ip "10.0.0.1/24" --groups web,servers
pki-kit nebula list
```

Set defaults via environment variables:

| Variable | Description |
|---|---|
| `PKI_KIT_BASE_PATH` | Root directory for filesystem stores |
| `PKI_KIT_PKI_NAME` | PKI instance name (default: `default`) |
| `PKI_KIT_SOPS_ARGS` | Extra arguments passed to SOPS |
| `PKI_KIT_OUTPUT_FORMAT` | Output format: `TABLE`, `JSON`, `YAML` |
| `PKI_NEBULA_CA_KEY` | Nebula: file holding the signing CA's private key (same as `--ca-key`) |

### Nebula without private keys in the PKI

By default `nebula issue` generates each host's key pair and keeps the private key, SOPS-encrypted, in the key store
beside the CA key. The three flows below keep every private key out of the PKI's base path: the host keeps its own key,
and the CA key is read from wherever you hold it at the moment of signing.

**Issue from the host's public key.** The host generates its key pair and hands over only the public key; the PKI
signs it and stores the certificate, no key. The key algorithm follows the public key. A public key already signed for
another host name, current or revoked, is refused with that host's name.

```bash
# on the host
nebula-cert keygen -out-key host1.key -out-pub host1.pub

# at the PKI
pki-kit nebula issue --common-name host1 --ip 10.0.0.1/24 --groups servers \
  --ca-serial <ca-serial> --duration 365d --public-key host1.pub --ca-key <ca-key-file>
pki-kit nebula export-cert <host1-serial> -o host1.crt
```

**Hold the CA key outside the PKI.** `--ca-key <file>` (or `PKI_NEBULA_CA_KEY`) names the CA's private key; signing
reads it from there and never from the key store. The file can be a tmpfs path or a process substitution that pulls the
key from a secret manager, so it never lands on disk:

```bash
pki-kit nebula issue ... --ca-key <(my-secret-manager read nebula-ca-key)
```

To move a CA created by `issue-ca` out of the key store, export its key into your secret manager and delete it from
`keys/`:

```bash
pki-kit nebula export-key <ca-serial> | my-secret-manager write nebula-ca-key
rm keys/<pki-name>-<ca-serial>-key.yaml
```

**Renew without the host.** `nebula renew` re-signs the public key of an existing host certificate with the same name,
IP, groups and subnets, under the same CA, for `--duration` or else the original duration. Neither the host's private
key nor the host itself is involved; it picks up the new certificate and keeps its key. The original certificate stays
valid until it expires or you revoke it.

```bash
pki-kit nebula renew <host1-serial> --ca-key <ca-key-file>
```

The same flows are available from Python: `NebulaCertificateRequest(public_key=...)`,
`NebulaPki(ca_key_path=...)` and `NebulaPki.renew_certificate()`.

## Key Algorithms

| Algorithm | Backend |
|---|---|
| `RSA_2048` | X.509 |
| `RSA_4096` | X.509 |
| `EC_P256` | X.509, Nebula |
| `EC_P384` | X.509 |
| `ED25519` | X.509, Nebula |

## Architecture

```text
Pki (abstract)
├── X509Pki          ─── CryptoProvider ─── KeyStore
└── NebulaPki                                  ├── InMemoryKeyStore
                                               └── FilesystemKeyStore (SOPS)
CertificateStore (generic)
├── InMemoryCertificateStore
└── FilesystemCertificateStore (YAML)

StateStore
├── InMemoryStateStore
└── FilesystemStateStore (YAML)
```

All stores default to in-memory implementations -- swap in filesystem stores when you need persistence, with no changes
to your certificate logic.

## Development

```bash
uv sync --all-extras
uv run pytest
uv run mypy src
uv run ruff check src tests
```

## License

See [LICENSE](LICENSE) for details.
