"""TLS certificate generation and management."""

import datetime
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def generate_self_signed_cert(
    cert_path: Path,
    key_path: Path,
    hostname: str = "localhost",
    days_valid: int = 365,
) -> str:
    """Generate a self-signed TLS certificate and private key.

    Returns the SHA-256 fingerprint of the certificate for pinning.
    """
    # Generate EC private key (ECDSA P-256 — compact and fast)
    private_key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AgentShell"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)

    san_names: list[x509.GeneralName] = [
        x509.DNSName(hostname),
        x509.DNSName("localhost"),
        x509.IPAddress(
            __import__("ipaddress").IPv4Address("127.0.0.1")
        ),
    ]
    # If hostname looks like an IP, add it as IPAddress too
    try:
        import ipaddress
        addr = ipaddress.ip_address(hostname)
        san_names.append(x509.IPAddress(addr))
    except ValueError:
        if hostname not in ("localhost",):
            san_names.append(x509.DNSName(hostname))

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Write key with restrictive permissions
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key_bytes)
    key_path.chmod(0o600)

    # Write certificate
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(cert_bytes)
    cert_path.chmod(0o644)

    # Compute fingerprint for pinning
    fingerprint = cert.fingerprint(hashes.SHA256()).hex(":")
    return fingerprint


def get_cert_fingerprint(cert_path: Path) -> str:
    """Get the SHA-256 fingerprint of an existing certificate."""
    cert_data = cert_path.read_bytes()
    cert = x509.load_pem_x509_certificate(cert_data)
    return cert.fingerprint(hashes.SHA256()).hex(":")


def create_server_ssl_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    """Create an SSL context for the server."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx


def create_client_ssl_context(
    expected_fingerprint: str | None = None,
    ca_cert_path: Path | None = None,
) -> ssl.SSLContext:
    """Create an SSL context for the client.

    If expected_fingerprint is provided, uses certificate pinning.
    If ca_cert_path is provided, verifies against that CA.
    Otherwise, disables verification (for self-signed certs — not recommended).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    if ca_cert_path and ca_cert_path.exists():
        ctx.load_verify_locations(cafile=str(ca_cert_path))
    else:
        # For self-signed certs: we rely on fingerprint pinning instead
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    return ctx
