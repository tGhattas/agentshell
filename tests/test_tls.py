"""Tests for TLS certificate generation."""

import tempfile
from pathlib import Path

from agentshell.tls import generate_self_signed_cert, get_cert_fingerprint


def test_generate_cert():
    with tempfile.TemporaryDirectory() as tmp:
        cert = Path(tmp) / "cert.pem"
        key = Path(tmp) / "key.pem"
        fp = generate_self_signed_cert(cert, key, hostname="localhost")

        assert cert.exists()
        assert key.exists()
        assert ":" in fp  # Colon-separated hex fingerprint


def test_fingerprint_consistency():
    with tempfile.TemporaryDirectory() as tmp:
        cert = Path(tmp) / "cert.pem"
        key = Path(tmp) / "key.pem"
        fp1 = generate_self_signed_cert(cert, key)
        fp2 = get_cert_fingerprint(cert)
        assert fp1 == fp2


def test_key_permissions():
    with tempfile.TemporaryDirectory() as tmp:
        cert = Path(tmp) / "cert.pem"
        key = Path(tmp) / "key.pem"
        generate_self_signed_cert(cert, key)
        assert oct(key.stat().st_mode & 0o777) == "0o600"
