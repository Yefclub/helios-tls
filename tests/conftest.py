"""Configura o ambiente ANTES de importar app/core (constantes lidas no import)."""
import datetime
import os
import sys
import tempfile

os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="helios-test-")
os.environ["RUN_SCHEDULER"] = "false"
os.environ["LE_DOMAIN"] = "*.example.test"
os.environ["LE_EMAIL"] = "test@example.test"
os.environ["APP_USER"] = "admin"
os.environ["APP_PASSWORD"] = "secret123"
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["CERT_API_TOKEN"] = ""

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def make_cert_pair(cn="*.example.test", sans=("*.example.test", "example.test"),
                   days=90, org="Test CA"):
    """Gera certificado autoassinado + chave (PEM) para os testes."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
    ])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=2))
        .not_valid_after(now + datetime.timedelta(days=days))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    crt_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return crt_pem, key_pem


@pytest.fixture
def cert_pair():
    return make_cert_pair()
