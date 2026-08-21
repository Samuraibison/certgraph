from datetime import datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from certgraph import certgraph as CertGraph

DEFAULT_CNS = [
    "root-authority",
    "intermediate-ca",
    "leaf-service",
    "sub-leaf-a",
    "sub-leaf-b",
]


def _make_cert(subject_cn, issuer_cn, signing_key, subject_key):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = (
        subject
        if issuer_cn is None
        else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    )
    builder = x509.CertificateBuilder()
    return (
        builder.subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.today() - timedelta(days=1))
        .not_valid_after(datetime.today() + timedelta(days=7))
        .sign(private_key=signing_key, algorithm=hashes.SHA256())
    )


@pytest.fixture
def make_chain():
    """Factory fixture: build a linear chain of n signed certificates.

    Certificate 0 is self-signed (a root); each subsequent certificate is
    issued by the private key of the one before it, mirroring a real CA chain.
    """

    def _build(n=3, cns=None):
        cns = cns or DEFAULT_CNS[:n]
        keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(n)]
        certs = []
        for i in range(n):
            issuer_cn = None if i == 0 else cns[i - 1]
            signing_key = keys[i] if i == 0 else keys[i - 1]
            certs.append(_make_cert(cns[i], issuer_cn, signing_key, keys[i]))
        return certs

    return _build


@pytest.fixture
def chain_certs(make_chain):
    return make_chain(3)


@pytest.fixture
def chain_pem(chain_certs):
    return "".join(
        cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        for cert in chain_certs
    )


@pytest.fixture
def self_signed_cert(make_chain):
    return make_chain(1)[0]


@pytest.fixture
def expired_cert():
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired-leaf")])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.today() - timedelta(days=30))
        .not_valid_after(datetime.today() - timedelta(days=1))
        .sign(private_key=key, algorithm=hashes.SHA256())
    )


@pytest.fixture
def graph():
    return CertGraph()
