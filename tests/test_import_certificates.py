import pytest
from cryptography.hazmat.primitives import serialization


def test_import_single_certificate_object(graph, self_signed_cert):
    graph.import_certificates(self_signed_cert)
    assert len(graph.report_fingerprint_edges()) == 1


def test_import_certificate_list(graph, chain_certs):
    graph.import_certificates(chain_certs)
    assert len(graph.report_fingerprint_edges()) == len(chain_certs)


def test_import_pem_string(graph, chain_pem, chain_certs):
    graph.import_certificates(chain_pem)
    assert len(graph.report_fingerprint_edges()) == len(chain_certs)


def test_import_der_bytes(graph, self_signed_cert):
    der = self_signed_cert.public_bytes(serialization.Encoding.DER)
    graph.import_certificates(der)
    assert len(graph.report_fingerprint_edges()) == 1


def test_import_invalid_type_raises_typeerror(graph):
    with pytest.raises(TypeError):
        graph.import_certificates(12345)


def test_import_returns_self_for_chaining(graph, self_signed_cert):
    result = graph.import_certificates(self_signed_cert)
    assert result is graph


def test_import_accumulates_across_multiple_calls(graph, chain_certs):
    graph.import_certificates(chain_certs[0])
    graph.import_certificates(chain_certs[1:])
    assert len(graph.report_fingerprint_edges()) == len(chain_certs)
