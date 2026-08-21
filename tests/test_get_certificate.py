from cryptography.hazmat.primitives import hashes


def test_returns_none_for_unknown_fingerprint(graph):
    assert graph.get_certificate("does-not-exist") is None


def test_returns_certificate_for_known_fingerprint(graph, self_signed_cert):
    graph.import_certificates(self_signed_cert)
    fingerprint = self_signed_cert.fingerprint(hashes.SHA256()).hex()

    assert graph.get_certificate(fingerprint) == self_signed_cert


def test_returns_correct_certificate_from_chain(graph, chain_certs):
    graph.import_certificates(chain_certs)
    target = chain_certs[1]
    fingerprint = target.fingerprint(hashes.SHA256()).hex()

    assert graph.get_certificate(fingerprint) == target
